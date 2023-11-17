package sframe

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/hkdf"
)

func numBytes(x uint64) int {
	count := 0
	for {
		if x > 0 {
			x >>= 1
			count++
		} else {
			break
		}
	}
	return (count + 7) / 8
}

func encodeBigEndian(x uint64, n int) []byte {
	if n == 8 {
		buffer := make([]byte, 8)
		binary.BigEndian.PutUint64(buffer, uint64(x))
		return buffer
	} else if n == 2 {
		buffer := make([]byte, 2)
		binary.BigEndian.PutUint16(buffer, uint16(x))
		return buffer
	} else if n > 8 {
		// XXX(caw): this doesn't handle counters larger than 2^64
		buffer := make([]byte, 8)
		binary.BigEndian.PutUint64(buffer, uint64(x))
		zeroes := make([]byte, n-8)
		return append(zeroes, buffer...)
	} else {
		panic("unsupported (lazy programmer)")
	}
}

func encodeHeader(kid uint64, ctr uint64) []byte {
	kidBuffer := []byte{}
	ctrBuffer := []byte{}
	headerPrefix := byte(0)
	if kid < 8 {
		headerPrefix |= uint8(kid) << 4
	} else {
		kidBytes := numBytes(kid)
		kidBuffer = make([]byte, 8)
		binary.BigEndian.PutUint64(kidBuffer, uint64(kid))
		kidBuffer = kidBuffer[(8 - kidBytes):]
		headerPrefix |= 0x80
		headerPrefix |= (uint8(kidBytes) - 1) << 4
	}
	if ctr < 8 {
		headerPrefix |= uint8(ctr)
	} else {
		ctrBytes := numBytes(ctr)
		ctrBuffer = make([]byte, 8)
		binary.BigEndian.PutUint64(ctrBuffer, uint64(ctr))
		ctrBuffer = ctrBuffer[(8 - ctrBytes):]
		headerPrefix |= 0x08
		headerPrefix |= uint8(ctrBytes) - 1
	}
	header := []byte{headerPrefix}
	header = append(header, kidBuffer...)
	header = append(header, ctrBuffer...)

	return header
}

func decodeHeader(header []byte) (uint64, uint64, int) {
	kid := uint64(0)
	kidLen := 0
	ctr := uint64(0)
	ctrLen := 0
	if header[0]&0x80 == 0 {
		kid = uint64((header[0] & 0x70) >> 4)
	} else {
		kidLen = int((header[0]&0x70)>>4) + 1
		buffer := make([]byte, 8)
		kidBuffer := header[1 : 1+kidLen]
		copy(buffer[8-kidLen:], kidBuffer)
		kid = binary.BigEndian.Uint64(buffer)
	}
	if header[0]&0x8 == 0 {
		ctr = uint64(header[0] & 0x7)
	} else {
		ctrLen = int(header[0]&0x7) + 1
		buffer := make([]byte, 8)
		ctrBuffer := header[1+kidLen : 1+kidLen+ctrLen]
		copy(buffer[8-ctrLen:], ctrBuffer)
		ctr = binary.BigEndian.Uint64(buffer)
	}

	return kid, ctr, 1 + kidLen + ctrLen
}

type Ciphersuite interface {
	AEAD() Encryptor
	Hash() func() hash.Hash
	ID() uint16
}

func NewCiphersuite(id uint16) (Ciphersuite, error) {
	if id == 0x0001 {
		return AesCtr128HmacSha256Tag80Suite{}, nil
	} else if id == 0x0002 {
		return AesCtr128HmacSha256Tag64Suite{}, nil
	} else if id == 0x0003 {
		return AesCtr128HmacSha256Tag32Suite{}, nil
	} else {
		return nil, fmt.Errorf("unsupported ciphersuite")
	}
}

type AesCtr128HmacSha256Tag80Suite struct {
}

func (s AesCtr128HmacSha256Tag80Suite) AEAD() Encryptor {
	return AesCtr128HmacSha256Tag80Encryptor{}
}

func (s AesCtr128HmacSha256Tag80Suite) Hash() func() hash.Hash {
	return sha256.New
}

func (s AesCtr128HmacSha256Tag80Suite) ID() uint16 {
	return 0x0001
}

type Encryptor interface {
	Encrypt(key, nonce, aad, plaintext []byte) ([]byte, error)
	Decrypt(key, nonce, aad, ciphertext []byte) ([]byte, error)
	Nk() int
	Nn() int
	Nt() int
}

// https://sframe-wg.github.io/sframe/draft-ietf-sframe-enc.html#name-cipher-suites
type AesCtr128HmacSha256Tag80Encryptor struct {
}

func deriveAesCtrHmacSubkeys(sframeKey []byte, nka int) ([]byte, []byte) {
	// def derive_subkeys(sframe_key):
	//   enc_key = sframe_key[..Nka]
	//   auth_key = sframe_key[Nka..]
	//   return enc_key, auth_key
	encKey := sframeKey[:nka]
	authKey := sframeKey[nka:]
	return encKey, authKey
}

func computeAesCtrHmacTag(authKey, nonce, aad, ct []byte, nt int) []byte {
	// def compute_tag(auth_key, nonce, aad, ct):
	//   aad_len = encode_big_endian(len(aad), 8)
	//   ct_len = encode_big_endian(len(ct), 8)
	//   tag_len = encode_big_endian(Nt, 8)
	//   auth_data = aad_len + ct_len + tag_len + nonce + aad + ct
	//   tag = HMAC(auth_key, auth_data)
	//   return truncate(tag, Nt)

	aadLen := encodeBigEndian(uint64(len(aad)), 8)
	ctLen := encodeBigEndian(uint64(len(ct)), 8)
	tagLen := encodeBigEndian(uint64(nt), 8)

	authData := append(aadLen, ctLen...)
	authData = append(authData, tagLen...)
	authData = append(authData, nonce...)
	authData = append(authData, aad...)
	authData = append(authData, ct...)

	mac := hmac.New(sha256.New, authKey)
	mac.Write(authData)
	tag := mac.Sum(nil)

	return tag[:nt]
}

func (e AesCtr128HmacSha256Tag80Encryptor) computeTag(authKey, nonce, aad, ct []byte) []byte {
	return computeAesCtrHmacTag(authKey, nonce, aad, ct, e.Nt())
}

func counterEncrypt(nonce, key, plaintext []byte) ([]byte, error) {
	fourZeroes := make([]byte, 4)
	iv := append(nonce, fourZeroes...)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ctr := cipher.NewCTR(block, iv)
	ciphertext := make([]byte, len(plaintext))
	ctr.XORKeyStream(ciphertext, plaintext)

	return ciphertext, nil
}

func (e AesCtr128HmacSha256Tag80Encryptor) Encrypt(key, nonce, aad, plaintext []byte) ([]byte, error) {
	// def AEAD.Encrypt(key, nonce, aad, pt):
	//   enc_key, auth_key = derive_subkeys(key)
	//   iv = nonce + 0x00000000 # append four zero bytes
	//   ct = AES-CTR.Encrypt(enc_key, iv, pt)
	//   tag = compute_tag(auth_key, nonce, aad, ct)
	//   return ct + tag

	encKey, authKey := deriveAesCtrHmacSubkeys(key, 16)
	ciphertext, err := counterEncrypt(nonce, encKey, plaintext)
	if err != nil {
		return nil, err
	}
	tag := computeAesCtrHmacTag(authKey, nonce, aad, ciphertext, e.Nt())

	return append(ciphertext, tag...), nil
}

func (e AesCtr128HmacSha256Tag80Encryptor) Decrypt(key, nonce, aad, ciphertext []byte) ([]byte, error) {
	// def AEAD.Decrypt(key, nonce, aad, ct):
	//   inner_ct, tag = split_ct(ct, tag_len)

	//   enc_key, auth_key = derive_subkeys(key)
	//   candidate_tag = compute_tag(auth_key, nonce, aad, inner_ct)
	//   if !constant_time_equal(tag, candidate_tag):
	//     raise Exception("Authentication Failure")

	//   iv = nonce + 0x00000000 # append four zero bytes
	//   return AES-CTR.Decrypt(enc_key, iv, inner_ct)

	innerCiphertext := ciphertext[:len(ciphertext)-e.Nt()]
	tag := ciphertext[len(ciphertext)-e.Nt():]

	encKey, authKey := deriveAesCtrHmacSubkeys(key, 16)
	candidateTag := computeAesCtrHmacTag(authKey, nonce, aad, innerCiphertext, e.Nt())
	if subtle.ConstantTimeCompare(tag, candidateTag) == 0 {
		return nil, fmt.Errorf("decrypt tag verification failed")
	}

	plaintext, err := counterEncrypt(nonce, encKey, innerCiphertext)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func (e AesCtr128HmacSha256Tag80Encryptor) Nk() int {
	return 48
}

func (e AesCtr128HmacSha256Tag80Encryptor) Nn() int {
	return 12
}

func (e AesCtr128HmacSha256Tag80Encryptor) Nt() int {
	return 10
}

type AesCtr128HmacSha256Tag64Suite struct {
}

// https://sframe-wg.github.io/sframe/draft-ietf-sframe-enc.html#name-cipher-suites
type AesCtr128HmacSha256Tag64Encryptor struct {
}

func (s AesCtr128HmacSha256Tag64Suite) AEAD() Encryptor {
	return AesCtr128HmacSha256Tag64Encryptor{}
}

func (s AesCtr128HmacSha256Tag64Suite) Hash() func() hash.Hash {
	return sha256.New
}

func (s AesCtr128HmacSha256Tag64Suite) ID() uint16 {
	return 0x0002
}

func (e AesCtr128HmacSha256Tag64Encryptor) Encrypt(key, nonce, aad, plaintext []byte) ([]byte, error) {
	encKey, authKey := deriveAesCtrHmacSubkeys(key, 16)

	ciphertext, err := counterEncrypt(nonce, encKey, plaintext)
	if err != nil {
		return nil, err
	}

	tag := computeAesCtrHmacTag(authKey, nonce, aad, ciphertext, e.Nt())

	return append(ciphertext, tag...), nil
}

func (e AesCtr128HmacSha256Tag64Encryptor) Decrypt(key, nonce, aad, ciphertext []byte) ([]byte, error) {
	innerCiphertext := ciphertext[:len(ciphertext)-e.Nt()]
	tag := ciphertext[len(ciphertext)-e.Nt():]

	encKey, authKey := deriveAesCtrHmacSubkeys(key, 16)
	candidateTag := computeAesCtrHmacTag(authKey, nonce, aad, innerCiphertext, e.Nt())
	if subtle.ConstantTimeCompare(tag, candidateTag) == 0 {
		return nil, fmt.Errorf("decrypt tag verification failed")
	}

	plaintext, err := counterEncrypt(nonce, encKey, innerCiphertext)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func (e AesCtr128HmacSha256Tag64Encryptor) Nk() int {
	return 48
}

func (e AesCtr128HmacSha256Tag64Encryptor) Nn() int {
	return 12
}

func (e AesCtr128HmacSha256Tag64Encryptor) Nt() int {
	return 8
}

type AesCtr128HmacSha256Tag32Suite struct {
}

// https://sframe-wg.github.io/sframe/draft-ietf-sframe-enc.html#name-cipher-suites
type AesCtr128HmacSha256Tag32Encryptor struct {
}

func (s AesCtr128HmacSha256Tag32Suite) AEAD() Encryptor {
	return AesCtr128HmacSha256Tag32Encryptor{}
}

func (s AesCtr128HmacSha256Tag32Suite) Hash() func() hash.Hash {
	return sha256.New
}

func (s AesCtr128HmacSha256Tag32Suite) ID() uint16 {
	return 0x0003
}

func (e AesCtr128HmacSha256Tag32Encryptor) Encrypt(key, nonce, aad, plaintext []byte) ([]byte, error) {
	encKey, authKey := deriveAesCtrHmacSubkeys(key, 16)

	ciphertext, err := counterEncrypt(nonce, encKey, plaintext)
	if err != nil {
		return nil, err
	}

	tag := computeAesCtrHmacTag(authKey, nonce, aad, ciphertext, e.Nt())

	return append(ciphertext, tag...), nil
}

func (e AesCtr128HmacSha256Tag32Encryptor) Decrypt(key, nonce, aad, ciphertext []byte) ([]byte, error) {
	innerCiphertext := ciphertext[:len(ciphertext)-e.Nt()]
	tag := ciphertext[len(ciphertext)-e.Nt():]

	encKey, authKey := deriveAesCtrHmacSubkeys(key, 16)
	candidateTag := computeAesCtrHmacTag(authKey, nonce, aad, innerCiphertext, e.Nt())
	if subtle.ConstantTimeCompare(tag, candidateTag) == 0 {
		return nil, fmt.Errorf("decrypt tag verification failed")
	}

	plaintext, err := counterEncrypt(nonce, encKey, innerCiphertext)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func (e AesCtr128HmacSha256Tag32Encryptor) Nk() int {
	return 48
}

func (e AesCtr128HmacSha256Tag32Encryptor) Nn() int {
	return 12
}

func (e AesCtr128HmacSha256Tag32Encryptor) Nt() int {
	return 4
}

type SFramerKey struct {
	key  []byte
	salt []byte
}

func NewSFramerKey(kid uint64, baseKey []byte, s Ciphersuite) (SFramerKey, error) {
	// def derive_key_salt(KID, base_key):
	// 	sframe_secret = HKDF-Extract("", base_key)
	// 	info = "SFrame 1.0 Secret key " + KID + cipher_suite
	// 	sframe_key = HKDF-Expand(sframe_secret, info, AEAD.Nk)
	// 	sframe_salt = HKDF-Expand(sframe_secret, info, AEAD.Nn)
	// 	return sframe_key, sframe_salt

	hash := s.Hash()
	infoSuffix := append(encodeBigEndian(kid, 8), encodeBigEndian(uint64(s.ID()), 2)...)

	keyInfo := append([]byte("SFrame 1.0 Secret key "), infoSuffix...)
	keyReader := hkdf.New(hash, baseKey, nil, keyInfo)
	sframeKey := make([]byte, s.AEAD().Nk())
	if _, err := io.ReadFull(keyReader, sframeKey); err != nil {
		return SFramerKey{}, err
	}
	saltInfo := append([]byte("SFrame 1.0 Secret salt "), infoSuffix...)
	saltReader := hkdf.New(hash, baseKey, nil, saltInfo)
	sframeSalt := make([]byte, s.AEAD().Nn())
	if _, err := io.ReadFull(saltReader, sframeSalt); err != nil {
		return SFramerKey{}, err
	}

	return SFramerKey{
		key:  sframeKey,
		salt: sframeSalt,
	}, nil
}

type SFramer struct {
	suite    Ciphersuite
	keyStore map[uint64]SFramerKey
}

func xor(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("invalid inputs to XOR")
	}
	c := make([]byte, len(a))
	for i, _ := range a {
		c[i] = a[i] ^ b[i]
	}
	return c
}

func (f SFramer) Encrypt(ctr uint64, kid uint64, metadata []byte, plaintext []byte) ([]byte, error) {
	// def encrypt(CTR, KID, metadata, plaintext):
	//   sframe_key, sframe_salt = key_store[KID]
	sframerKey, ok := f.keyStore[kid]
	if !ok {
		return nil, fmt.Errorf("unknown KID")
	}

	//   ctr = encode_big_endian(CTR, AEAD.Nn)
	encodedCtr := encodeBigEndian(ctr, f.suite.AEAD().Nn())

	//   nonce = xor(sframe_salt, CTR)
	nonce := xor(sframerKey.salt, encodedCtr)

	//   header = encode_sframe_header(CTR, KID)
	header := encodeHeader(kid, ctr)

	//   aad = header + metadata
	aad := append(header, metadata...)

	// ciphertext = AEAD.Encrypt(sframe_key, nonce, aad, plaintext)
	ciphertext, err := f.suite.AEAD().Encrypt(sframerKey.key, nonce, aad, plaintext)
	if err != nil {
		return nil, err
	}

	// return header + ciphertext
	return append(header, ciphertext...), nil
}

func (f SFramer) Decrypt(metadata []byte, sframeCiphertext []byte) ([]byte, error) {
	// def decrypt(metadata, sframe_ciphertext):
	// 	KID, CTR, ciphertext = parse_ciphertext(sframe_ciphertext)
	kid, ctr, offset := decodeHeader(sframeCiphertext)
	header := sframeCiphertext[0:offset]
	ciphertext := sframeCiphertext[offset:]

	// 	sframe_key, sframe_salt = key_store[KID]
	sframerKey, ok := f.keyStore[kid]
	if !ok {
		return nil, fmt.Errorf("unknown KID")
	}

	// 	ctr = encode_big_endian(CTR, AEAD.Nn)
	encodedCtr := encodeBigEndian(ctr, f.suite.AEAD().Nn())

	// 	nonce = xor(sframe_salt, ctr)
	nonce := xor(sframerKey.salt, encodedCtr)

	// 	aad = header + metadata
	aad := append(header, metadata...)

	// 	return AEAD.Decrypt(sframe_key, nonce, aad, ciphertext)
	plaintext, err := f.suite.AEAD().Decrypt(sframerKey.key, nonce, aad, ciphertext)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
