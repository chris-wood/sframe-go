package sframe

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
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

func (e AesCtr128HmacSha256Tag80Encryptor) deriveSubkeys(sframeKey []byte) ([]byte, []byte) {
	// def derive_subkeys(sframe_key):
	//   enc_key = sframe_key[..Nka]
	//   auth_key = sframe_key[Nka..]
	//   return enc_key, auth_key
	Nka := 16
	encKey := sframeKey[:Nka]
	authKey := sframeKey[Nka:]
	return encKey, authKey
}

func (e AesCtr128HmacSha256Tag80Encryptor) computeTag(authKey, nonce, aad, ct []byte) []byte {
	// def compute_tag(auth_key, nonce, aad, ct):
	//   aad_len = encode_big_endian(len(aad), 8)
	//   ct_len = encode_big_endian(len(ct), 8)
	//   tag_len = encode_big_endian(Nt, 8)
	//   auth_data = aad_len + ct_len + tag_len + nonce + aad + ct
	//   tag = HMAC(auth_key, auth_data)
	//   return truncate(tag, Nt)

	aadLen := encodeBigEndian(uint64(len(aad)), 8)
	ctLen := encodeBigEndian(uint64(len(ct)), 8)
	tagLen := encodeBigEndian(uint64(e.Nt()), 8)

	authData := append(aadLen, ctLen...)
	authData = append(authData, tagLen...)
	authData = append(authData, nonce...)
	authData = append(authData, aad...)
	authData = append(authData, ct...)

	mac := hmac.New(sha256.New, authKey)
	mac.Write(authData)
	tag := mac.Sum(nil)

	return tag[:e.Nt()]
}

func (e AesCtr128HmacSha256Tag80Encryptor) Encrypt(key, nonce, aad, plaintext []byte) ([]byte, error) {
	// def AEAD.Encrypt(key, nonce, aad, pt):
	//   enc_key, auth_key = derive_subkeys(key)
	//   iv = nonce + 0x00000000 # append four zero bytes
	//   ct = AES-CTR.Encrypt(enc_key, iv, pt)
	//   tag = compute_tag(auth_key, nonce, aad, ct)
	//   return ct + tag

	encKey, authKey := e.deriveSubkeys(key)

	fourZeroes := make([]byte, 4)
	iv := append(nonce, fourZeroes...)

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	ctr := cipher.NewCTR(block, iv)
	ciphertext := make([]byte, len(plaintext))
	ctr.XORKeyStream(ciphertext, plaintext)

	tag := e.computeTag(authKey, nonce, aad, ciphertext)

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

	encKey, authKey := e.deriveSubkeys(key)
	candidateTag := e.computeTag(authKey, nonce, aad, innerCiphertext)
	if subtle.ConstantTimeCompare(tag, candidateTag) == 0 {
		return nil, fmt.Errorf("decrypt tag verification failed")
	}

	fourZeroes := make([]byte, 4)
	iv := append(nonce, fourZeroes...)

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	ctr := cipher.NewCTR(block, iv)
	plaintext := make([]byte, len(innerCiphertext))
	ctr.XORKeyStream(plaintext, innerCiphertext)

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

type SFramerKey struct {
	key  []byte
	salt []byte
}

func NewSFramerKey(kid uint64, baseKey []byte, e Encryptor) (SFramerKey, error) {
	// def derive_key_salt(KID, base_key):
	// 	sframe_secret = HKDF-Extract("", base_key)
	// 	info = "SFrame 1.0 Secret key " + KID + cipher_suite
	// 	sframe_key = HKDF-Expand(sframe_secret, info, AEAD.Nk)
	// 	sframe_salt = HKDF-Expand(sframe_secret, info, AEAD.Nn)
	// 	return sframe_key, sframe_salt

	// XXX(caw): get HKDF from the ciphersuite
	hash := sha256.New
	infoSuffix := append(encodeBigEndian(kid, 8), encodeBigEndian(0x0001, 2)...)

	keyInfo := append([]byte("SFrame 1.0 Secret key "), infoSuffix...)
	keyReader := hkdf.New(hash, baseKey, nil, keyInfo)
	sframeKey := make([]byte, e.Nk())
	if _, err := io.ReadFull(keyReader, sframeKey); err != nil {
		return SFramerKey{}, err
	}
	saltInfo := append([]byte("SFrame 1.0 Secret salt "), infoSuffix...)
	saltReader := hkdf.New(hash, baseKey, nil, saltInfo)
	sframeSalt := make([]byte, e.Nn())
	if _, err := io.ReadFull(saltReader, sframeSalt); err != nil {
		return SFramerKey{}, err
	}

	return SFramerKey{
		key:  sframeKey,
		salt: sframeSalt,
	}, nil
}

type SFramer struct {
	encryptor Encryptor
	keyStore  map[uint64]SFramerKey
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
	encodedCtr := encodeBigEndian(ctr, f.encryptor.Nn())

	//   nonce = xor(sframe_salt, CTR)
	nonce := xor(sframerKey.salt, encodedCtr)

	//   header = encode_sframe_header(CTR, KID)
	header := encodeHeader(kid, ctr)

	//   aad = header + metadata
	aad := append(header, metadata...)

	// ciphertext = AEAD.Encrypt(sframe_key, nonce, aad, plaintext)
	ciphertext, err := f.encryptor.Encrypt(sframerKey.key, nonce, aad, plaintext)
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
	encodedCtr := encodeBigEndian(ctr, f.encryptor.Nn())

	// 	nonce = xor(sframe_salt, ctr)
	nonce := xor(sframerKey.salt, encodedCtr)

	// 	aad = header + metadata
	aad := append(header, metadata...)

	// 	return AEAD.Decrypt(sframe_key, nonce, aad, ciphertext)
	plaintext, err := f.encryptor.Decrypt(sframerKey.key, nonce, aad, ciphertext)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
