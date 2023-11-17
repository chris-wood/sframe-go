package sframe

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
)

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

// https://sframe-wg.github.io/sframe/draft-ietf-sframe-enc.html#name-cipher-suites
type AesCtr128HmacSha256Tag64Encryptor struct {
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

// https://sframe-wg.github.io/sframe/draft-ietf-sframe-enc.html#name-cipher-suites
type AesCtr128HmacSha256Tag32Encryptor struct {
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

// https://sframe-wg.github.io/sframe/draft-ietf-sframe-enc.html#name-cipher-suites
type AesGcm128Sha256Tag128Encryptor struct {
}

func (e AesGcm128Sha256Tag128Encryptor) Encrypt(key, nonce, aad, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, aad)

	return ciphertext, nil
}

func (e AesGcm128Sha256Tag128Encryptor) Decrypt(key, nonce, aad, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, aad)
	return plaintext, err
}

func (e AesGcm128Sha256Tag128Encryptor) Nk() int {
	return 16
}

func (e AesGcm128Sha256Tag128Encryptor) Nn() int {
	return 12
}

func (e AesGcm128Sha256Tag128Encryptor) Nt() int {
	return 16
}

// https://sframe-wg.github.io/sframe/draft-ietf-sframe-enc.html#name-cipher-suites
type AesGcm256Sha256Tag128Encryptor struct {
}

func (e AesGcm256Sha256Tag128Encryptor) Encrypt(key, nonce, aad, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, aad)

	return ciphertext, nil
}

func (e AesGcm256Sha256Tag128Encryptor) Decrypt(key, nonce, aad, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, aad)
	return plaintext, err
}

func (e AesGcm256Sha256Tag128Encryptor) Nk() int {
	return 32
}

func (e AesGcm256Sha256Tag128Encryptor) Nn() int {
	return 12
}

func (e AesGcm256Sha256Tag128Encryptor) Nt() int {
	return 16
}
