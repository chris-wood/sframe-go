package sframe

import (
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

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
