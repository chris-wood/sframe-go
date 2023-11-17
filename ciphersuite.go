package sframe

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
)

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
	} else if id == 0x0004 {
		return AesGcm128Sha256Tag128Suite{}, nil
	} else if id == 0x0005 {
		return AesGcm256Sha512Tag128Suite{}, nil
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

type AesCtr128HmacSha256Tag64Suite struct {
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

type AesCtr128HmacSha256Tag32Suite struct {
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

type AesGcm128Sha256Tag128Suite struct {
}

func (s AesGcm128Sha256Tag128Suite) AEAD() Encryptor {
	return AesGcm128Sha256Tag128Encryptor{}
}

func (s AesGcm128Sha256Tag128Suite) Hash() func() hash.Hash {
	return sha256.New
}

func (s AesGcm128Sha256Tag128Suite) ID() uint16 {
	return 0x0004
}

type AesGcm256Sha512Tag128Suite struct {
}

func (s AesGcm256Sha512Tag128Suite) AEAD() Encryptor {
	return AesGcm256Sha256Tag128Encryptor{}
}

func (s AesGcm256Sha512Tag128Suite) Hash() func() hash.Hash {
	return sha512.New
}

func (s AesGcm256Sha512Tag128Suite) ID() uint16 {
	return 0x0005
}
