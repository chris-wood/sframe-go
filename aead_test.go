package sframe

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// https://sframe-wg.github.io/sframe/draft-ietf-sframe-enc.html#name-aead-encryption-decryption-
func TestAeadRoundTrip(t *testing.T) {
	var testVectors = []struct {
		cipherSuite uint16
		keyHex      string
		nonceHex    string
		aadHex      string
		ptHex       string
		ctHex       string
	}{
		{
			cipherSuite: 0x0001,
			keyHex:      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
			nonceHex:    "101112131415161718191a1b",
			aadHex:      "4945544620534672616d65205747",
			ptHex:       "64726166742d696574662d736672616d652d656e63",
			ctHex:       "6339af04ada1d064688a442b8dc69d5b6bfa40f4bef0583e8081069cc60705",
		},
		{
			cipherSuite: 0x0002,
			keyHex:      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
			nonceHex:    "101112131415161718191a1b",
			aadHex:      "4945544620534672616d65205747",
			ptHex:       "64726166742d696574662d736672616d652d656e63",
			ctHex:       "6339af04ada1d064688a442b8dc69d5b6bfa40f4be6e93b7da076927bb",
		},
		{
			cipherSuite: 0x0003,
			keyHex:      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
			nonceHex:    "101112131415161718191a1b",
			aadHex:      "4945544620534672616d65205747",
			ptHex:       "64726166742d696574662d736672616d652d656e63",
			ctHex:       "6339af04ada1d064688a442b8dc69d5b6bfa40f4be09480509",
		},
	}

	for _, vector := range testVectors {
		key := mustDecodeHex(vector.keyHex)
		nonce := mustDecodeHex(vector.nonceHex)
		aad := mustDecodeHex(vector.aadHex)
		pt := mustDecodeHex(vector.ptHex)
		ct := mustDecodeHex(vector.ctHex)

		suite, err := NewCiphersuite(vector.cipherSuite)
		if err == nil {
			encryptor := suite.AEAD()
			ciphertext, err := encryptor.Encrypt(key, nonce, aad, pt)
			require.Nil(t, err, "Encryption failed", err)
			require.Equal(t, ct, ciphertext, "Encryption mismatch")

			plaintext, err := encryptor.Decrypt(key, nonce, aad, ciphertext)
			require.Nil(t, err, "Decryption failed", err)
			require.Equal(t, pt, plaintext, "Decryption mismatch")
		} else {
			t.Logf("unsupported ciphersuite: %x\n", vector.cipherSuite)
		}
	}
}
