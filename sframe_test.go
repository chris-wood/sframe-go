package sframe

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func mustDecodeHex(x string) []byte {
	val, err := hex.DecodeString(x)
	if err != nil {
		panic(err)
	}
	return val
}

func mustDecodeHexInt(x string) uint64 {
	v := mustDecodeHex(x)
	return binary.BigEndian.Uint64(v)
}

type HeaderTestVector struct {
	Kid    string `json:"kid"`
	Ctr    string `json:"ctr"`
	Header string `json:"header"`
}

// https://sframe-wg.github.io/sframe/draft-ietf-sframe-enc.html#name-header-encoding-decoding
func TestHeaderEncode(t *testing.T) {
	var testVectors []HeaderTestVector
	testVectorBytes, err := os.ReadFile("header_test_vectors.json")
	require.Nil(t, err, "Failed reading test vectors")
	if err := json.Unmarshal(testVectorBytes, &testVectors); err != nil {
		require.Nil(t, err, "Failed parsing test vectors")
	}

	for _, vector := range testVectors {
		kidBytes := mustDecodeHex(vector.Kid)
		ctrBytes := mustDecodeHex(vector.Ctr)
		headerBytes := mustDecodeHex(vector.Header)

		kid := binary.BigEndian.Uint64(kidBytes)
		ctr := binary.BigEndian.Uint64(ctrBytes)

		header := encodeHeader(kid, ctr)
		require.Equal(t, headerBytes, header)

		recoveredKid, recoveredCtr, _ := decodeHeader(header)
		require.Equal(t, kid, recoveredKid, "KID decode failure")
		require.Equal(t, ctr, recoveredCtr, "CTR decode failure")
	}
}

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

// https://sframe-wg.github.io/sframe/draft-ietf-sframe-enc.html#name-sframe-encryption-decryptio
func TestSFrameRoundTrip(t *testing.T) {
	// cipher_suite: 0x0001
	kidHex := "0000000000000123"
	ctrHex := "0000000000004567"
	baseKeyHex := "000102030405060708090a0b0c0d0e0f"
	// sframeKeyLabel := "534672616d6520312e3020536563726574206b65792000000000000001230001"
	// sframeSaltLabel := "534672616d6520312e30205365637265742073616c742000000000000001230001"
	// sframeSecret := "d926952ca8b7ec4a95941d1ada3a5203ceff8cceee34f574d23909eb314c40c0"
	// sframeKey := "3f7d9a7c83ae8e1c8a11ae695ab59314b367e359fadac7b9c46b2bc6f81f46e16b96f0811868d59402b7e870102720b3"
	// sframeSalt := "50b29329a04dc0f184ac3168"
	metadataHex := "4945544620534672616d65205747"
	// nonce := "50b29329a04dc0f184ac740f"
	// aad := "99012345674945544620534672616d65205747"
	plaintextHex := "64726166742d696574662d736672616d652d656e63"
	ciphertextHex := "9901234567449408b6f490086165b9d6f62b24ae1a59a56486b4ae8ed036b88912e24f11"

	kid := mustDecodeHexInt(kidHex)
	ctr := mustDecodeHexInt(ctrHex)
	baseKey := mustDecodeHex(baseKeyHex)
	metadata := mustDecodeHex(metadataHex)
	plaintext := mustDecodeHex(plaintextHex)
	ciphertext := mustDecodeHex(ciphertextHex)

	suite := AesCtr128HmacSha256Tag80Suite{}

	var err error
	kidMap := make(map[uint64]SFramerKey)
	kidMap[kid], err = NewSFramerKey(kid, baseKey, suite)
	require.Nil(t, err, "NewSFramerKey failed")
	sframer := SFramer{
		suite:    suite,
		keyStore: kidMap,
	}

	sframeCiphertext, err := sframer.Encrypt(ctr, kid, metadata, plaintext)
	require.Nil(t, err, "SFramer encrypt failed")
	require.Equal(t, sframeCiphertext, ciphertext, "SFramer encryption ciphertext mismatch")
}
