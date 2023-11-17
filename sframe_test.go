package sframe

import (
	"encoding/binary"
	"encoding/hex"
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

// https://sframe-wg.github.io/sframe/draft-ietf-sframe-enc.html#name-sframe-encryption-decryptio
func TestSFrameRoundTrip(t *testing.T) {

	var testVectors = []struct {
		cipherSuite   uint16
		kidHex        string
		ctrHex        string
		baseKeyHex    string
		metadataHex   string
		plaintextHex  string
		ciphertextHex string
	}{
		{
			cipherSuite:   0x0001,
			kidHex:        "0000000000000123",
			ctrHex:        "0000000000004567",
			baseKeyHex:    "000102030405060708090a0b0c0d0e0f",
			metadataHex:   "4945544620534672616d65205747",
			plaintextHex:  "64726166742d696574662d736672616d652d656e63",
			ciphertextHex: "9901234567449408b6f490086165b9d6f62b24ae1a59a56486b4ae8ed036b88912e24f11",
		},
		{
			cipherSuite:   0x0002,
			kidHex:        "0000000000000123",
			ctrHex:        "0000000000004567",
			baseKeyHex:    "000102030405060708090a0b0c0d0e0f",
			metadataHex:   "4945544620534672616d65205747",
			plaintextHex:  "64726166742d696574662d736672616d652d656e63",
			ciphertextHex: "99012345673f31438db4d09434e43afa0f8a2f00867a2be085046a9f5cb4f101d607",
		},
		{
			cipherSuite:   0x0003,
			kidHex:        "0000000000000123",
			ctrHex:        "0000000000004567",
			baseKeyHex:    "000102030405060708090a0b0c0d0e0f",
			metadataHex:   "4945544620534672616d65205747",
			plaintextHex:  "64726166742d696574662d736672616d652d656e63",
			ciphertextHex: "990123456717fc8af28a5a695afcfc6c8df6358a17e26b2fcb3bae32e443",
		},
		{
			cipherSuite:   0x0004,
			kidHex:        "0000000000000123",
			ctrHex:        "0000000000004567",
			baseKeyHex:    "000102030405060708090a0b0c0d0e0f",
			metadataHex:   "4945544620534672616d65205747",
			plaintextHex:  "64726166742d696574662d736672616d652d656e63",
			ciphertextHex: "9901234567b7412c2513a1b66dbb48841bbaf17f598751176ad847681a69c6d0b091c07018ce4adb34eb",
		},
		{
			cipherSuite:   0x0005,
			kidHex:        "0000000000000123",
			ctrHex:        "0000000000004567",
			baseKeyHex:    "000102030405060708090a0b0c0d0e0f",
			metadataHex:   "4945544620534672616d65205747",
			plaintextHex:  "64726166742d696574662d736672616d652d656e63",
			ciphertextHex: "990123456794f509d36e9beacb0e261d99c7d1e972f1fed787d4049f17ca21353c1cc24d56ceabced279",
		},
	}

	for _, vector := range testVectors {
		kid := mustDecodeHexInt(vector.kidHex)
		ctr := mustDecodeHexInt(vector.ctrHex)
		baseKey := mustDecodeHex(vector.baseKeyHex)
		metadata := mustDecodeHex(vector.metadataHex)
		plaintext := mustDecodeHex(vector.plaintextHex)
		ciphertext := mustDecodeHex(vector.ciphertextHex)

		suite, err := NewCiphersuite(vector.cipherSuite)
		if err == nil {
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
		} else {
			t.Logf("unsupported ciphersuite: %x\n", vector.cipherSuite)
		}
	}
}
