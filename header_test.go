package sframe

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

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
