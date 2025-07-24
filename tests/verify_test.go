package test

import (
	"encoding/hex"
	"testing"

	bbs "github.com/Iscaraca/bbs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test vectors from BLS12-381-SHAKE-256 ciphersuite (Section 8.3)
const testPublicKeyHex = "92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb18fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5"

// Messages from Section 8.2
var testMessages = []string{
	"9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
	"c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80",
	"7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73",
	"77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c",
	"496694774c5604ab1b2544eababcf0f53278ff50",
	"515ae153e22aae04ad16f759e07237b4",
	"d183ddc6e2665aa4e2f088af",
	"ac55fb33a75909ed",
	"96012096",
	"",
}

func TestVerify_SingleMessage(t *testing.T) {
	// Test vector from spec Section 8.3.4.1
	headerHex := "11223344556677889900aabbccddeeff"
	header, err := hex.DecodeString(headerHex)
	require.NoError(t, err, "Failed to decode header")

	pkBytes, err := hex.DecodeString(testPublicKeyHex)
	require.NoError(t, err, "Failed to decode public key")

	messageHex := testMessages[0]
	message, err := hex.DecodeString(messageHex)
	require.NoError(t, err, "Failed to decode message")
	messages := [][]byte{message}

	// Expected signature from spec Section 8.3.4.1
	signatureHex := "b9a622a4b404e6ca4c85c15739d2124a1deb16df750be202e2430e169bc27fb71c44d98e6d40792033e1c452145ada95030832c5dc778334f2f1b528eced21b0b97a12025a283d78b7136bb9825d04ef"
	signature, err := hex.DecodeString(signatureHex)
	require.NoError(t, err, "Failed to decode signature")

	valid, err := bbs.Verify(pkBytes, signature, header, messages)
	require.NoError(t, err, "Verify should not fail")
	assert.True(t, valid, "Expected signature to be valid, but got invalid")
}

func TestVerify_MultiMessage(t *testing.T) {
	// Test vector from spec Section 8.3.4.2
	headerHex := "11223344556677889900aabbccddeeff"
	header, err := hex.DecodeString(headerHex)
	require.NoError(t, err, "Failed to decode header")

	pkBytes, err := hex.DecodeString(testPublicKeyHex)
	require.NoError(t, err, "Failed to decode public key")

	var messages [][]byte
	for i, msgHex := range testMessages {
		if msgHex == "" {
			messages = append(messages, []byte{})
		} else {
			msg, err := hex.DecodeString(msgHex)
			require.NoError(t, err, "Failed to decode message %d", i)
			messages = append(messages, msg)
		}
	}

	// Expected signature from spec Section 8.3.4.2
	signatureHex := "956a3427b1b8e3642e60e6a7990b67626811adeec7a0a6cb4f770cdd7c20cf08faabb913ac94d18e1e92832e924cb6e202912b624261fc6c59b0fea801547f67fb7d3253e1e2acbcf90ef59a6911931e"
	signature, err := hex.DecodeString(signatureHex)
	require.NoError(t, err, "Failed to decode signature")

	valid, err := bbs.Verify(pkBytes, signature, header, messages)
	require.NoError(t, err, "Verify should not fail")
	assert.True(t, valid, "Expected signature to be valid, but got invalid")
}
