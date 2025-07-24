package test

import (
	"encoding/hex"
	"testing"

	bbs "github.com/Iscaraca/bbs"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidSingleMessageSignature(t *testing.T) {
	// Test vector from spec Section 8.3.4.1
	msgHex := "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"
	skHex := "2eee0f60a8a3a8bec0ee942bfd46cbdae9a0738ee68f5a64e7238311cf09a079"
	pkHex := "92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb18fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5"
	headerHex := "11223344556677889900aabbccddeeff"
	// Expected signature from spec Section 8.3.4.1
	expectedSigHex := "b9a622a4b404e6ca4c85c15739d2124a1deb16df750be202e2430e169bc27fb71c44d98e6d40792033e1c452145ada95030832c5dc778334f2f1b528eced21b0b97a12025a283d78b7136bb9825d04ef"

	msg, err := hex.DecodeString(msgHex)
	require.NoError(t, err, "Failed to decode message")
	skBytes, err := hex.DecodeString(skHex)
	require.NoError(t, err, "Failed to decode secret key")
	pkBytes, err := hex.DecodeString(pkHex)
	require.NoError(t, err, "Failed to decode public key")
	header, err := hex.DecodeString(headerHex)
	require.NoError(t, err, "Failed to decode header")
	expectedSig, err := hex.DecodeString(expectedSigHex)
	require.NoError(t, err, "Failed to decode expected signature")

	var sk fr.Element
	sk.SetBytes(skBytes)

	sig, err := bbs.Sign(sk, pkBytes, header, [][]byte{msg})
	require.NoError(t, err, "Sign should not fail")
	assert.Equal(t, expectedSig, sig, "Signature does not match expected value from specification")
}

func TestValidMultiMessageSignature(t *testing.T) {
	var err error
	// Test vector from spec Section 8.3.4.2
	msgsHex := []string{
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
	skHex := "2eee0f60a8a3a8bec0ee942bfd46cbdae9a0738ee68f5a64e7238311cf09a079"
	pkHex := "92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb18fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5"
	headerHex := "11223344556677889900aabbccddeeff"
	// Expected signature from spec Section 8.3.4.2
	expectedSigHex := "956a3427b1b8e3642e60e6a7990b67626811adeec7a0a6cb4f770cdd7c20cf08faabb913ac94d18e1e92832e924cb6e202912b624261fc6c59b0fea801547f67fb7d3253e1e2acbcf90ef59a6911931e"

	msgs := make([][]byte, len(msgsHex))
	for i, m := range msgsHex {
		msgs[i], err = hex.DecodeString(m)
		require.NoError(t, err, "Failed to decode message %d", i)
	}
	skBytes, err := hex.DecodeString(skHex)
	require.NoError(t, err, "Failed to decode secret key")
	pkBytes, err := hex.DecodeString(pkHex)
	require.NoError(t, err, "Failed to decode public key")
	header, err := hex.DecodeString(headerHex)
	require.NoError(t, err, "Failed to decode header")
	expectedSig, err := hex.DecodeString(expectedSigHex)
	require.NoError(t, err, "Failed to decode expected signature")

	var sk fr.Element
	sk.SetBytes(skBytes)

	sig, err := bbs.Sign(sk, pkBytes, header, msgs)
	require.NoError(t, err, "Sign should not fail")
	assert.Equal(t, expectedSig, sig, "Multi-message signature does not match expected value from specification")
}
