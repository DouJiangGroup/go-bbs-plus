package test

import (
	"encoding/hex"
	"testing"

	bbs "github.com/Iscaraca/bbs"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyGenVectors(t *testing.T) {
	// Test vector inputs from BBS spec Section 8.3.1
	keyMaterialHex := "746869732d49532d6a7573742d616e2d546573742d494b4d2d746f2d67656e65726174652d246528724074232d6b6579"
	keyInfoHex := "746869732d49532d736f6d652d6b65792d6d657461646174612d746f2d62652d757365642d696e2d746573742d6b65792d67656e"

	// Expected values from spec Section 8.3.1
	expectedSKHex := "2eee0f60a8a3a8bec0ee942bfd46cbdae9a0738ee68f5a64e7238311cf09a079"
	expectedPKHex := "92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb18fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5"

	// Convert hex strings to byte arrays
	keyMaterial, err := hex.DecodeString(keyMaterialHex)
	require.NoError(t, err, "Failed to decode key material hex")

	keyInfo, err := hex.DecodeString(keyInfoHex)
	require.NoError(t, err, "Failed to decode key info hex")

	expectedSKBytes, err := hex.DecodeString(expectedSKHex)
	require.NoError(t, err, "Failed to decode expected SK hex")

	expectedPKBytes, err := hex.DecodeString(expectedPKHex)
	require.NoError(t, err, "Failed to decode expected PK hex")

	// Convert expected SK bytes to fr.Element
	var expectedSK fr.Element
	expectedSK.SetBytes(expectedSKBytes)

	// Generate secret key using the test vectors
	sk, err := bbs.KeyGen(keyMaterial, keyInfo, nil)
	require.NoError(t, err, "KeyGen should not fail")

	// Compare the generated key with the expected key
	assert.True(t, sk.Equal(&expectedSK), "Generated secret key does not match expected value")

	// Test PK generation
	pk, err := bbs.SkToPk(sk)
	require.NoError(t, err, "SkToPk should not fail")

	// Compare the generated public key bytes with expected bytes
	assert.Equal(t, expectedPKBytes, pk, "Generated public key does not match expected value")
}
