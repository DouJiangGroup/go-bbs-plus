package test

import (
	"encoding/hex"
	"testing"

	bbs "github.com/Iscaraca/bbs"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMapMessagesToScalars(t *testing.T) {
	// Test vector inputs - messages from Section 8.2 of spec
	messages := []string{
		"9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
		"c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80",
		"7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73",
		"77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c",
		"496694774c5604ab1b2544eababcf0f53278ff50",
		"515ae153e22aae04ad16f759e07237b4",
		"d183ddc6e2665aa4e2f088af",
		"ac55fb33a75909ed",
		"96012096",
		""}

	// Expected scalar values from spec Section 8.3.2
	expectedScalars := []string{
		"1e0dea6c9ea8543731d331a0ab5f64954c188542b33c5bbc8ae5b3a830f2d99f",
		"3918a40fb277b4c796805d1371931e08a314a8bf8200a92463c06054d2c56a9f",
		"6642b981edf862adf34214d933c5d042bfa8f7ef343165c325131e2ffa32fa94",
		"33c021236956a2006f547e22ff8790c9d2d40c11770c18cce6037786c6f23512",
		"52b249313abbe323e7d84230550f448d99edfb6529dec8c4e783dbd6dd2a8471",
		"2a50bdcbe7299e47e1046100aadffe35b4247bf3f059d525f921537484dd54fc",
		"0e92550915e275f8cfd6da5e08e334d8ef46797ee28fa29de40a1ebccd9d95d3",
		"4c28f612e6c6f82f51f95e1e4faaf597547f93f6689827a6dcda3cb94971d356",
		"1db51bedc825b85efe1dab3e3ab0274fa82bbd39732be3459525faf70f197650",
		"27878da72f7775e709bb693d81b819dc4e9fa60711f4ea927740e40073489e78"}

	msgBytesSlice := make([][]byte, len(messages))
	for i, msg := range messages {
		msgBytes, err := hex.DecodeString(msg)
		require.NoError(t, err, "Failed to decode message hex at index %d", i)
		msgBytesSlice[i] = msgBytes
	}

	// Use proper api_id for BLS12-381-SHAKE-256 ciphersuite
	apiID := []byte(bbs.CIPHERSUITE_ID + bbs.H2G_HM2S_ID)
	scalars, err := bbs.MessagesToScalars(msgBytesSlice, apiID)
	require.NoError(t, err, "MessagesToScalars should not fail")
	require.Len(t, scalars, len(expectedScalars), "Should return correct number of scalars")

	// Compare each generated scalar with expected value from spec
	for i, expectedScalarHex := range expectedScalars {
		expectedScalarBytes, err := hex.DecodeString(expectedScalarHex)
		require.NoError(t, err, "Failed to decode expected scalar hex at index %d", i)

		var expectedScalar fr.Element
		expectedScalar.SetBytes(expectedScalarBytes)

		assert.True(t, scalars[i].Equal(&expectedScalar),
			"Scalar %d does not match expected value from specification", i)
	}
}
