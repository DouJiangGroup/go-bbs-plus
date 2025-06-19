package bbs

import (
	"errors"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// mapToScalarAsHash implements map_to_scalar_as_hash from Section 4.3.1.1
//
// Inputs:
// - msg, an octet string.
// - dst, an octet string representing the domain separation tag.
//
// Outputs:
// - scalar, a scalar.
//
// Procedure:
// 1. uniform_bytes = expand_message(msg, dst, expand_len)
// 2. scalar = OS2IP(uniform_bytes) mod r
// 3. if scalar == 0, return INVALID
// 4. return scalar
func mapToScalarAsHash(msg []byte, dst []byte) (fr.Element, error) {
	var scalar fr.Element

	// 1. uniform_bytes = expand_message(msg, dst, expand_len)
	uniformBytes := expandMessageXOF(msg, dst, ExpandLen)

	// 2. scalar = OS2IP(uniform_bytes) mod r
	// SetBytes interprets uniformBytes as big-endian integer and reduces mod r
	scalar.SetBytes(uniformBytes)

	// 3. if scalar == 0, return INVALID
	if scalar.IsZero() {
		return scalar, errors.New("INVALID: scalar is zero")
	}

	// 4. return scalar
	return scalar, nil
}

// hashToScalar implements hash_to_scalar using map_to_scalar_as_hash
// as specified in Section 6.2.1 (map_to_scalar: map_to_scalar_as_hash)
func hashToScalar(msg []byte, dst []byte) (fr.Element, error) {
	return mapToScalarAsHash(msg, dst)
}

// MessagesToScalars maps a list of input messages as octet strings
// to their respective scalar values, required by Sign, Verify, ProofGen,
// and ProofVerify
func MessagesToScalars(messages [][]byte) []fr.Element {
	dst := []byte(CiphersuiteID + "MAP_MSG_TO_SCALAR_AS_HASH_")
	scalars := make([]fr.Element, len(messages))

	for i, msg := range messages {
		msgCopy := append([]byte{}, msg...)
		scalar, _ := hashToScalar(msgCopy, dst)
		scalars[i] = scalar
	}

	return scalars
}
