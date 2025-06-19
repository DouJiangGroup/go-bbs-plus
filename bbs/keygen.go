package bbs

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"golang.org/x/crypto/sha3"
)

// expandMessageXOF implements expand_message_xof as defined in
// RFC 9380, Section 5.3.3 for SHAKE-256
func expandMessageXOF(msg []byte, dst []byte, lenInBytes int) []byte {
	shake := sha3.NewShake256()

	// Construct DST_prime = DST || I2OSP(len(DST), 1)
	dstPrime := append(dst, byte(len(dst)))

	// Input: msg || I2OSP(len_in_bytes, 2) || DST_prime
	shake.Write(msg)
	shake.Write(I2OSP(lenInBytes, 2))
	shake.Write(dstPrime)

	output := make([]byte, lenInBytes)
	shake.Read(output)
	return output
}

// GenerateRandomKeyMaterial generates cryptographically secure random key material
// This is a utility function to help generate proper key_material
func GenerateRandomKeyMaterial(length int) ([]byte, error) {
	if length < 32 {
		length = 32 // Minimum required length per spec
	}

	keyMaterial := make([]byte, length)
	_, err := rand.Read(keyMaterial)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random key material: %w", err)
	}

	return keyMaterial, nil
}

// KeyGen generates a secret key from key material
// SK = KeyGen(key_material, key_info, key_dst)
//
// Inputs:
//   - key_material (REQUIRED), a secret octet string. See requirements above.
//   - key_info (OPTIONAL), an octet string. s to an empty string if not supplied.
//   - key_dst (OPTIONAL), an octet string representing the domain separation tag.
//     s to the octet string ciphersuite_id || "KEYGEN_DST_"
//     if not supplied.
//
// Outputs:
// - SK, a uniformly random integer such that 0 < SK < r.
//
// Procedure:
// 1. if length(key_material) < 32, return INVALID
// 2. if length(key_info) > 65535, return INVALID
// 3. derive_input = key_material || I2OSP(length(key_info), 2) || key_info
// 4. SK = hash_to_scalar(derive_input, key_dst)
// 5. if SK is INVALID, return INVALID
// 6. return SK
func KeyGen(keyMaterial []byte, keyInfo []byte, keyDst []byte) (fr.Element, error) {
	var sk fr.Element

	// 1. if length(key_material) < 32, return INVALID
	if len(keyMaterial) < 32 {
		return sk, errors.New("INVALID: key_material must be at least 32 bytes")
	}

	// 2. if length(key_info) > 65535, return INVALID
	if len(keyInfo) > 65535 {
		return sk, errors.New("INVALID: key_info must be at most 65535 bytes")
	}

	// Handle optional parameters with correct s
	if keyInfo == nil {
		keyInfo = []byte{} //  to empty string
	}
	if keyDst == nil {
		keyDst = []byte(KeygenDST) //  DST
	}

	// 3. derive_input = key_material || I2OSP(length(key_info), 2) || key_info
	keyInfoLen := I2OSP(len(keyInfo), 2)
	deriveInput := make([]byte, 0, len(keyMaterial)+2+len(keyInfo))
	deriveInput = append(deriveInput, keyMaterial...)
	deriveInput = append(deriveInput, keyInfoLen...)
	deriveInput = append(deriveInput, keyInfo...)

	// 4. SK = hash_to_scalar(derive_input, key_dst)
	sk, err := hashToScalar(deriveInput, keyDst)
	if err != nil {
		// 5. if SK is INVALID, return INVALID
		return sk, fmt.Errorf("INVALID: hash_to_scalar failed: %w", err)
	}

	// 6. return SK
	return sk, nil
}

// SkToPk generates a public key from a secret key
// W = SkToPk(SK)
//
// Inputs:
// - SK, a uniformly random secret integer such that 0 < SK < r.
//
// Outputs:
// - PK, a public key encoded as an octet string.
//
// 1. W = SK * BP2
// 2. return point_to_octets_g2(W)
func SkToPk(sk fr.Element) ([]byte, error) {
	var pk bls12381.G2Affine
	var skBigInt big.Int
	sk.BigInt(&skBigInt)
	pk.ScalarMultiplication(&g2Aff, &skBigInt)
	return PointToOctetsG2(pk), nil
}
