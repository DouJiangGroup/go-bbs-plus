package bbs

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

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

	// Step 1: if length(key_material) < 32, return INVALID
	if len(keyMaterial) < 32 {
		return sk, errors.New("INVALID: key_material must be at least 32 bytes")
	}

	// Step 2: if length(key_info) > 65535, return INVALID
	if len(keyInfo) > 65535 {
		return sk, errors.New("INVALID: key_info must be at most 65535 bytes")
	}

	if keyInfo == nil {
		keyInfo = []byte{}
	}
	if keyDst == nil {
		keyDst = []byte(CIPHERSUITE_ID + H2G_HM2S_ID + KEYGEN_DST_ID)
	}

	// Step 3: derive_input = key_material || I2OSP(length(key_info), 2) || key_info
	keyInfoLen := I2OSP(len(keyInfo), 2)
	deriveInput := make([]byte, 0, len(keyMaterial)+2+len(keyInfo))
	deriveInput = append(deriveInput, keyMaterial...)
	deriveInput = append(deriveInput, keyInfoLen...)
	deriveInput = append(deriveInput, keyInfo...)

	// Step 4: SK = hash_to_scalar(derive_input, key_dst)
	sk, err := HashToScalarlar(deriveInput, keyDst)
	if err != nil {
		return sk, fmt.Errorf("INVALID: hash_to_scalar failed: %w", err)
	}

	// Step 5: return SK
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
	if sk.IsZero() {
		return nil, errors.New("INVALID: secret key cannot be zero")
	}

	var pk bls12381.G2Affine
	var skBigInt big.Int
	sk.BigInt(&skBigInt)
	pk.ScalarMultiplication(&g2Aff, &skBigInt)

	if pk.IsInfinity() {
		return nil, errors.New("INVALID: public key cannot be identity")
	}

	return PointToOctetsG2(pk), nil
}
