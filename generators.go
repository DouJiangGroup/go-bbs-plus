package bbs

import (
	"encoding/hex"
	"errors"
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/hash_to_curve"
)

var (
	_, _, g1Aff, g2Aff = bls12381.Generators()
)

func CreateP1() (bls12381.G1Affine, error) {
	ciphersuiteID := []byte(CIPHERSUITE_ID)

	seedDST := append(ciphersuiteID, []byte(H2G_HM2S_ID+SIG_GENERATOR_SEED_ID)...)
	generatorDST := append(ciphersuiteID, []byte(H2G_HM2S_ID+SIG_GENERATOR_DST_ID)...)
	generatorSeed := append(ciphersuiteID, []byte(H2G_HM2S_ID+BP_MESSAGE_GENERATOR_SEED_ID)...)

	v := expandMessageXOF(generatorSeed, seedDST, EXPAND_LEN)
	v = expandMessageXOF(append(v, I2OSP(1, 8)...), seedDST, EXPAND_LEN)

	p1, err := hashToG1SHAKE256(v, generatorDST)
	if err != nil {
		return bls12381.G1Affine{}, fmt.Errorf("INVALID: hash_to_curve failed: %w", err)
	}

	if p1.IsInfinity() {
		return bls12381.G1Affine{}, errors.New("INVALID: P1 cannot be infinity")
	}

	return p1, nil
}

// More efficient, cached version
func GetP1() bls12381.G1Affine {
	p1Bytes, _ := hex.DecodeString(P1Hex)
	var p1 bls12381.G1Affine
	p1.SetBytes(p1Bytes)
	return p1
}

func CreateGenerators(count uint64, apiID []byte) ([]bls12381.G1Affine, error) {
	if apiID == nil {
		apiID = []byte{}
	}

	if count == 0 {
		return []bls12381.G1Affine{}, nil
	}

	seedDST := append(apiID, []byte(SIG_GENERATOR_SEED_ID)...)
	generatorDST := append(apiID, []byte(SIG_GENERATOR_DST_ID)...)
	generatorSeed := append(apiID, []byte(MESSAGE_GENERATOR_SEED_ID)...)

	v := expandMessageXOF(generatorSeed, seedDST, EXPAND_LEN)
	generators := make([]bls12381.G1Affine, 0, count)

	for i := uint64(1); i <= count; i++ {
		v = expandMessageXOF(append(v, I2OSP(int(i), 8)...), seedDST, EXPAND_LEN)
		generatorI, err := hashToG1SHAKE256(v, generatorDST)
		if err != nil {
			return generators, fmt.Errorf("INVALID: hash_to_curve failed at index %d: %w", i-1, err)
		}

		if generatorI.IsInfinity() {
			return generators, fmt.Errorf("INVALID: generator %d is infinity", i-1)
		}

		generators = append(generators, generatorI)
	}
	return generators, nil
}

// hashToFieldSHAKE256 hashes msg to count prime field elements using SHAKE-256.
// This replaces fp.Hash() to use expand_message_xof instead of expand_message_xmd.
func hashToFieldSHAKE256(msg, dst []byte, count int) ([]fp.Element, error) {
	// 128 bits of security for BLS12-381
	// L = ceil((ceil(log2(p)) + k) / 8), where k is the security parameter = 128
	// For BLS12-381: Bits = 381, so:
	const Bits = 381             // BLS12-381 prime field bit length
	const Bytes = 1 + (Bits-1)/8 // = 1 + 380/8 = 48
	const L = 16 + Bytes         // = 16 + 48 = 64 (security parameter + field size)

	lenInBytes := count * L

	// Use SHAKE-256 expand_message_xof instead of SHA-256 expand_message_xmd
	pseudoRandomBytes := expandMessageXOF(msg, dst, lenInBytes)

	res := make([]fp.Element, count)
	for i := 0; i < count; i++ {
		// Convert each L-byte chunk to a field element
		var element fp.Element
		element.SetBytes(pseudoRandomBytes[i*L : (i+1)*L])
		res[i] = element
	}

	return res, nil
}

// HashToG1SHAKE256 hashes a message to a point on the G1 curve using the SSWU map
// with SHAKE-256 expand_message_xof (implementing BLS12381G1_XOF:SHAKE-256_SSWU_RO_).
func hashToG1SHAKE256(msg, dst []byte) (bls12381.G1Affine, error) {
	if len(dst) == 0 {
		return bls12381.G1Affine{}, errors.New("INVALID: empty domain separation tag")
	}

	u, err := hashToFieldSHAKE256(msg, dst, 2*1)
	if err != nil {
		return bls12381.G1Affine{}, err
	}

	Q0 := bls12381.MapToCurve1(&u[0])
	Q1 := bls12381.MapToCurve1(&u[1])

	hash_to_curve.G1Isogeny(&Q0.X, &Q0.Y)
	hash_to_curve.G1Isogeny(&Q1.X, &Q1.Y)

	var _Q0, _Q1 bls12381.G1Jac
	_Q0.FromAffine(&Q0)
	_Q1.FromAffine(&Q1).AddAssign(&_Q0)
	_Q1.ClearCofactor(&_Q1)

	var result bls12381.G1Affine
	result.FromJacobian(&_Q1)

	if result.IsInfinity() {
		return result, errors.New("INVALID: hash_to_curve resulted in infinity")
	}

	return result, nil
}

// HashToG2SHAKE256 hashes a message to a point on the G2 curve using the SSWU map
// with SHAKE-256 expand_message_xof (implementing BLS12381G2_XOF:SHAKE-256_SSWU_RO_).
func hashToG2SHAKE256(msg, dst []byte) (bls12381.G2Affine, error) {
	if len(dst) == 0 {
		return bls12381.G2Affine{}, errors.New("INVALID: empty domain separation tag")
	}

	// Step 1: Hash to field using SHAKE-256 (get 2 field elements, each with 2 components for Fp2)
	// G2 points have coordinates in Fp2, so we need 2*2=4 field elements total
	u, err := hashToFieldSHAKE256(msg, dst, 2*2)
	if err != nil {
		return bls12381.G2Affine{}, err
	}

	// Step 2: Construct Fp2 elements from the 4 field elements
	var u0, u1 bls12381.E2
	u0.A0 = u[0] // Real part of first Fp2 element
	u0.A1 = u[1] // Imaginary part of first Fp2 element
	u1.A0 = u[2] // Real part of second Fp2 element
	u1.A1 = u[3] // Imaginary part of second Fp2 element

	// Step 3: Map each Fp2 element to curve using SSWU
	Q0 := bls12381.MapToCurve2(&u0)
	Q1 := bls12381.MapToCurve2(&u1)

	// Step 4: Apply isogeny map to get points on target curve E2 (not E2')
	hash_to_curve.G2Isogeny(&Q0.X, &Q0.Y)
	hash_to_curve.G2Isogeny(&Q1.X, &Q1.Y)

	// Step 5: Add the two points together (in Jacobian coordinates for efficiency)
	var _Q0, _Q1 bls12381.G2Jac
	_Q0.FromAffine(&Q0)
	_Q1.FromAffine(&Q1)
	_Q1.AddAssign(&_Q0)

	// Step 6: Clear cofactor to ensure we're in the prime-order subgroup
	_Q1.ClearCofactor(&_Q1)

	// Step 7: Convert back to affine coordinates
	var result bls12381.G2Affine
	result.FromJacobian(&_Q1)

	if result.IsInfinity() {
		return result, errors.New("INVALID: hash_to_curve resulted in infinity")
	}

	return result, nil
}
