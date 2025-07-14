package bbs

import (
	"encoding/hex"
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/hash_to_curve"
)

var (
	_, _, g1Aff, g2Aff = bls12381.Generators()
)

func CreateP1() (bls12381.G1Affine, error) {
	v := expandMessageXOF([]byte(P1GeneratorSeed), []byte(SeedDST), ExpandLen)
	v = expandMessageXOF(append(v, I2OSP(1, 8)...), []byte(SeedDST), ExpandLen)

	p1, err := hashToG1SHAKE256(v, []byte(GeneratorDST))
	if err != nil {
		return bls12381.G1Affine{}, fmt.Errorf("INVALID: hash_to_curve failed: %w", err)
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

func CreateGenerators(count uint64, pk bls12381.G2Affine) ([]bls12381.G1Affine, error) {
	return hashToGenerators(count)
}

func hashToGenerators(count uint64) ([]bls12381.G1Affine, error) {
	v := expandMessageXOF([]byte(GeneratorSeed), []byte(SeedDST), ExpandLen)
	generators := make([]bls12381.G1Affine, 0, count)
	for i := uint64(1); i <= count; i++ {
		v = expandMessageXOF(append(v, I2OSP(int(i), 8)...), []byte(SeedDST), ExpandLen)
		generatorI, err := hashToG1SHAKE256(v, []byte(GeneratorDST))
		if err != nil {
			return generators, fmt.Errorf("INVALID: hash_to_scalar failed: %w", err)
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
	// Step 1: Hash to field using SHAKE-256 (get 2 field elements)
	u, err := hashToFieldSHAKE256(msg, dst, 2*1)
	if err != nil {
		return bls12381.G1Affine{}, err
	}

	// Step 2: Map each field element to curve using SSWU
	Q0 := bls12381.MapToCurve1(&u[0])
	Q1 := bls12381.MapToCurve1(&u[1])

	// Step 3: Apply isogeny map to get points on target curve E (not E')
	hash_to_curve.G1Isogeny(&Q0.X, &Q0.Y)
	hash_to_curve.G1Isogeny(&Q1.X, &Q1.Y)

	// Step 4: Add the two points together (in Jacobian coordinates for efficiency)
	var _Q0, _Q1 bls12381.G1Jac
	_Q0.FromAffine(&Q0)
	_Q1.FromAffine(&Q1).AddAssign(&_Q0)

	// Step 5: Clear cofactor to ensure we're in the prime-order subgroup
	_Q1.ClearCofactor(&_Q1)

	// Step 6: Convert back to affine coordinates
	var result bls12381.G1Affine
	result.FromJacobian(&_Q1)
	return result, nil
}

// HashToG2SHAKE256 hashes a message to a point on the G2 curve using the SSWU map
// with SHAKE-256 expand_message_xof (implementing BLS12381G2_XOF:SHAKE-256_SSWU_RO_).
func hashToG2SHAKE256(msg, dst []byte) (bls12381.G2Affine, error) {
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

	return result, nil
}
