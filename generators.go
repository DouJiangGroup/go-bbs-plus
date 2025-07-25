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
	_, _, _, g2Aff = bls12381.Generators()
)

func CreateP1() (bls12381.G1Affine, error) {
	ciphersuiteID := []byte(CIPHERSUITE_ID)

	seedDST := append(ciphersuiteID, []byte(H2G_HM2S_ID+SIG_GENERATOR_SEED_ID)...)
	generatorDST := append(ciphersuiteID, []byte(H2G_HM2S_ID+SIG_GENERATOR_DST_ID)...)
	generatorSeed := append(ciphersuiteID, []byte(H2G_HM2S_ID+BP_MESSAGE_GENERATOR_SEED_ID)...)

	v := ExpandMessageXOF(generatorSeed, seedDST, EXPAND_LEN)
	v = ExpandMessageXOF(append(v, I2OSP(1, 8)...), seedDST, EXPAND_LEN)

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

	v := ExpandMessageXOF(generatorSeed, seedDST, EXPAND_LEN)
	generators := make([]bls12381.G1Affine, 0, count)

	for i := uint64(1); i <= count; i++ {
		v = ExpandMessageXOF(append(v, I2OSP(int(i), 8)...), seedDST, EXPAND_LEN)
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
	pseudoRandomBytes := ExpandMessageXOF(msg, dst, lenInBytes)

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
