package bbs

import (
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

func Verify(pkBytes []byte, signature []byte, header []byte, messages [][]byte) (bool, error) {
	if header == nil {
		header = []byte{}
	}
	if messages == nil {
		messages = [][]byte{}
	}

	A, e, err := OctetsToSignature(signature)
	if err != nil {
		return false, err
	}

	W, err := OctetsToPublicKey(pkBytes)
	if err != nil {
		return false, err
	}

	L := len(messages)
	msgScalars := MessagesToScalars(messages)

	// 1. (Q_1, H_1, ..., H_L) = create_generators(L+1, PK)
	pk, err := OctetsToPointG2(pkBytes)
	if err != nil {
		return false, err
	}

	generators, err := CreateGenerators(uint64(L+1), pk)
	if err != nil {
		return false, err
	}
	Q1 := generators[0]
	H := generators[1:]

	domain, err := CalculateDomain(pkBytes, Q1, H, header)
	if err != nil {
		return false, err
	}

	// 4. B = P1 + Q_1 * domain + H_1 * msg_1 + ... + H_L * msg_L
	var B bls12381.G1Jac
	P1 := GetP1()
	B.FromAffine(&P1)

	// Q_1 * domain
	var tmpQ bls12381.G1Jac
	tmpQJac := bls12381.G1Jac{}
	tmpQJac.FromAffine(&Q1)
	tmpQ.ScalarMultiplication(&tmpQJac, domain.BigInt(new(big.Int)))
	B.AddAssign(&tmpQ)

	// H_i * msg_i
	for i := 0; i < L; i++ {
		var tmpH bls12381.G1Jac
		tmpHJac := bls12381.G1Jac{}
		tmpHJac.FromAffine(&H[i])
		tmpH.ScalarMultiplication(&tmpHJac, msgScalars[i].BigInt(new(big.Int)))
		B.AddAssign(&tmpH)
	}

	var BAffine bls12381.G1Affine
	BAffine.FromJacobian(&B)

	var BP2ScalarMult bls12381.G2Jac
	BP2Jac := bls12381.G2Jac{}
	BP2Jac.FromAffine(&g2Aff)
	BP2ScalarMult.ScalarMultiplication(&BP2Jac, e.BigInt(new(big.Int)))

	// Compute W + BP2 * e
	var WPlusBP2e bls12381.G2Jac
	WJac := bls12381.G2Jac{}
	WJac.FromAffine(&W)
	WPlusBP2e.Set(&WJac)
	WPlusBP2e.AddAssign(&BP2ScalarMult)

	var WPlusBP2eAffine bls12381.G2Affine
	WPlusBP2eAffine.FromJacobian(&WPlusBP2e)

	// Compute -BP2
	var negBP2 bls12381.G2Affine
	negBP2.Neg(&g2Aff)

	// Compute pairings: e(A, W + BP2 * e) * e(B, -BP2)
	pairing1, err := bls12381.Pair([]bls12381.G1Affine{A}, []bls12381.G2Affine{WPlusBP2eAffine})
	if err != nil {
		return false, err
	}

	pairing2, err := bls12381.Pair([]bls12381.G1Affine{BAffine}, []bls12381.G2Affine{negBP2})
	if err != nil {
		return false, err
	}

	// Multiply pairings
	result := pairing1
	result.Mul(&result, &pairing2)

	// 5. Check if result equals identity in GT
	if result.IsOne() {
		return true, nil // VALID
	}

	return false, nil // INVALID
}
