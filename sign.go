package bbs

import (
	"errors"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// Compute deterministic signature from SK (optionally over a header and vector of input messages)
func Sign(sk fr.Element, pkBytes []byte, header []byte, messages [][]byte) ([]byte, error) {
	if header == nil {
		header = []byte{}
	}
	if messages == nil {
		messages = [][]byte{}
	}
	L := len(messages)
	msgScalars := MessagesToScalars(messages)
	pk, err := OctetsToPointG2(pkBytes)
	if err != nil {
		return nil, err
	}

	// 1. (Q_1, H_1, ..., H_L) = create_generators(L+1, PK)
	generators, err := CreateGenerators(uint64(L+1), pk)
	if err != nil {
		return nil, err
	}
	Q1 := generators[0]
	H := generators[1:]

	// 2. domain = calculate_domain(PK, Q_1, (H_1, ..., H_L), header)
	domain, err := CalculateDomain(pkBytes, Q1, H, header)
	if err != nil {
		return nil, err
	}

	// 3. e = hash_to_scalar(serialize((SK, domain, msg_1, ..., msg_L)))
	serializeInputs := []interface{}{sk, domain}
	for _, m := range msgScalars {
		serializeInputs = append(serializeInputs, m)
	}
	ser, err := Serialize(serializeInputs...)
	if err != nil {
		return nil, err
	}
	// USE DEFAULT DST
	e, err := hashToScalar(ser, nil)
	if err != nil {
		return nil, err
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

	// 5. A = B * (1 / (SK + e))
	var denom fr.Element
	denom.Add(&sk, &e)
	if denom.IsZero() {
		return nil, errors.New("INVALID: SK + e = 0")
	}
	var denomInv fr.Element
	denomInv.Inverse(&denom)
	B.ScalarMultiplication(&B, denomInv.BigInt(new(big.Int)))
	A := bls12381.G1Affine{}
	A.FromJacobian(&B)
	if A.IsInfinity() {
		return nil, errors.New("INVALID: signature point is identity")
	}

	// 6. return signature_to_octets(A, e)
	return SignatureToOctets(A, e)
}
