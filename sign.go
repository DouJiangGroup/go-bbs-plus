package bbs

import (
	"errors"
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// Sign returns a BBS signature from a secret key. See BBS spec section 3.5.1
func Sign(sk fr.Element, pkBytes []byte, header []byte, messages [][]byte) ([]byte, error) {
	if header == nil {
		header = []byte{}
	}
	if messages == nil {
		messages = [][]byte{}
	}

	if sk.IsZero() {
		return nil, errors.New("INVALID: secret key cannot be zero")
	}
	if len(pkBytes) != OCTET_POINT_LENGTH*2 {
		return nil, errors.New("INVALID: public key length")
	}

	apiID := []byte(CIPHERSUITE_ID + H2G_HM2S_ID)

	messageScalars, err := MessagesToScalars(messages, apiID)
	if err != nil {
		return nil, fmt.Errorf("failed to convert messages to scalars: %w", err)
	}

	generators, err := CreateGenerators(uint64(len(messages))+1, apiID)
	if err != nil {
		return nil, err
	}

	return CoreSign(sk, pkBytes, generators, header, messageScalars, apiID)
}

// CoreSign computes a deterministic signature. See BBS spec section 3.6.1
func CoreSign(sk fr.Element, pkBytes []byte, generators []bls12381.G1Affine, header []byte, messages []fr.Element, apiID []byte) ([]byte, error) {
	if header == nil {
		header = []byte{}
	}
	if messages == nil {
		messages = []fr.Element{}
	}
	if apiID == nil {
		apiID = []byte{}
	}
	if sk.IsZero() {
		return nil, errors.New("INVALID: secret key cannot be zero")
	}
	if len(pkBytes) != OCTET_POINT_LENGTH*2 {
		return nil, errors.New("INVALID: public key length")
	}

	L := len(messages)
	if len(generators) != L+1 {
		return nil, errors.New("INVALID: generators length")
	}

	Q1 := generators[0]
	H := generators[1:]

	// Step 1: domain = calculate_domain(PK, Q_1, (H_1, ..., H_L), header, api_id)
	domain, err := CalculateDomain(pkBytes, Q1, H, header, apiID)
	if err != nil {
		return nil, err
	}

	// Step 2: e = hash_to_scalar(serialize((SK, msg_1, ..., msg_L, domain)), hash_to_scalar_dst)
	// Order is (SK, msg_1, ..., msg_L, domain)
	serializeInputs := []interface{}{sk}
	for _, m := range messages {
		serializeInputs = append(serializeInputs, m)
	}
	serializeInputs = append(serializeInputs, domain)

	ser, err := Serialize(serializeInputs...)
	if err != nil {
		return nil, err
	}

	// hash_to_scalar_dst = api_id || "H2S_"
	hashToScalarDST := append(apiID, []byte("H2S_")...)
	e, err := hashToScalar(ser, hashToScalarDST)
	if err != nil {
		return nil, err
	}

	// Step 3: B = P1 + Q_1 * domain + H_1 * msg_1 + ... + H_L * msg_L
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
		tmpH.ScalarMultiplication(&tmpHJac, messages[i].BigInt(new(big.Int)))
		B.AddAssign(&tmpH)
	}

	// Step 4: A = B * (1 / (SK + e))
	// Check for the extremely rare case where (SK + e) = 0 mod r
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

	return SignatureToOctets(A, e)
}
