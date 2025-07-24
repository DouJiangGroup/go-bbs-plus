package bbs

import (
	"errors"
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// Verify validates a BBS signature. See BBS spec section 3.5.2
func Verify(pkBytes []byte, signature []byte, header []byte, messages [][]byte) (bool, error) {
	if header == nil {
		header = []byte{}
	}
	if messages == nil {
		messages = [][]byte{}
	}

	if len(pkBytes) != OCTET_POINT_LENGTH*2 {
		return false, errors.New("INVALID: public key length")
	}
	if len(signature) != OCTET_POINT_LENGTH+OCTET_SCALAR_LENGTH {
		return false, errors.New("INVALID: signature length")
	}

	apiID := []byte(CIPHERSUITE_ID + H2G_HM2S_ID)

	messageScalars, err := MessagesToScalars(messages, apiID)
	if err != nil {
		return false, fmt.Errorf("failed to convert messages to scalars: %w", err)
	}

	generators, err := CreateGenerators(uint64(len(messages))+1, apiID)
	if err != nil {
		return false, err
	}

	return CoreVerify(pkBytes, signature, generators, header, messageScalars, apiID)
}

// CoreVerify checks that a signature is valid. See BBS spec section 3.6.2
func CoreVerify(pkBytes []byte, signature []byte, generators []bls12381.G1Affine, header []byte, messages []fr.Element, apiID []byte) (bool, error) {
	if header == nil {
		header = []byte{}
	}
	if messages == nil {
		messages = []fr.Element{}
	}
	if apiID == nil {
		apiID = []byte{}
	}

	// Deserialization steps 1-3: signature_result = octets_to_signature(signature)
	A, e, err := OctetsToSignature(signature)
	if err != nil {
		return false, err // signature_result is INVALID
	}

	// Deserialization steps 4-5: W = octets_to_pubkey(PK)
	W, err := OctetsToPublicKey(pkBytes)
	if err != nil {
		return false, err // W is INVALID
	}

	// Deserialization steps 6-9
	L := len(messages)
	if len(generators) != L+1 {
		return false, errors.New("INVALID: generators length")
	}

	Q1 := generators[0]
	H := generators[1:]

	// Step 1: domain = calculate_domain(PK, Q_1, (H_1, ..., H_L), header, api_id)
	domain, err := CalculateDomain(pkBytes, Q1, H, header, apiID)
	if err != nil {
		return false, err
	}

	// Step 2: B = P1 + Q_1 * domain + H_1 * msg_1 + ... + H_L * msg_L
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

	var BAffine bls12381.G1Affine
	BAffine.FromJacobian(&B)

	// Step 3: Pairing verification
	// The spec shows: if h(A, W) * h(A * e - B, BP2) != Identity_GT, return INVALID
	// But the standard BBS verification is: e(A, W + BP2 * e) * e(B, -BP2) = 1
	// We'll use the latter form which is mathematically equivalent and standard

	var BP2ScalarMult bls12381.G2Jac
	BP2Jac := bls12381.G2Jac{}
	BP2Jac.FromAffine(&g2Aff) // BP2 is the G2 generator
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

	// Check if result equals identity in GT
	if result.IsOne() {
		return true, nil // VALID
	}

	return false, nil // INVALID
}
