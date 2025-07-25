package bbs

import (
	"errors"
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// ProofVerify validates a BBS proof. See BBS spec section 3.5.4
func ProofVerify(pkBytes []byte, proof []byte, header []byte, ph []byte, disclosedMessages [][]byte, disclosedIndexes []int) (bool, error) {
	if header == nil {
		header = []byte{}
	}
	if ph == nil {
		ph = []byte{}
	}
	if disclosedMessages == nil {
		disclosedMessages = [][]byte{}
	}
	if disclosedIndexes == nil {
		disclosedIndexes = []int{}
	}

	apiID := []byte(CIPHERSUITE_ID + H2G_HM2S_ID)

	proofLenFloor := 3*OCTET_POINT_LENGTH + 4*OCTET_SCALAR_LENGTH
	if len(proof) < proofLenFloor {
		return false, errors.New("INVALID: proof too short")
	}
	U := (len(proof) - proofLenFloor) / OCTET_SCALAR_LENGTH
	R := len(disclosedIndexes)

	messageScalars, err := MessagesToScalars(disclosedMessages, apiID)
	if err != nil {
		return false, fmt.Errorf("failed to convert messages to scalars: %w", err)
	}

	// Step 2: generators = create_generators(U + R + 1, api_id)
	generators, err := CreateGenerators(uint64(U+R+1), apiID)
	if err != nil {
		return false, err
	}

	// Step 3: result = CoreProofVerify(PK, proof, generators, header, ph, message_scalars, disclosed_indexes, api_id)
	valid, err := CoreProofVerify(pkBytes, proof, generators, header, ph, messageScalars, disclosedIndexes, apiID)
	if err != nil {
		return false, err
	}

	return valid, nil
}

// CoreProofVerify performs the core proof verification. See BBS spec section 3.6.4
func CoreProofVerify(pkBytes []byte, proof []byte, generators []bls12381.G1Affine, header []byte, ph []byte, disclosedMessages []fr.Element, disclosedIndexes []int, apiID []byte) (bool, error) {
	if header == nil {
		header = []byte{}
	}
	if ph == nil {
		ph = []byte{}
	}
	if disclosedMessages == nil {
		disclosedMessages = []fr.Element{}
	}
	if disclosedIndexes == nil {
		disclosedIndexes = []int{}
	}
	if apiID == nil {
		apiID = []byte{}
	}

	proofResult, err := OctetsToProof(proof)
	if err != nil {
		return false, err
	}

	W, err := OctetsToPublicKey(pkBytes)
	if err != nil {
		return false, err
	}

	initRes, err := ProofVerifyInit(pkBytes, proofResult, generators, header, disclosedMessages, disclosedIndexes, apiID)
	if err != nil {
		return false, err
	}

	challenge, err := ProofChallengeCalculate(initRes, disclosedMessages, disclosedIndexes, ph, apiID)
	if err != nil {
		return false, err
	}

	proofChallenge, ok := proofResult[len(proofResult)-1].(fr.Element)
	if !ok {
		return false, errors.New("INVALID: proof challenge format")
	}

	if !challenge.Equal(&proofChallenge) {
		return false, nil // Invalid proof, but not an error
	}
	Abar, ok := proofResult[0].(bls12381.G1Affine)
	if !ok {
		return false, errors.New("INVALID: proof Abar format")
	}
	Bbar, ok := proofResult[1].(bls12381.G1Affine)
	if !ok {
		return false, errors.New("INVALID: proof Bbar format")
	}

	// This checks e(Abar, W) = e(Bbar, BP2) where BP2 = -P2
	valid, err := verifyPairing(Abar, W, Bbar)
	if err != nil {
		return false, err
	}
	if !valid {
		return false, nil // Invalid proof, but not an error
	}

	return true, nil
}

// ProofVerifyInit initializes the proof verification. See BBS spec section 3.7.3
func ProofVerifyInit(pkBytes []byte, proof []interface{}, generators []bls12381.G1Affine, header []byte, disclosedMessages []fr.Element, disclosedIndexes []int, apiID []byte) ([]interface{}, error) {
	if header == nil {
		header = []byte{}
	}
	if disclosedMessages == nil {
		disclosedMessages = []fr.Element{}
	}
	if disclosedIndexes == nil {
		disclosedIndexes = []int{}
	}
	if apiID == nil {
		apiID = []byte{}
	}

	if len(proof) < 7 {
		return nil, errors.New("INVALID: proof format")
	}

	Abar, ok := proof[0].(bls12381.G1Affine)
	if !ok {
		return nil, errors.New("INVALID: proof Abar")
	}
	Bbar, ok := proof[1].(bls12381.G1Affine)
	if !ok {
		return nil, errors.New("INVALID: proof Bbar")
	}
	D, ok := proof[2].(bls12381.G1Affine)
	if !ok {
		return nil, errors.New("INVALID: proof D")
	}
	eHat, ok := proof[3].(fr.Element)
	if !ok {
		return nil, errors.New("INVALID: proof e^")
	}
	r1Hat, ok := proof[4].(fr.Element)
	if !ok {
		return nil, errors.New("INVALID: proof r1^")
	}
	r3Hat, ok := proof[5].(fr.Element)
	if !ok {
		return nil, errors.New("INVALID: proof r3^")
	}

	// Extract commitments (m^_j1, ..., m^_jU)
	commitments := make([]fr.Element, 0)
	for i := 6; i < len(proof)-1; i++ {
		commitment, ok := proof[i].(fr.Element)
		if !ok {
			return nil, fmt.Errorf("INVALID: proof commitment %d", i-6)
		}
		commitments = append(commitments, commitment)
	}

	c, ok := proof[len(proof)-1].(fr.Element)
	if !ok {
		return nil, errors.New("INVALID: proof challenge")
	}

	U := len(commitments)
	R := len(disclosedIndexes)
	L := R + U

	for _, i := range disclosedIndexes {
		if i < 0 || i > L-1 {
			return nil, fmt.Errorf("INVALID: disclosed index %d out of range [0,%d]", i, L-1)
		}
	}

	if len(disclosedMessages) != R {
		return nil, errors.New("INVALID: disclosed messages length mismatch")
	}

	if len(generators) != L+1 {
		return nil, fmt.Errorf("INVALID: generators length %d, expected %d", len(generators), L+1)
	}

	Q1 := generators[0]
	H := generators[1:]

	domain, err := CalculateDomain(pkBytes, Q1, H, header, apiID)
	if err != nil {
		return nil, err
	}

	var T1 bls12381.G1Jac

	// Bbar * c
	var BbarC bls12381.G1Jac
	BbarC.FromAffine(&Bbar)
	BbarC.ScalarMultiplication(&BbarC, c.BigInt(new(big.Int)))
	T1.Set(&BbarC)

	// Abar * e^
	var AbarEHat bls12381.G1Jac
	AbarEHat.FromAffine(&Abar)
	AbarEHat.ScalarMultiplication(&AbarEHat, eHat.BigInt(new(big.Int)))
	T1.AddAssign(&AbarEHat)

	// D * r1^
	var Dr1Hat bls12381.G1Jac
	Dr1Hat.FromAffine(&D)
	Dr1Hat.ScalarMultiplication(&Dr1Hat, r1Hat.BigInt(new(big.Int)))
	T1.AddAssign(&Dr1Hat)

	var T1Affine bls12381.G1Affine
	T1Affine.FromJacobian(&T1)

	// Bv = P1 + Q_1 * domain + H_i1 * msg_i1 + ... + H_iR * msg_iR
	var Bv bls12381.G1Jac
	P1 := GetP1()
	Bv.FromAffine(&P1)

	// Q_1 * domain
	var Q1Domain bls12381.G1Jac
	Q1Domain.FromAffine(&Q1)
	Q1Domain.ScalarMultiplication(&Q1Domain, domain.BigInt(new(big.Int)))
	Bv.AddAssign(&Q1Domain)

	// H_i * msg_i for disclosed messages
	for i, idx := range disclosedIndexes {
		var HiMsgi bls12381.G1Jac
		HiJac := bls12381.G1Jac{}
		HiJac.FromAffine(&H[idx])
		HiMsgi.ScalarMultiplication(&HiJac, disclosedMessages[i].BigInt(new(big.Int)))
		Bv.AddAssign(&HiMsgi)
	}

	var BvAffine bls12381.G1Affine
	BvAffine.FromJacobian(&Bv)

	// T2 = Bv * c + D * r3^ + H_j1 * m^_j1 + ... +  H_jU * m^_jU
	var T2 bls12381.G1Jac

	// Bv * c
	var BvC bls12381.G1Jac
	BvC.FromAffine(&BvAffine)
	BvC.ScalarMultiplication(&BvC, c.BigInt(new(big.Int)))
	T2.Set(&BvC)

	// D * r3^
	var Dr3Hat bls12381.G1Jac
	Dr3Hat.FromAffine(&D)
	Dr3Hat.ScalarMultiplication(&Dr3Hat, r3Hat.BigInt(new(big.Int)))
	T2.AddAssign(&Dr3Hat)

	// Calculate undisclosed indexes
	disclosedSet := make(map[int]bool)
	for _, idx := range disclosedIndexes {
		disclosedSet[idx] = true
	}
	undisclosedIndexes := make([]int, 0, U)
	for i := 0; i < L; i++ {
		if !disclosedSet[i] {
			undisclosedIndexes = append(undisclosedIndexes, i)
		}
	}

	// H_j * m^_j for undisclosed messages
	for i, j := range undisclosedIndexes {
		var HjMHatj bls12381.G1Jac
		HjJac := bls12381.G1Jac{}
		HjJac.FromAffine(&H[j])
		HjMHatj.ScalarMultiplication(&HjJac, commitments[i].BigInt(new(big.Int)))
		T2.AddAssign(&HjMHatj)
	}

	var T2Affine bls12381.G1Affine
	T2Affine.FromJacobian(&T2)

	// Step 5: return (Abar, Bbar, D, T1, T2, domain)
	return []interface{}{Abar, Bbar, D, T1Affine, T2Affine, domain}, nil
}

// OctetsToProof deserializes a proof from octets. See BBS spec section 4.2.4.5
func OctetsToProof(proofOctets []byte) ([]interface{}, error) {
	// Minimum length: 3 points + 4 scalars
	minLen := 3*OCTET_POINT_LENGTH + 4*OCTET_SCALAR_LENGTH
	if len(proofOctets) < minLen {
		return nil, errors.New("INVALID: proof octets too short")
	}

	// Calculate number of commitment scalars
	remainingLen := len(proofOctets) - minLen
	if remainingLen%OCTET_SCALAR_LENGTH != 0 {
		return nil, errors.New("INVALID: proof octets length")
	}
	U := remainingLen / OCTET_SCALAR_LENGTH

	proof := make([]interface{}, 0, 7+U)
	offset := 0

	// Extract 3 G1 points: Abar, Bbar, D
	for i := 0; i < 3; i++ {
		pointBytes := proofOctets[offset : offset+OCTET_POINT_LENGTH]
		point, err := OctetsToPointG1(pointBytes)
		if err != nil {
			return nil, fmt.Errorf("INVALID: failed to deserialize point %d: %w", i, err)
		}
		proof = append(proof, point)
		offset += OCTET_POINT_LENGTH
	}

	// Extract 3 + U scalars: e^, r1^, r3^, commitments..., challenge
	totalScalars := 3 + U + 1 // e^, r1^, r3^, commitments, challenge
	for i := 0; i < totalScalars; i++ {
		scalarBytes := proofOctets[offset : offset+OCTET_SCALAR_LENGTH]
		var scalar fr.Element
		scalar.SetBytes(scalarBytes)
		proof = append(proof, scalar)
		offset += OCTET_SCALAR_LENGTH
	}

	return proof, nil
}

// verifyPairing checks the pairing equation: e(Abar, W) = e(Bbar, BP2)
// where BP2 = -P2 (the negative of the G2 generator)
func verifyPairing(Abar bls12381.G1Affine, W bls12381.G2Affine, Bbar bls12381.G1Affine) (bool, error) {
	// Calculate -P2
	var negP2 bls12381.G2Affine
	negP2.Neg(&g2Aff)

	pairing1, _ := bls12381.Pair([]bls12381.G1Affine{Abar, Bbar}, []bls12381.G2Affine{W, negP2})

	// Check if the result equals the identity in GT
	var identity bls12381.GT
	identity.SetOne()

	return pairing1.Equal(&identity), nil
}
