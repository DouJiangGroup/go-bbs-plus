package bbs

import (
	"errors"
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// ProofGen creates a BBS proof with selective disclosure. See BBS spec section 3.5.3
func ProofGen(pkBytes []byte, signature []byte, header []byte, ph []byte, messages [][]byte, disclosedIndexes []int) ([]byte, error) {
	if header == nil {
		header = []byte{}
	}
	if ph == nil {
		ph = []byte{}
	}
	if messages == nil {
		messages = [][]byte{}
	}
	if disclosedIndexes == nil {
		disclosedIndexes = []int{}
	}

	// Validate input lengths
	if len(pkBytes) != OCTET_POINT_LENGTH*2 {
		return nil, errors.New("INVALID: public key length")
	}
	if len(signature) != OCTET_POINT_LENGTH+OCTET_SCALAR_LENGTH {
		return nil, errors.New("INVALID: signature length")
	}

	apiID := []byte(CIPHERSUITE_ID + H2G_HM2S_ID)

	// Step 1: message_scalars = messages_to_scalars(messages, api_id)
	messageScalars, err := MessagesToScalars(messages, apiID)
	if err != nil {
		return nil, fmt.Errorf("failed to convert messages to scalars: %w", err)
	}

	// Step 2: generators = create_generators(length(messages) + 1, api_id)
	generators, err := CreateGenerators(uint64(len(messages))+1, apiID)
	if err != nil {
		return nil, err
	}

	// Step 3: proof = CoreProofGen(PK, signature, generators, header, ph, message_scalars, disclosed_indexes, api_id)
	proof, err := CoreProofGen(pkBytes, signature, generators, header, ph, messageScalars, disclosedIndexes, apiID)
	if err != nil {
		return nil, err
	}

	return proof, nil
}

// CoreProofGen computes a zero-knowledge proof-of-knowledge of a signature. See BBS spec section 3.6.3
func CoreProofGen(pkBytes []byte, signature []byte, generators []bls12381.G1Affine, header []byte, ph []byte, messages []fr.Element, disclosedIndexes []int, apiID []byte) ([]byte, error) {
	if header == nil {
		header = []byte{}
	}
	if ph == nil {
		ph = []byte{}
	}
	if messages == nil {
		messages = []fr.Element{}
	}
	if disclosedIndexes == nil {
		disclosedIndexes = []int{}
	}
	if apiID == nil {
		apiID = []byte{}
	}

	// Deserialization steps 1-3: signature_result = octets_to_signature(signature)
	A, e, err := OctetsToSignature(signature)
	if err != nil {
		return nil, err
	}

	// Deserialization steps 4-8: Validate inputs
	L := len(messages)
	R := len(disclosedIndexes)
	if R > L {
		return nil, errors.New("INVALID: more disclosed indexes than messages")
	}
	U := L - R

	// Validate disclosed_indexes
	for _, i := range disclosedIndexes {
		if i < 0 || i > L-1 {
			return nil, fmt.Errorf("INVALID: disclosed index %d out of range [0,%d]", i, L-1)
		}
	}

	// Calculate undisclosed_indexes = (0, 1, ..., L-1) \ disclosed_indexes
	undisclosedIndexes := make([]int, 0, U)
	disclosedSet := make(map[int]bool)
	for _, idx := range disclosedIndexes {
		disclosedSet[idx] = true
	}
	for i := 0; i < L; i++ {
		if !disclosedSet[i] {
			undisclosedIndexes = append(undisclosedIndexes, i)
		}
	}

	// Extract disclosed and undisclosed messages
	disclosedMessages := make([]fr.Element, R)
	for i, idx := range disclosedIndexes {
		disclosedMessages[i] = messages[idx]
	}
	undisclosedMessages := make([]fr.Element, U)
	for i, idx := range undisclosedIndexes {
		undisclosedMessages[i] = messages[idx]
	}

	// Procedure step 1: random_scalars = calculate_random_scalars(5+U)
	randomScalars, err := calculateRandomScalars(5 + U)
	if err != nil {
		return nil, err
	}

	// Step 2: init_res = ProofInit(...)
	signatureResult := []interface{}{A, e}
	initRes, err := ProofInit(pkBytes, signatureResult, generators, randomScalars, header, messages, undisclosedIndexes, apiID)
	if err != nil {
		return nil, err
	}

	// Step 4: challenge = ProofChallengeCalculate(...)
	challenge, err := ProofChallengeCalculate(initRes, disclosedMessages, disclosedIndexes, ph, apiID)
	if err != nil {
		return nil, err
	}

	// Step 6: proof = ProofFinalize(...)
	proof, err := ProofFinalize(initRes, challenge, e, randomScalars, undisclosedMessages)
	if err != nil {
		return nil, err
	}

	return proof, nil
}

// ProofInit initializes the proof generation. See BBS spec section 3.7.1
func ProofInit(pkBytes []byte, signature []interface{}, generators []bls12381.G1Affine, randomScalars []fr.Element, header []byte, messages []fr.Element, undisclosedIndexes []int, apiID []byte) ([]interface{}, error) {
	if header == nil {
		header = []byte{}
	}
	if messages == nil {
		messages = []fr.Element{}
	}
	if undisclosedIndexes == nil {
		undisclosedIndexes = []int{}
	}
	if apiID == nil {
		apiID = []byte{}
	}

	// Deserialization
	if len(signature) != 2 {
		return nil, errors.New("INVALID: signature format")
	}
	A, ok := signature[0].(bls12381.G1Affine)
	if !ok {
		return nil, errors.New("INVALID: signature A component")
	}
	e, ok := signature[1].(fr.Element)
	if !ok {
		return nil, errors.New("INVALID: signature e component")
	}

	L := len(messages)
	U := len(undisclosedIndexes)

	// Validate random_scalars length
	if len(randomScalars) != U+5 {
		return nil, fmt.Errorf("INVALID: random_scalars length %d, expected %d", len(randomScalars), U+5)
	}

	// Unpack random_scalars: (r1, r2, e~, r1~, r3~, m~_j1, ..., m~_jU)
	r1 := randomScalars[0]
	r2 := randomScalars[1]
	eTilde := randomScalars[2]
	r1Tilde := randomScalars[3]
	r3Tilde := randomScalars[4]
	mTildes := randomScalars[5:]

	// Validate generators length
	if len(generators) != L+1 {
		return nil, fmt.Errorf("INVALID: generators length %d, expected %d", len(generators), L+1)
	}

	Q1 := generators[0]
	H := generators[1:]

	// ABORT conditions
	for _, i := range undisclosedIndexes {
		if i < 0 || i > L-1 {
			return nil, fmt.Errorf("INVALID: undisclosed index %d out of range", i)
		}
	}
	if U > L {
		return nil, errors.New("INVALID: more undisclosed indexes than messages")
	}

	// Step 1: domain = calculate_domain(PK, Q_1, (H_1, ..., H_L), header, api_id)
	domain, err := CalculateDomain(pkBytes, Q1, H, header, apiID)
	if err != nil {
		return nil, err
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

	// H_i * msg_i for all messages
	for i := 0; i < L; i++ {
		var tmpH bls12381.G1Jac
		tmpHJac := bls12381.G1Jac{}
		tmpHJac.FromAffine(&H[i])
		tmpH.ScalarMultiplication(&tmpHJac, messages[i].BigInt(new(big.Int)))
		B.AddAssign(&tmpH)
	}

	var BAffine bls12381.G1Affine
	BAffine.FromJacobian(&B)

	// Step 3: D = B * r2
	var D bls12381.G1Jac
	D.FromAffine(&BAffine)
	D.ScalarMultiplication(&D, r2.BigInt(new(big.Int)))
	var DAffine bls12381.G1Affine
	DAffine.FromJacobian(&D)

	// Step 4: Abar = A * (r1 * r2)
	var r1r2 fr.Element
	r1r2.Mul(&r1, &r2)
	var Abar bls12381.G1Jac
	AJac := bls12381.G1Jac{}
	AJac.FromAffine(&A)
	Abar.ScalarMultiplication(&AJac, r1r2.BigInt(new(big.Int)))
	var AbarAffine bls12381.G1Affine
	AbarAffine.FromJacobian(&Abar)

	// Step 5: Bbar = D * r1 - Abar * e
	var Dr1 bls12381.G1Jac
	Dr1.FromAffine(&DAffine)
	Dr1.ScalarMultiplication(&Dr1, r1.BigInt(new(big.Int)))

	var AbarE bls12381.G1Jac
	AbarE.FromAffine(&AbarAffine)
	AbarE.ScalarMultiplication(&AbarE, e.BigInt(new(big.Int)))

	var Bbar bls12381.G1Jac
	Bbar.Set(&Dr1)
	Bbar.SubAssign(&AbarE)
	var BbarAffine bls12381.G1Affine
	BbarAffine.FromJacobian(&Bbar)

	// Step 6: T1 = Abar * e~ + D * r1~
	var AbarETilde bls12381.G1Jac
	AbarETilde.FromAffine(&AbarAffine)
	AbarETilde.ScalarMultiplication(&AbarETilde, eTilde.BigInt(new(big.Int)))

	var Dr1Tilde bls12381.G1Jac
	Dr1Tilde.FromAffine(&DAffine)
	Dr1Tilde.ScalarMultiplication(&Dr1Tilde, r1Tilde.BigInt(new(big.Int)))

	var T1 bls12381.G1Jac
	T1.Set(&AbarETilde)
	T1.AddAssign(&Dr1Tilde)
	var T1Affine bls12381.G1Affine
	T1Affine.FromJacobian(&T1)

	// Step 7: T2 = D * r3~ + H_j1 * m~_j1 + ... + H_jU * m~_jU
	var T2 bls12381.G1Jac
	T2.FromAffine(&DAffine)
	T2.ScalarMultiplication(&T2, r3Tilde.BigInt(new(big.Int)))

	// Add undisclosed message contributions
	for i, j := range undisclosedIndexes {
		var HjMTilde bls12381.G1Jac
		HjJac := bls12381.G1Jac{}
		HjJac.FromAffine(&H[j])
		HjMTilde.ScalarMultiplication(&HjJac, mTildes[i].BigInt(new(big.Int)))
		T2.AddAssign(&HjMTilde)
	}
	var T2Affine bls12381.G1Affine
	T2Affine.FromJacobian(&T2)

	// Step 8: return (Abar, Bbar, D, T1, T2, domain)
	return []interface{}{AbarAffine, BbarAffine, DAffine, T1Affine, T2Affine, domain}, nil
}

// ProofChallengeCalculate computes the challenge scalar. See BBS spec section 3.7.4
func ProofChallengeCalculate(initRes []interface{}, disclosedMessages []fr.Element, disclosedIndexes []int, ph []byte, apiID []byte) (fr.Element, error) {
	if disclosedMessages == nil {
		disclosedMessages = []fr.Element{}
	}
	if disclosedIndexes == nil {
		disclosedIndexes = []int{}
	}
	if ph == nil {
		ph = []byte{}
	}
	if apiID == nil {
		apiID = []byte{}
	}

	var challenge fr.Element

	// Deserialization
	R := len(disclosedIndexes)
	if len(disclosedMessages) != R {
		return challenge, errors.New("INVALID: disclosed messages and indexes length mismatch")
	}

	if len(initRes) != 6 {
		return challenge, errors.New("INVALID: init_res format")
	}

	Abar, ok := initRes[0].(bls12381.G1Affine)
	if !ok {
		return challenge, errors.New("INVALID: init_res Abar")
	}
	Bbar, ok := initRes[1].(bls12381.G1Affine)
	if !ok {
		return challenge, errors.New("INVALID: init_res Bbar")
	}
	D, ok := initRes[2].(bls12381.G1Affine)
	if !ok {
		return challenge, errors.New("INVALID: init_res D")
	}
	T1, ok := initRes[3].(bls12381.G1Affine)
	if !ok {
		return challenge, errors.New("INVALID: init_res T1")
	}
	T2, ok := initRes[4].(bls12381.G1Affine)
	if !ok {
		return challenge, errors.New("INVALID: init_res T2")
	}
	domain, ok := initRes[5].(fr.Element)
	if !ok {
		return challenge, errors.New("INVALID: init_res domain")
	}

	// ABORT conditions (simplified since impossible in practice)
	// The spec checks R > 2^64-1 and len(ph) > 2^64-1, but these are impossible in Go

	// Procedure step 1: c_arr = (R, i1, msg_i1, i2, msg_i2, ..., iR, msg_iR, Abar, Bbar, D, T1, T2, domain)
	cArr := make([]interface{}, 0, 1+2*R+6)
	cArr = append(cArr, uint64(R))

	// Add disclosed index/message pairs
	for i := 0; i < R; i++ {
		cArr = append(cArr, uint64(disclosedIndexes[i]))
		cArr = append(cArr, disclosedMessages[i])
	}

	// Add points and domain
	cArr = append(cArr, Abar, Bbar, D, T1, T2, domain)

	// Step 2: c_octs = serialize(c_arr) || I2OSP(length(ph), 8) || ph
	cOcts, err := Serialize(cArr...)
	if err != nil {
		return challenge, err
	}

	phLenBytes := I2OSP(len(ph), 8)
	cOcts = append(cOcts, phLenBytes...)
	cOcts = append(cOcts, ph...)

	// Step 3: hash_to_scalar_dst = api_id || "H2S_"
	HashToScalarlarDST := append(apiID, []byte(H2S_ID)...)

	// Step 3: return hash_to_scalar(c_octs, hash_to_scalar_dst)
	challenge, err = HashToScalarlar(cOcts, HashToScalarlarDST)
	if err != nil {
		return challenge, err
	}

	return challenge, nil
}

// ProofFinalize finalizes the proof calculation. See BBS spec section 3.7.2
func ProofFinalize(initRes []interface{}, challenge fr.Element, eValue fr.Element, randomScalars []fr.Element, undisclosedMessages []fr.Element) ([]byte, error) {
	if undisclosedMessages == nil {
		undisclosedMessages = []fr.Element{}
	}

	// Deserialization
	U := len(undisclosedMessages)
	if len(randomScalars) != U+5 {
		return nil, fmt.Errorf("INVALID: random_scalars length %d, expected %d", len(randomScalars), U+5)
	}

	// Unpack random_scalars: (r1, r2, e~, r1~, r3~, m~_j1, ..., m~_jU)
	r1 := randomScalars[0]
	r2 := randomScalars[1]
	eTilde := randomScalars[2]
	r1Tilde := randomScalars[3]
	r3Tilde := randomScalars[4]
	mTildes := randomScalars[5:]

	// Extract Abar, Bbar, D from init_res
	if len(initRes) < 3 {
		return nil, errors.New("INVALID: init_res format")
	}
	Abar, ok := initRes[0].(bls12381.G1Affine)
	if !ok {
		return nil, errors.New("INVALID: init_res Abar")
	}
	Bbar, ok := initRes[1].(bls12381.G1Affine)
	if !ok {
		return nil, errors.New("INVALID: init_res Bbar")
	}
	D, ok := initRes[2].(bls12381.G1Affine)
	if !ok {
		return nil, errors.New("INVALID: init_res D")
	}

	// Procedure step 1: r3 = r2^-1 (mod r)
	var r3 fr.Element
	r3.Inverse(&r2)

	// Step 2: e^ = e~ + e_value * challenge
	var eHat fr.Element
	var eChal fr.Element
	eChal.Mul(&eValue, &challenge)
	eHat.Add(&eTilde, &eChal)

	// Step 3: r1^ = r1~ - r1 * challenge
	var r1Hat fr.Element
	var r1Chal fr.Element
	r1Chal.Mul(&r1, &challenge)
	r1Hat.Sub(&r1Tilde, &r1Chal)

	// Step 4: r3^ = r3~ - r3 * challenge
	var r3Hat fr.Element
	var r3Chal fr.Element
	r3Chal.Mul(&r3, &challenge)
	r3Hat.Sub(&r3Tilde, &r3Chal)

	// Step 5: for j in (1, ..., U): m^_j = m~_j + undisclosed_j * challenge (mod r)
	mHats := make([]fr.Element, U)
	for j := 0; j < U; j++ {
		var mChal fr.Element
		mChal.Mul(&undisclosedMessages[j], &challenge)
		mHats[j].Add(&mTildes[j], &mChal)
	}

	// Step 6: proof = (Abar, Bbar, D, e^, r1^, r3^, (m^_j1, ..., m^_jU), challenge)
	proof := make([]interface{}, 0, 7+U)
	proof = append(proof, Abar, Bbar, D, eHat, r1Hat, r3Hat)
	for _, mHat := range mHats {
		proof = append(proof, mHat)
	}
	proof = append(proof, challenge)

	// Step 7: return proof_to_octets(proof)
	return ProofToOctets(proof)
}

// calculateRandomScalars generates the requested number of pseudo-random scalars. See BBS spec section 4.2.1
func calculateRandomScalars(count int) ([]fr.Element, error) {
	if count < 0 {
		return nil, errors.New("INVALID: negative count")
	}
	if count == 0 {
		return []fr.Element{}, nil
	}

	scalars := make([]fr.Element, count)
	for i := 0; i < count; i++ {
		scalar, err := randomScalar()
		if err != nil {
			return nil, err
		}
		scalars[i] = scalar
	}

	return scalars, nil
}

// ProofToOctets encodes a proof to an octet string. See BBS spec section 4.2.4.4
func ProofToOctets(proof []interface{}) ([]byte, error) {
	if len(proof) < 7 {
		return nil, errors.New("INVALID: proof format")
	}

	// Extract components: (Abar, Bbar, D, e^, r1^, r3^, (m^_1, ..., m^_U), challenge)
	return Serialize(proof...)
}
