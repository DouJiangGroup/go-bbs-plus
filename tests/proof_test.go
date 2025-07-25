// IMPORTANT: This test file is just a logic sanity check, and doesn't actually test the proof logic in prove.go.
// It uses the library's internal functions to replicate the proof generation process.

package test

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"testing"

	bbs "github.com/Iscaraca/bbs"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// seededRandomScalars generates deterministic "random" scalars from a seed
func seededRandomScalars(seed []byte, dst []byte, count int) ([]fr.Element, error) {
	if count < 0 {
		return nil, errors.New("INVALID: negative count")
	}
	if count == 0 {
		return []fr.Element{}, nil
	}

	outLen := bbs.EXPAND_LEN * count
	if outLen > 65535 {
		return nil, errors.New("INVALID: count * expand_len > 65535")
	}

	v := bbs.ExpandMessageXOF(seed, dst, outLen)

	scalars := make([]fr.Element, count)
	for i := 0; i < count; i++ {
		startIdx := i * bbs.EXPAND_LEN
		endIdx := startIdx + bbs.EXPAND_LEN
		scalarBytes := v[startIdx:endIdx]

		var scalar fr.Element
		scalar.SetBytes(scalarBytes)
		scalars[i] = scalar
	}

	return scalars, nil
}

// mockedCalculateRandomScalars uses the BBS spec test vectors
func mockedCalculateRandomScalars(count int) ([]fr.Element, error) {
	seed, _ := hex.DecodeString("332e313431353932363533353839373933323338343632363433333833323739")
	apiID := []byte(bbs.CIPHERSUITE_ID + bbs.H2G_HM2S_ID)
	dst := append(apiID, []byte("MOCK_RANDOM_SCALARS_DST_")...)
	return seededRandomScalars(seed, dst, count)
}

// testProofGen is a test-only version that accepts a custom random function
func testProofGen(pkBytes []byte, signature []byte, header []byte, ph []byte, messages [][]byte, disclosedIndexes []int, randomFunc func(int) ([]fr.Element, error)) ([]byte, error) {
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
	if len(pkBytes) != bbs.OCTET_POINT_LENGTH*2 {
		return nil, errors.New("INVALID: public key length")
	}
	if len(signature) != bbs.OCTET_POINT_LENGTH+bbs.OCTET_SCALAR_LENGTH {
		return nil, errors.New("INVALID: signature length")
	}

	apiID := []byte(bbs.CIPHERSUITE_ID + bbs.H2G_HM2S_ID)

	// Step 1: message_scalars = messages_to_scalars(messages, api_id)
	messageScalars, err := bbs.MessagesToScalars(messages, apiID)
	if err != nil {
		return nil, fmt.Errorf("failed to convert messages to scalars: %w", err)
	}

	// Step 2: generators = create_generators(length(messages) + 1, api_id)
	generators, err := bbs.CreateGenerators(uint64(len(messages))+1, apiID)
	if err != nil {
		return nil, err
	}

	// Step 3: Custom CoreProofGen with injected random function
	return testCoreProofGen(pkBytes, signature, generators, header, ph, messageScalars, disclosedIndexes, apiID, randomFunc)
}

// testCoreProofGen replicates CoreProofGen logic but uses provided random function
func testCoreProofGen(pkBytes []byte, signature []byte, generators []bls12381.G1Affine, header []byte, ph []byte, messages []fr.Element, disclosedIndexes []int, apiID []byte, randomFunc func(int) ([]fr.Element, error)) ([]byte, error) {
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

	// Deserialization: signature_result = octets_to_signature(signature)
	A, e, err := bbs.OctetsToSignature(signature)
	if err != nil {
		return nil, err
	}

	// Validate inputs
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

	// Calculate undisclosed_indexes
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

	// Use the provided random function instead of the library's
	randomScalars, err := randomFunc(5 + U)
	if err != nil {
		return nil, err
	}

	// The rest follows the same pattern as library's CoreProofGen
	// but we need to replicate the internal functions since they're not exported

	// ProofInit equivalent
	initRes, err := testProofInit(pkBytes, A, e, generators, randomScalars, header, messages, undisclosedIndexes, apiID)
	if err != nil {
		return nil, err
	}

	// ProofChallengeCalculate equivalent
	challenge, err := testProofChallengeCalculate(initRes, disclosedMessages, disclosedIndexes, ph, apiID)
	if err != nil {
		return nil, err
	}

	// ProofFinalize equivalent
	proof, err := testProofFinalize(initRes, challenge, e, randomScalars, undisclosedMessages)
	if err != nil {
		return nil, err
	}

	return proof, nil
}

// testProofInit replicates the ProofInit logic
func testProofInit(pkBytes []byte, A bls12381.G1Affine, e fr.Element, generators []bls12381.G1Affine, randomScalars []fr.Element, header []byte, messages []fr.Element, undisclosedIndexes []int, apiID []byte) ([]interface{}, error) {
	L := len(messages)
	U := len(undisclosedIndexes)

	if len(randomScalars) != U+5 {
		return nil, fmt.Errorf("INVALID: random_scalars length %d, expected %d", len(randomScalars), U+5)
	}

	// Unpack random_scalars
	r1 := randomScalars[0]
	r2 := randomScalars[1]
	eTilde := randomScalars[2]
	r1Tilde := randomScalars[3]
	r3Tilde := randomScalars[4]
	mTildes := randomScalars[5:]

	if len(generators) != L+1 {
		return nil, fmt.Errorf("INVALID: generators length %d, expected %d", len(generators), L+1)
	}

	Q1 := generators[0]
	H := generators[1:]

	// Calculate domain
	domain, err := bbs.CalculateDomain(pkBytes, Q1, H, header, apiID)
	if err != nil {
		return nil, err
	}

	// B = P1 + Q_1 * domain + H_1 * msg_1 + ... + H_L * msg_L
	var B bls12381.G1Jac
	P1 := bbs.GetP1()
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

	// D = B * r2
	var D bls12381.G1Jac
	D.FromAffine(&BAffine)
	D.ScalarMultiplication(&D, r2.BigInt(new(big.Int)))
	var DAffine bls12381.G1Affine
	DAffine.FromJacobian(&D)

	// Abar = A * (r1 * r2)
	var r1r2 fr.Element
	r1r2.Mul(&r1, &r2)
	var Abar bls12381.G1Jac
	AJac := bls12381.G1Jac{}
	AJac.FromAffine(&A)
	Abar.ScalarMultiplication(&AJac, r1r2.BigInt(new(big.Int)))
	var AbarAffine bls12381.G1Affine
	AbarAffine.FromJacobian(&Abar)

	// Bbar = D * r1 - Abar * e
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

	// T1 = Abar * e~ + D * r1~
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

	// T2 = D * r3~ + H_j1 * m~_j1 + ... + H_jU * m~_jU
	var T2 bls12381.G1Jac
	T2.FromAffine(&DAffine)
	T2.ScalarMultiplication(&T2, r3Tilde.BigInt(new(big.Int)))

	for i, j := range undisclosedIndexes {
		var HjMTilde bls12381.G1Jac
		HjJac := bls12381.G1Jac{}
		HjJac.FromAffine(&H[j])
		HjMTilde.ScalarMultiplication(&HjJac, mTildes[i].BigInt(new(big.Int)))
		T2.AddAssign(&HjMTilde)
	}
	var T2Affine bls12381.G1Affine
	T2Affine.FromJacobian(&T2)

	return []interface{}{AbarAffine, BbarAffine, DAffine, T1Affine, T2Affine, domain}, nil
}

// testProofChallengeCalculate replicates ProofChallengeCalculate
func testProofChallengeCalculate(initRes []interface{}, disclosedMessages []fr.Element, disclosedIndexes []int, ph []byte, apiID []byte) (fr.Element, error) {
	var challenge fr.Element

	R := len(disclosedIndexes)
	if len(disclosedMessages) != R {
		return challenge, errors.New("INVALID: disclosed messages and indexes length mismatch")
	}

	if len(initRes) != 6 {
		return challenge, errors.New("INVALID: init_res format")
	}

	Abar := initRes[0].(bls12381.G1Affine)
	Bbar := initRes[1].(bls12381.G1Affine)
	D := initRes[2].(bls12381.G1Affine)
	T1 := initRes[3].(bls12381.G1Affine)
	T2 := initRes[4].(bls12381.G1Affine)
	domain := initRes[5].(fr.Element)

	// c_arr = (R, i1, msg_i1, i2, msg_i2, ..., iR, msg_iR, Abar, Bbar, D, T1, T2, domain)
	cArr := make([]interface{}, 0, 1+2*R+6)
	cArr = append(cArr, uint64(R))

	for i := 0; i < R; i++ {
		cArr = append(cArr, uint64(disclosedIndexes[i]))
		cArr = append(cArr, disclosedMessages[i])
	}

	cArr = append(cArr, Abar, Bbar, D, T1, T2, domain)

	// c_octs = serialize(c_arr) || I2OSP(length(ph), 8) || ph
	cOcts, err := bbs.Serialize(cArr...)
	if err != nil {
		return challenge, err
	}

	phLenBytes := bbs.I2OSP(len(ph), 8)
	cOcts = append(cOcts, phLenBytes...)
	cOcts = append(cOcts, ph...)

	// hash_to_scalar_dst = api_id || "H2S_"
	HashToScalarlarDST := append(apiID, []byte(bbs.H2S_ID)...)

	challenge, err = bbs.HashToScalarlar(cOcts, HashToScalarlarDST)
	if err != nil {
		return challenge, err
	}

	return challenge, nil
}

// testProofFinalize replicates ProofFinalize
func testProofFinalize(initRes []interface{}, challenge fr.Element, eValue fr.Element, randomScalars []fr.Element, undisclosedMessages []fr.Element) ([]byte, error) {
	U := len(undisclosedMessages)
	if len(randomScalars) != U+5 {
		return nil, fmt.Errorf("INVALID: random_scalars length %d, expected %d", len(randomScalars), U+5)
	}

	// Unpack random_scalars
	r1 := randomScalars[0]
	r2 := randomScalars[1]
	eTilde := randomScalars[2]
	r1Tilde := randomScalars[3]
	r3Tilde := randomScalars[4]
	mTildes := randomScalars[5:]

	Abar := initRes[0].(bls12381.G1Affine)
	Bbar := initRes[1].(bls12381.G1Affine)
	D := initRes[2].(bls12381.G1Affine)

	// r3 = r2^-1 (mod r)
	var r3 fr.Element
	r3.Inverse(&r2)

	// e^ = e~ + e_value * challenge
	var eHat fr.Element
	var eChal fr.Element
	eChal.Mul(&eValue, &challenge)
	eHat.Add(&eTilde, &eChal)

	// r1^ = r1~ - r1 * challenge
	var r1Hat fr.Element
	var r1Chal fr.Element
	r1Chal.Mul(&r1, &challenge)
	r1Hat.Sub(&r1Tilde, &r1Chal)

	// r3^ = r3~ - r3 * challenge
	var r3Hat fr.Element
	var r3Chal fr.Element
	r3Chal.Mul(&r3, &challenge)
	r3Hat.Sub(&r3Tilde, &r3Chal)

	// m^_j = m~_j + undisclosed_j * challenge (mod r)
	mHats := make([]fr.Element, U)
	for j := 0; j < U; j++ {
		var mChal fr.Element
		mChal.Mul(&undisclosedMessages[j], &challenge)
		mHats[j].Add(&mTildes[j], &mChal)
	}

	// proof = (Abar, Bbar, D, e^, r1^, r3^, (m^_j1, ..., m^_jU), challenge)
	proof := make([]interface{}, 0, 7+U)
	proof = append(proof, Abar, Bbar, D, eHat, r1Hat, r3Hat)
	for _, mHat := range mHats {
		proof = append(proof, mHat)
	}
	proof = append(proof, challenge)

	return bbs.Serialize(proof...)
}

// Tests start here

func TestMockedRandomScalars(t *testing.T) {
	expectedHex := []string{
		"1004262112c3eaa95941b2b0d1311c09c845db0099a50e67eda628ad26b43083",
		"6da7f145a94c1fa7f116b2482d59e4d466fe49c955ae8726e79453065156a9a4",
		"05017919b3607e78c51e8ec34329955d49c8c90e4488079c43e74824e98f1306",
		"4d451dad519b6a226bba79e11b44c441f1a74800eecfec6a2e2d79ea65b9d32d",
		"5e7e4894e6dbe68023bc92ef15c410b01f3828109fc72b3b5ab159fc427b3f51",
		"646e3014f49accb375253d268eb6c7f3289a1510f1e9452b612dd73a06ec5dd4",
		"363ecc4c1f9d6d9144374de8f1f7991405e3345a3ec49dd485a39982753c11a4",
		"12e592fe28d91d7b92a198c29afaa9d5329a4dcfdaf8b08557807412faeb4ac6",
		"513325acdcdec7ea572360587b350a8b095ca19bdd8258c5c69d375e8706141a",
		"6474fceba35e7e17365dde1a0284170180e446ae96c82943290d7baa3a6ed429",
	}

	scalars, err := mockedCalculateRandomScalars(10)
	if err != nil {
		t.Fatalf("Failed to generate mocked random scalars: %v", err)
	}

	if len(scalars) != 10 {
		t.Fatalf("Expected 10 scalars, got %d", len(scalars))
	}

	for i, expected := range expectedHex {
		expectedBytes, _ := hex.DecodeString(expected)
		var expectedScalar fr.Element
		expectedScalar.SetBytes(expectedBytes)

		if !scalars[i].Equal(&expectedScalar) {
			bytes := scalars[i].Bytes()
			actualHex := hex.EncodeToString(bytes[:])
			t.Errorf("Scalar %d mismatch:\nExpected: %s\nActual:   %s", i+1, expected, actualHex)
		}
	}
}

func TestValidSingleMessageProof(t *testing.T) {
	m0, _ := hex.DecodeString("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02")
	publicKey, _ := hex.DecodeString("92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb18fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5")
	signature, _ := hex.DecodeString("b9a622a4b404e6ca4c85c15739d2124a1deb16df750be202e2430e169bc27fb71c44d98e6d40792033e1c452145ada95030832c5dc778334f2f1b528eced21b0b97a12025a283d78b7136bb9825d04ef")
	header, _ := hex.DecodeString("11223344556677889900aabbccddeeff")
	presentationHeader, _ := hex.DecodeString("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501")
	revealedIndexes := []int{0}
	expectedProof, _ := hex.DecodeString("89e4ab0c160880e0c2f12a754b9c051ed7f5fccfee3d5cbbb62e1239709196c737fff4303054660f8fcd08267a5de668a2e395ebe8866bdcb0dff9786d7014fa5e3c8cf7b41f8d7510e27d307f18032f6b788e200b9d6509f40ce1d2f962ceedb023d58ee44d660434e6ba60ed0da1a5d2cde031b483684cd7c5b13295a82f57e209b584e8fe894bcc964117bf3521b43d8e2eb59ce31f34d68b39f05bb2c625e4de5e61e95ff38bfd62ab07105d016414b45b01625c69965ad3c8a933e7b25d93daeb777302b966079827a99178240e6c3f13b7db2fb1f14790940e239d775ab32f539bdf9f9b582b250b05882996832652f7f5d3b6e04744c73ada1702d6791940ccbd75e719537f7ace6ee817298d")

	messages := [][]byte{m0}

	proof, err := testProofGen(publicKey, signature, header, presentationHeader, messages, revealedIndexes, mockedCalculateRandomScalars)
	if err != nil {
		t.Fatalf("ProofGen failed: %v", err)
	}

	if !bytesEqual(proof, expectedProof) {
		t.Errorf("Proof mismatch:\nExpected: %x\nActual:   %x", expectedProof, proof)
	}
}

func TestValidMultiMessageAllDisclosedProof(t *testing.T) {
	messages := [][]byte{
		mustDecodeHex("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"),
		mustDecodeHex("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80"),
		mustDecodeHex("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73"),
		mustDecodeHex("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c"),
		mustDecodeHex("496694774c5604ab1b2544eababcf0f53278ff50"),
		mustDecodeHex("515ae153e22aae04ad16f759e07237b4"),
		mustDecodeHex("d183ddc6e2665aa4e2f088af"),
		mustDecodeHex("ac55fb33a75909ed"),
		mustDecodeHex("96012096"),
		mustDecodeHex(""),
	}

	publicKey := mustDecodeHex("92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb18fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5")
	signature := mustDecodeHex("956a3427b1b8e3642e60e6a7990b67626811adeec7a0a6cb4f770cdd7c20cf08faabb913ac94d18e1e92832e924cb6e202912b624261fc6c59b0fea801547f67fb7d3253e1e2acbcf90ef59a6911931e")
	header := mustDecodeHex("11223344556677889900aabbccddeeff")
	presentationHeader := mustDecodeHex("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501")
	revealedIndexes := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	expectedProof := mustDecodeHex("91b0f598268c57b67bc9e55327c3c2b9b1654be89a0cf963ab392fa9e1637c565241d71fd6d7bbd7dfe243de85a9bac8b7461575c1e13b5055fed0b51fd0ec1433096607755b2f2f9ba6dc614dfa456916ca0d7fc6482b39c679cfb747a50ea1b3dd7ed57aaadc348361e2501a17317352e555a333e014e8e7d71eef808ae4f8fbdf45cd19fde45038bb310d5135f5205fc550b077e381fb3a3543dca31a0d8bba97bc0b660a5aa239eb74921e184aa3035fa01eaba32f52029319ec3df4fa4a4f716edb31a6ce19a19dbb971380099345070bd0fdeecf7c4774a33e0a116e069d5e215992fb637984802066dee6919146ae50b70ea52332dfe57f6e05c66e99f1764d8b890d121d65bfcc2984886ee0")

	proof, err := testProofGen(publicKey, signature, header, presentationHeader, messages, revealedIndexes, mockedCalculateRandomScalars)
	if err != nil {
		t.Fatalf("ProofGen failed: %v", err)
	}

	if !bytesEqual(proof, expectedProof) {
		t.Errorf("Proof mismatch:\nExpected: %x\nActual:   %x", expectedProof, proof)
	}
}

func TestValidMultiMessageSomeDisclosedProof(t *testing.T) {
	messages := [][]byte{
		mustDecodeHex("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"),
		mustDecodeHex("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80"),
		mustDecodeHex("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73"),
		mustDecodeHex("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c"),
		mustDecodeHex("496694774c5604ab1b2544eababcf0f53278ff50"),
		mustDecodeHex("515ae153e22aae04ad16f759e07237b4"),
		mustDecodeHex("d183ddc6e2665aa4e2f088af"),
		mustDecodeHex("ac55fb33a75909ed"),
		mustDecodeHex("96012096"),
		mustDecodeHex(""),
	}

	publicKey := mustDecodeHex("92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb18fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5")
	signature := mustDecodeHex("956a3427b1b8e3642e60e6a7990b67626811adeec7a0a6cb4f770cdd7c20cf08faabb913ac94d18e1e92832e924cb6e202912b624261fc6c59b0fea801547f67fb7d3253e1e2acbcf90ef59a6911931e")
	header := mustDecodeHex("11223344556677889900aabbccddeeff")
	presentationHeader := mustDecodeHex("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501")
	revealedIndexes := []int{0, 2, 4, 6}
	expectedProof := mustDecodeHex("b1f8bf99a11c39f04e2a032183c1ead12956ad322dd06799c50f20fb8cf6b0ac279210ef5a2920a7be3ec2aa0911ace7b96811a98f3c1cceba4a2147ae763b3ba036f47bc21c39179f2b395e0ab1ac49017ea5b27848547bedd27be481c1dfc0b73372346feb94ab16189d4c525652b8d3361bab43463700720ecfb0ee75e595ea1b13330615011050a0dfcffdb21af356dd39bf8bcbfd41bf95d913f4c9b2979e1ed2ca10ac7e881bb6a271722549681e398d29e9ba4eac8848b168eddd5e4acec7df4103e2ed165e6e32edc80f0a3b28c36fb39ca19b4b8acee570deadba2da9ec20d1f236b571e0d4c2ea3b826fe924175ed4dfffbf18a9cfa98546c241efb9164c444d970e8c89849bc8601e96cf228fdefe38ab3b7e289cac859e68d9cbb0e648faf692b27df5ff6539c30da17e5444a65143de02ca64cee7b0823be65865cdc310be038ec6b594b99280072ae067bad1117b0ff3201a5506a8533b925c7ffae9cdb64558857db0ac5f5e0f18e750ae77ec9cf35263474fef3f78138c7a1ef5cfbc878975458239824fad3ce05326ba3969b1f5451bd82bd1f8075f3d32ece2d61d89a064ab4804c3c892d651d11bc325464a71cd7aacc2d956a811aaff13ea4c35cef7842b656e8ba4758e7558")

	proof, err := testProofGen(publicKey, signature, header, presentationHeader, messages, revealedIndexes, mockedCalculateRandomScalars)
	if err != nil {
		t.Fatalf("ProofGen failed: %v", err)
	}

	if !bytesEqual(proof, expectedProof) {
		t.Errorf("Proof mismatch:\nExpected: %x\nActual:   %x", expectedProof, proof)
	}
}

// Helper functions
func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Test ProofVerify for the single message proof
func TestProofVerifySingleMessage(t *testing.T) {
	// Test data from spec section 8.3.5.1
	m0, _ := hex.DecodeString("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02")
	publicKey, _ := hex.DecodeString("92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb18fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5")
	signature, _ := hex.DecodeString("b9a622a4b404e6ca4c85c15739d2124a1deb16df750be202e2430e169bc27fb71c44d98e6d40792033e1c452145ada95030832c5dc778334f2f1b528eced21b0b97a12025a283d78b7136bb9825d04ef")
	header, _ := hex.DecodeString("11223344556677889900aabbccddeeff")
	presentationHeader, _ := hex.DecodeString("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501")
	revealedIndexes := []int{0}
	messages := [][]byte{m0}
	disclosedMessages := [][]byte{m0} // Same as messages since index 0 is revealed

	// Generate proof using test function
	proof, err := testProofGen(publicKey, signature, header, presentationHeader, messages, revealedIndexes, mockedCalculateRandomScalars)
	if err != nil {
		t.Fatalf("Failed to generate proof: %v", err)
	}

	// Verify the proof
	valid, err := bbs.ProofVerify(publicKey, proof, header, presentationHeader, disclosedMessages, revealedIndexes)
	if err != nil {
		t.Fatalf("ProofVerify failed: %v", err)
	}

	if !valid {
		t.Error("Proof should be valid but verification failed")
	}

	// Test with wrong disclosed message - should fail
	wrongMessage := [][]byte{mustDecodeHex("0000000000000000000000000000000000000000000000000000000000000000")}
	valid, err = bbs.ProofVerify(publicKey, proof, header, presentationHeader, wrongMessage, revealedIndexes)
	if err != nil {
		t.Fatalf("ProofVerify failed: %v", err)
	}

	if valid {
		t.Error("Proof should be invalid with wrong disclosed message")
	}

	// Test with wrong header - should fail
	wrongHeader := []byte("wrong header")
	valid, err = bbs.ProofVerify(publicKey, proof, wrongHeader, presentationHeader, disclosedMessages, revealedIndexes)
	if err != nil {
		t.Fatalf("ProofVerify failed: %v", err)
	}

	if valid {
		t.Error("Proof should be invalid with wrong header")
	}
}

// Test ProofVerify for the multi-message all disclosed proof
func TestProofVerifyMultiMessageAllDisclosed(t *testing.T) {
	// Test data from spec section 8.3.5.2
	messages := [][]byte{
		mustDecodeHex("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"),
		mustDecodeHex("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80"),
		mustDecodeHex("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73"),
		mustDecodeHex("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c"),
		mustDecodeHex("496694774c5604ab1b2544eababcf0f53278ff50"),
		mustDecodeHex("515ae153e22aae04ad16f759e07237b4"),
		mustDecodeHex("d183ddc6e2665aa4e2f088af"),
		mustDecodeHex("ac55fb33a75909ed"),
		mustDecodeHex("96012096"),
		mustDecodeHex(""),
	}

	publicKey := mustDecodeHex("92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb18fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5")
	signature := mustDecodeHex("956a3427b1b8e3642e60e6a7990b67626811adeec7a0a6cb4f770cdd7c20cf08faabb913ac94d18e1e92832e924cb6e202912b624261fc6c59b0fea801547f67fb7d3253e1e2acbcf90ef59a6911931e")
	header := mustDecodeHex("11223344556677889900aabbccddeeff")
	presentationHeader := mustDecodeHex("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501")
	revealedIndexes := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9} // All messages disclosed
	disclosedMessages := messages                          // All messages are disclosed

	// Generate proof using test function
	proof, err := testProofGen(publicKey, signature, header, presentationHeader, messages, revealedIndexes, mockedCalculateRandomScalars)
	if err != nil {
		t.Fatalf("Failed to generate proof: %v", err)
	}

	// Verify the proof
	valid, err := bbs.ProofVerify(publicKey, proof, header, presentationHeader, disclosedMessages, revealedIndexes)
	if err != nil {
		t.Fatalf("ProofVerify failed: %v", err)
	}

	if !valid {
		t.Error("Proof should be valid but verification failed")
	}

	// Test with wrong disclosed indexes - should fail
	wrongIndexes := []int{0, 1, 2, 3, 4, 5, 6, 7, 8} // Missing index 9
	valid, err = bbs.ProofVerify(publicKey, proof, header, presentationHeader, disclosedMessages[:9], wrongIndexes)
	if err != nil {
		t.Fatalf("ProofVerify failed: %v", err)
	}

	if valid {
		t.Error("Proof should be invalid with wrong disclosed indexes")
	}
}

// Test ProofVerify for the multi-message some disclosed proof
func TestProofVerifyMultiMessageSomeDisclosed(t *testing.T) {
	// Test data from spec section 8.3.5.3
	messages := [][]byte{
		mustDecodeHex("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"),
		mustDecodeHex("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80"),
		mustDecodeHex("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73"),
		mustDecodeHex("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c"),
		mustDecodeHex("496694774c5604ab1b2544eababcf0f53278ff50"),
		mustDecodeHex("515ae153e22aae04ad16f759e07237b4"),
		mustDecodeHex("d183ddc6e2665aa4e2f088af"),
		mustDecodeHex("ac55fb33a75909ed"),
		mustDecodeHex("96012096"),
		mustDecodeHex(""),
	}

	publicKey := mustDecodeHex("92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb18fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5")
	signature := mustDecodeHex("956a3427b1b8e3642e60e6a7990b67626811adeec7a0a6cb4f770cdd7c20cf08faabb913ac94d18e1e92832e924cb6e202912b624261fc6c59b0fea801547f67fb7d3253e1e2acbcf90ef59a6911931e")
	header := mustDecodeHex("11223344556677889900aabbccddeeff")
	presentationHeader := mustDecodeHex("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501")
	revealedIndexes := []int{0, 2, 4, 6} // Some messages disclosed
	disclosedMessages := [][]byte{
		messages[0], // index 0
		messages[2], // index 2
		messages[4], // index 4
		messages[6], // index 6
	}

	// Generate proof using test function
	proof, err := testProofGen(publicKey, signature, header, presentationHeader, messages, revealedIndexes, mockedCalculateRandomScalars)
	if err != nil {
		t.Fatalf("Failed to generate proof: %v", err)
	}

	// Verify the proof
	valid, err := bbs.ProofVerify(publicKey, proof, header, presentationHeader, disclosedMessages, revealedIndexes)
	if err != nil {
		t.Fatalf("ProofVerify failed: %v", err)
	}

	if !valid {
		t.Error("Proof should be valid but verification failed")
	}

	// Test with wrong presentation header - should fail
	wrongPH := []byte("wrong presentation header")
	valid, err = bbs.ProofVerify(publicKey, proof, header, wrongPH, disclosedMessages, revealedIndexes)
	if err != nil {
		t.Fatalf("ProofVerify failed: %v", err)
	}

	if valid {
		t.Error("Proof should be invalid with wrong presentation header")
	}

	// Test with messages in wrong order - should fail
	wrongOrderMessages := [][]byte{
		messages[2], // Should be index 0
		messages[0], // Should be index 2
		messages[4], // index 4
		messages[6], // index 6
	}
	valid, err = bbs.ProofVerify(publicKey, proof, header, presentationHeader, wrongOrderMessages, revealedIndexes)
	if err != nil {
		t.Fatalf("ProofVerify failed: %v", err)
	}

	if valid {
		t.Error("Proof should be invalid with messages in wrong order")
	}
}

// Test ProofVerify with invalid proof data
func TestProofVerifyInvalidProof(t *testing.T) {
	publicKey := mustDecodeHex("92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb18fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5")
	header := []byte("header")
	presentationHeader := []byte("ph")
	disclosedMessages := [][]byte{mustDecodeHex("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02")}
	revealedIndexes := []int{0}

	// Test with proof too short
	shortProof := make([]byte, 10)
	valid, err := bbs.ProofVerify(publicKey, shortProof, header, presentationHeader, disclosedMessages, revealedIndexes)
	if err == nil {
		t.Error("Expected error for proof too short")
	}
	if valid {
		t.Error("Short proof should not be valid")
	}

	// Test with malformed proof data
	malformedProof := make([]byte, 3*bbs.OCTET_POINT_LENGTH+4*bbs.OCTET_SCALAR_LENGTH)
	// Fill with invalid point data
	for i := range malformedProof {
		malformedProof[i] = 0xFF
	}

	valid, err = bbs.ProofVerify(publicKey, malformedProof, header, presentationHeader, disclosedMessages, revealedIndexes)
	if err == nil {
		t.Error("Expected error for malformed proof")
	}
	if valid {
		t.Error("Malformed proof should not be valid")
	}
}

// Test ProofVerify with valid proof from expected test vectors
func TestProofVerifyWithExpectedProofs(t *testing.T) {
	// Test with the expected proof from spec section 8.3.5.1
	publicKey, _ := hex.DecodeString("92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb18fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5")
	header, _ := hex.DecodeString("11223344556677889900aabbccddeeff")
	presentationHeader, _ := hex.DecodeString("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501")
	expectedProof, _ := hex.DecodeString("89e4ab0c160880e0c2f12a754b9c051ed7f5fccfee3d5cbbb62e1239709196c737fff4303054660f8fcd08267a5de668a2e395ebe8866bdcb0dff9786d7014fa5e3c8cf7b41f8d7510e27d307f18032f6b788e200b9d6509f40ce1d2f962ceedb023d58ee44d660434e6ba60ed0da1a5d2cde031b483684cd7c5b13295a82f57e209b584e8fe894bcc964117bf3521b43d8e2eb59ce31f34d68b39f05bb2c625e4de5e61e95ff38bfd62ab07105d016414b45b01625c69965ad3c8a933e7b25d93daeb777302b966079827a99178240e6c3f13b7db2fb1f14790940e239d775ab32f539bdf9f9b582b250b05882996832652f7f5d3b6e04744c73ada1702d6791940ccbd75e719537f7ace6ee817298d")
	disclosedMessages := [][]byte{mustDecodeHex("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02")}
	revealedIndexes := []int{0}

	// Verify the expected proof
	valid, err := bbs.ProofVerify(publicKey, expectedProof, header, presentationHeader, disclosedMessages, revealedIndexes)
	if err != nil {
		t.Fatalf("ProofVerify failed with expected proof: %v", err)
	}

	if !valid {
		t.Error("Expected proof from BBS spec should be valid")
	}
}
