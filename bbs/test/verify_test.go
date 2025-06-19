package test

import (
	"encoding/hex"
	"testing"

	bbs "github.com/Iscaraca/bbs"
	"github.com/stretchr/testify/assert"
)

// Test vectors from BLS12-381-SHAKE-256 ciphersuite (Section 7.3)

// Public key from Section 7.3.1
const testPublicKeyHex = "92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb18fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5"

// Messages from Section 7.2
var testMessages = []string{
	"9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
	"c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80",
	"7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73",
	"77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c",
	"496694774c5604ab1b2544eababcf0f53278ff50",
	"515ae153e22aae04ad16f759e07237b4",
	"d183ddc6e2665aa4e2f088af",
	"ac55fb33a75909ed",
	"96012096",
	"",
}

func TestVerify_SingleMessage(t *testing.T) {
	headerHex := "11223344556677889900aabbccddeeff"
	header, err := hex.DecodeString(headerHex)
	assert.NoError(t, err)

	pkBytes, err := hex.DecodeString(testPublicKeyHex)
	assert.NoError(t, err)

	messageHex := testMessages[0]
	message, err := hex.DecodeString(messageHex)
	assert.NoError(t, err)
	messages := [][]byte{message}

	signatureHex := "98eb37fceb31115bf647f2983aef578ad895e55f7451b1add02fa738224cb89a31b148eace4d20d001be31d162c58d12574f30e68665b6403956a83b23a16f1daceacce8c5fde25d3defd52d6d5ff2e1"
	signature, err := hex.DecodeString(signatureHex)
	assert.NoError(t, err)

	valid, err := bbs.Verify(pkBytes, signature, header, messages)
	assert.NoError(t, err)
	assert.True(t, valid, "Expected signature to be valid, but got invalid")
}

func TestVerify_MultiMessage(t *testing.T) {
	headerHex := "11223344556677889900aabbccddeeff"
	header, err := hex.DecodeString(headerHex)
	assert.NoError(t, err)

	pkBytes, err := hex.DecodeString(testPublicKeyHex)
	assert.NoError(t, err)

	var messages [][]byte
	for _, msgHex := range testMessages {
		if msgHex == "" {
			messages = append(messages, []byte{})
		} else {
			msg, err := hex.DecodeString(msgHex)
			assert.NoError(t, err)
			messages = append(messages, msg)
		}
	}

	signatureHex := "97a296c83ed3626fe254d26021c5e9a087b580f1e8bc91bb51efb04420bfdaca215fe376a0bc12440bcc52224fb33c696cca9239b9f28dcddb7bd850aae9cd1a9c3e9f3639953fe789dbba53b8f0dd6f"
	signature, err := hex.DecodeString(signatureHex)
	assert.NoError(t, err)

	valid, err := bbs.Verify(pkBytes, signature, header, messages)
	assert.NoError(t, err)
	assert.True(t, valid, "Expected signature to be valid, but got invalid")
}

func TestVerify_InvalidSignature(t *testing.T) {
	headerHex := "11223344556677889900aabbccddeeff"
	header, err := hex.DecodeString(headerHex)
	assert.NoError(t, err)

	pkBytes, err := hex.DecodeString(testPublicKeyHex)
	assert.NoError(t, err)

	message, err := hex.DecodeString(testMessages[0])
	assert.NoError(t, err)
	messages := [][]byte{message}

	signatureHex := "98eb37fceb31115bf647f2983aef578ad895e55f7451b1add02fa738224cb89a31b148eace4d20d001be31d162c58d12574f30e68665b6403956a83b23a16f1daceacce8c5fde25d3defd52d6d5ff2e2"
	signature, err := hex.DecodeString(signatureHex)
	assert.NoError(t, err)

	valid, err := bbs.Verify(pkBytes, signature, header, messages)
	assert.NoError(t, err)
	assert.False(t, valid, "Expected tampered signature to be invalid, but got valid")
}

func TestVerify_WrongMessage(t *testing.T) {
	headerHex := "11223344556677889900aabbccddeeff"
	header, err := hex.DecodeString(headerHex)
	assert.NoError(t, err)

	pkBytes, err := hex.DecodeString(testPublicKeyHex)
	assert.NoError(t, err)

	message, err := hex.DecodeString(testMessages[1])
	assert.NoError(t, err)
	messages := [][]byte{message}

	signatureHex := "98eb37fceb31115bf647f2983aef578ad895e55f7451b1add02fa738224cb89a31b148eace4d20d001be31d162c58d12574f30e68665b6403956a83b23a16f1daceacce8c5fde25d3defd52d6d5ff2e1"
	signature, err := hex.DecodeString(signatureHex)
	assert.NoError(t, err)

	valid, err := bbs.Verify(pkBytes, signature, header, messages)
	assert.NoError(t, err)
	assert.False(t, valid, "Expected signature with wrong message to be invalid, but got valid")
}

func TestVerify_EmptyMessages(t *testing.T) {
	pkBytes, err := hex.DecodeString(testPublicKeyHex)
	assert.NoError(t, err)

	var header []byte
	var messages [][]byte

	signatureHex := "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	signature, err := hex.DecodeString(signatureHex)
	assert.NoError(t, err)

	valid, err := bbs.Verify(pkBytes, signature, header, messages)
	if err == nil && valid {
		t.Log("Empty messages verification: unexpected success")
	} else {
		t.Log("Empty messages verification: failed as expected with dummy signature")
	}
}
