package test

import (
	"encoding/hex"
	"testing"

	bbs "github.com/Iscaraca/bbs"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/assert"
)

func TestValidSingleMessageSignature(t *testing.T) {
	headerHex := "11223344556677889900aabbccddeeff"
	msgHex := "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"
	skHex := "2eee0f60a8a3a8bec0ee942bfd46cbdae9a0738ee68f5a64e7238311cf09a079"
	expectedSigHex := "98eb37fceb31115bf647f2983aef578ad895e55f7451b1add02fa738224cb89a31b148eace4d20d001be31d162c58d12574f30e68665b6403956a83b23a16f1daceacce8c5fde25d3defd52d6d5ff2e1"

	header, _ := hex.DecodeString(headerHex)
	msg, _ := hex.DecodeString(msgHex)
	skBytes, _ := hex.DecodeString(skHex)
	expectedSig, _ := hex.DecodeString(expectedSigHex)

	var sk fr.Element
	sk.SetBytes(skBytes)
	pkBytes, _ := bbs.SkToPk(sk)

	sig, err := bbs.Sign(sk, pkBytes, header, [][]byte{msg})
	assert.NoError(t, err)
	assert.Equal(t, expectedSig, sig)
}

func TestValidMultiMessageSignature(t *testing.T) {
	headerHex := "11223344556677889900aabbccddeeff"
	msgsHex := []string{
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
	skHex := "2eee0f60a8a3a8bec0ee942bfd46cbdae9a0738ee68f5a64e7238311cf09a079"
	expectedSigHex := "97a296c83ed3626fe254d26021c5e9a087b580f1e8bc91bb51efb04420bfdaca215fe376a0bc12440bcc52224fb33c696cca9239b9f28dcddb7bd850aae9cd1a9c3e9f3639953fe789dbba53b8f0dd6f"

	header, _ := hex.DecodeString(headerHex)
	msgs := make([][]byte, len(msgsHex))
	for i, m := range msgsHex {
		msgs[i], _ = hex.DecodeString(m)
	}
	skBytes, _ := hex.DecodeString(skHex)
	expectedSig, _ := hex.DecodeString(expectedSigHex)

	var sk fr.Element
	sk.SetBytes(skBytes)
	pkBytes, _ := bbs.SkToPk(sk)

	sig, err := bbs.Sign(sk, pkBytes, header, msgs)
	assert.NoError(t, err)
	assert.Equal(t, expectedSig, sig)
}
