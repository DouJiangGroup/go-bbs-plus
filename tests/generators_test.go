package test

import (
	"encoding/hex"
	"testing"

	bbs "github.com/Iscaraca/bbs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestP1FixedPoint(t *testing.T) {
	// Expected P1 from Section 6.2.1 (BLS12-381-SHAKE-256 suite)
	expectedHex := "8929dfbc7e6642c4ed9cba0856e493f8b9d7d5fcb0c31ef8fdcd34d50648a56c795e106e9eada6e0bda386b414150755"
	expected, err := hex.DecodeString(expectedHex)
	require.NoError(t, err)

	// Generate P1
	p1, err := bbs.CreateP1()
	require.NoError(t, err, "CreateP1 should not fail")

	actual := bbs.PointToOctetsG1(p1)
	assert.Equal(t, expected, actual, "Generated P1 fixed point does not match expected value")

	// Get cached P1
	p1Cached := bbs.GetP1()
	actual = bbs.PointToOctetsG1(p1Cached)
	assert.Equal(t, expected, actual, "Cached P1 fixed point does not match expected value")
}

func TestMessageGenerators(t *testing.T) {
	// Expected generators from spec Section 8.3.3 (BLS12-381-SHAKE-256 suite)
	expectedGenerators := []string{
		// Q_1 (domain generator)
		"a9d40131066399fd41af51d883f4473b0dcd7d028d3d34ef17f3241d204e28507d7ecae032afa1d5490849b7678ec1f8",
		// H_1 through H_10 (message generators)
		"903c7ca0b7e78a2017d0baf74103bd00ca8ff9bf429f834f071c75ffe6bfdec6d6dca15417e4ac08ca4ae1e78b7adc0e",
		"84321f5855bfb6b001f0dfcb47ac9b5cc68f1a4edd20f0ec850e0563b27d2accee6edff1a26b357762fb24e8ddbb6fcb",
		"b3060dff0d12a32819e08da00e61810676cc9185fdd750e5ef82b1a9798c7d76d63de3b6225d6c9a479d6c21a7c8bf93",
		"8f1093d1e553cdead3c70ce55b6d664e5d1912cc9edfdd37bf1dad11ca396a0a8bb062092d391ebf8790ea5722413f68",
		"990824e00b48a68c3d9a308e8c52a57b1bc84d1cf5d3c0f8c6fb6b1230e4e5b8eb752fb374da0b1ef687040024868140",
		"b86d1c6ab8ce22bc53f625d1ce9796657f18060fcb1893ce8931156ef992fe56856199f8fa6c998e5d855a354a26b0dd",
		"b4cdd98c5c1e64cb324e0c57954f719d5c5f9e8d991fd8e159b31c8d079c76a67321a30311975c706578d3a0ddc313b7",
		"8311492d43ec9182a5fc44a75419b09547e311251fe38b6864dc1e706e29446cb3ea4d501634eb13327245fd8a574f77",
		"ac00b493f92d17837a28d1f5b07991ca5ab9f370ae40d4f9b9f2711749ca200110ce6517dc28400d4ea25dddc146cacc",
		"965a6c62451d4be6cb175dec39727dc665762673ee42bf0ac13a37a74784fbd61e84e0915277a6f59863b2bb4f5f6005",
	}

	// Use proper api_id for BLS12-381-SHAKE-256 ciphersuite
	apiID := []byte(bbs.CIPHERSUITE_ID + bbs.H2G_HM2S_ID)
	generators, err := bbs.CreateGenerators(11, apiID)
	require.NoError(t, err, "CreateGenerators should not fail")
	require.Len(t, generators, 11, "Should generate exactly 11 generators")

	// Verify each generator matches the expected value from spec
	for i, expectedHex := range expectedGenerators {
		expected, err := hex.DecodeString(expectedHex)
		require.NoError(t, err, "Failed to decode expected generator hex for index %d", i)

		actual := bbs.PointToOctetsG1(generators[i])
		assert.Equal(t, expected, actual, "Generator %d does not match expected value from specification", i)
	}
}
