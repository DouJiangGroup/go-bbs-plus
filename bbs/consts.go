package bbs

const (
	// BLS12-381-SHAKE-256 ciphersuite parameters (Section 6.2.1)
	CiphersuiteID     = "BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_"
	OctetScalarLength = 32
	OctetPointLength  = 48
	ExpandLen         = 48

	// Keygen
	KeygenDST = CiphersuiteID + "KEYGEN_DST_"

	// Generator
	P1Hex = "8929dfbc7e6642c4ed9cba0856e493f8b9d7d5fcb0c31ef8fdcd34d50648a56c795e106e9eada6e0bda386b414150755"

	P1GeneratorSeed = CiphersuiteID + "BP_MESSAGE_GENERATOR_SEED"
	GeneratorSeed   = CiphersuiteID + "MESSAGE_GENERATOR_SEED"
	SeedDST         = CiphersuiteID + "SIG_GENERATOR_SEED_" // 19 bytes
	GeneratorDST    = CiphersuiteID + "SIG_GENERATOR_DST_"  // 18 bytes
)
