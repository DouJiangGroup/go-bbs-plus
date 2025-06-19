package bbs

import (
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// Fetch the built-in generators
var (
	_, _, g1Aff, g2Aff = bls12381.Generators()
)

// PointToOctetsG1 converts a G1 point to octets using compression
func PointToOctetsG1(p bls12381.G1Affine) []byte {
	bytes := p.Bytes()
	return bytes[:]
}

// PointToOctetsG2 converts a G2 point to octets using compression
func PointToOctetsG2(p bls12381.G2Affine) []byte {
	bytes := p.Bytes()
	return bytes[:]
}

// OctetsToPointG1 converts octets to a G1 point
func OctetsToPointG1(bytes []byte) (bls12381.G1Affine, error) {
	var point bls12381.G1Affine
	_, err := point.SetBytes(bytes)
	return point, err
}

// OctetsToPointG2 converts octets to a G2 point
func OctetsToPointG2(bytes []byte) (bls12381.G2Affine, error) {
	var point bls12381.G2Affine
	_, err := point.SetBytes(bytes)
	return point, err
}
