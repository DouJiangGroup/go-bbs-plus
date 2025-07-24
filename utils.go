package bbs

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"golang.org/x/crypto/sha3"
)

// ================================================================
// Encoding utilities

// I2OSP converts an integer to an octet string of specified length
// As defined in RFC 3447, Section 4.1
func I2OSP(val int, length int) []byte {
	if length <= 0 {
		return nil
	}

	result := make([]byte, length)
	switch length {
	case 1:
		result[0] = byte(val)
	case 2:
		binary.BigEndian.PutUint16(result, uint16(val))
	case 4:
		binary.BigEndian.PutUint32(result, uint32(val))
	case 8:
		binary.BigEndian.PutUint64(result, uint64(val))
	default:
		// For other lengths, handle manually
		for i := length - 1; i >= 0; i-- {
			result[i] = byte(val & 0xFF)
			val >>= 8
		}
	}

	return result
}

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

// OctetsToPublicKey decodes an octet string representing a public key,
// validates it and returns the corresponding point in G2.
// Implements Section 4.7.6 of the BBS specification.
func OctetsToPublicKey(pk []byte) (bls12381.G2Affine, error) {
	// 1. W = octets_to_point_g2(PK)
	W, err := OctetsToPointG2(pk)

	// 2. If W is INVALID, return INVALID
	if err != nil {
		return bls12381.G2Affine{}, errors.New("INVALID: cannot decode G2 point")
	}

	// 3. if subgroup_check(W) is INVALID, return INVALID
	if !W.IsInSubGroup() {
		return bls12381.G2Affine{}, errors.New("INVALID: point not in correct subgroup")
	}

	// 4. If W == Identity_G2, return INVALID
	if W.IsInfinity() {
		return bls12381.G2Affine{}, errors.New("INVALID: public key is identity element")
	}

	// 5. return W
	return W, nil
}

// ================================================================
// Serialization utility

// Serialize serializes an array of elements (G1/G2 points, scalars, ASCII strings, or integers) to a single octet string.
func Serialize(inputArray ...interface{}) ([]byte, error) {
	octetsResult := []byte{}
	for _, el := range inputArray {
		switch v := el.(type) {
		case bls12381.G1Affine:
			if !v.IsOnCurve() {
				return nil, fmt.Errorf("INVALID: G1 point not on curve")
			}
			octetsResult = append(octetsResult, PointToOctetsG1(v)...)
		case bls12381.G2Affine:
			if !v.IsOnCurve() {
				return nil, fmt.Errorf("INVALID: G2 point not on curve")
			}
			octetsResult = append(octetsResult, PointToOctetsG2(v)...)
		case fr.Element:
			// Use the fr.Element's native Bytes() method
			bytes := v.Bytes() // Should be exactly 32 bytes
			octetsResult = append(octetsResult, bytes[:]...)
		case []byte:
			octetsResult = append(octetsResult, v...)
		case string:
			octetsResult = append(octetsResult, []byte(v)...)
		case int:
			octetsResult = append(octetsResult, I2OSP(v, 8)...)
		case uint64:
			octetsResult = append(octetsResult, I2OSP(int(v), 8)...)
		default:
			return nil, errors.New("INVALID: unsupported type in serialize")
		}
	}
	return octetsResult, nil
}

// ================================================================
// Signature serialization utilities

// SignatureToOctets encodes a signature (A, e) to an octet string as per BBS spec 4.7.2
func SignatureToOctets(A bls12381.G1Affine, e fr.Element) ([]byte, error) {
	return Serialize(A, e)
}

// OctetsToSignature decodes an octet string to a signature (A, e) as per BBS spec 4.7.3
func OctetsToSignature(signatureOctets []byte) (bls12381.G1Affine, fr.Element, error) {
	expectedLen := OCTET_POINT_LENGTH + OCTET_SCALAR_LENGTH // 48 + 32 = 80 bytes
	if len(signatureOctets) != expectedLen {
		return bls12381.G1Affine{}, fr.Element{}, errors.New("INVALID: signature octet length")
	}

	A_octets := signatureOctets[:OCTET_POINT_LENGTH]
	A, err := OctetsToPointG1(A_octets)
	if err != nil {
		return bls12381.G1Affine{}, fr.Element{}, errors.New("INVALID: cannot decode G1 point")
	}
	if A.IsInfinity() {
		return bls12381.G1Affine{}, fr.Element{}, errors.New("INVALID: G1 point is identity")
	}

	index := OCTET_POINT_LENGTH
	endIndex := index + OCTET_SCALAR_LENGTH
	eBytes := signatureOctets[index:endIndex]
	var e fr.Element
	e.SetBytes(eBytes)
	if e.IsZero() {
		return bls12381.G1Affine{}, fr.Element{}, errors.New("INVALID: scalar e is zero")
	}

	return A, e, nil
}

// ================================================================
// Scalar representation utilities

// expandMessageXOF implements expand_message_xof as defined in
// RFC 9380, Section 5.3.3 for SHAKE-256
func expandMessageXOF(msg []byte, dst []byte, lenInBytes int) []byte {
	shake := sha3.NewShake256()

	// Construct DST_prime = DST || I2OSP(len(DST), 1)
	dstPrime := append(dst, byte(len(dst)))

	// Input: msg || I2OSP(len_in_bytes, 2) || DST_prime
	shake.Write(msg)
	shake.Write(I2OSP(lenInBytes, 2))
	shake.Write(dstPrime)

	output := make([]byte, lenInBytes)
	shake.Read(output)
	return output
}

// mapToScalarAsHash implements map_to_scalar_as_hash from Section 4.3.1.1
//
// Inputs:
// - msg, an octet string.
// - dst, an octet string representing the domain separation tag.
//
// Outputs:
// - scalar, a scalar.
//
// Procedure:
// 1. uniform_bytes = expand_message(msg, dst, expand_len)
// 2. scalar = OS2IP(uniform_bytes) mod r
// 3. if scalar == 0, return INVALID
// 4. return scalar
func mapToScalarAsHash(msg []byte, dst []byte) (fr.Element, error) {
	var scalar fr.Element

	// 1. uniform_bytes = expand_message(msg, dst, expand_len)
	uniformBytes := expandMessageXOF(msg, dst, EXPAND_LEN)

	// 2. scalar = OS2IP(uniform_bytes) mod r
	// SetBytes interprets uniformBytes as big-endian integer and reduces mod r
	scalar.SetBytes(uniformBytes)

	// 3. if scalar == 0, return INVALID
	if scalar.IsZero() {
		return scalar, errors.New("INVALID: scalar is zero")
	}

	// 4. return scalar
	return scalar, nil
}

// hashToScalar implements hash_to_scalar using map_to_scalar_as_hash
// as specified in Section 6.2.1 (map_to_scalar: map_to_scalar_as_hash)
func hashToScalar(msg []byte, dst []byte) (fr.Element, error) {
	if dst == nil {
		dst = []byte(CIPHERSUITE_ID + "H2S_")
	}
	return mapToScalarAsHash(msg, dst)
}

// MessagesToScalars maps a list of input messages as octet strings
// to their respective scalar values, required by Sign, Verify, ProofGen,
// and ProofVerify
func MessagesToScalars(messages [][]byte, apiID []byte) ([]fr.Element, error) {
	if apiID == nil {
		apiID = []byte{}
	}

	if len(messages) > math.MaxInt {
		return nil, errors.New("INVALID: too many messages")
	}

	dst := append(apiID, []byte(MAP_MSG_TO_SCALAR_AS_HASH_ID)...)
	scalars := make([]fr.Element, len(messages))

	for i, msg := range messages {
		msgCopy := append([]byte{}, msg...)
		scalar, err := hashToScalar(msgCopy, dst)
		if err != nil {
			return nil, fmt.Errorf("INVALID: hash_to_scalar failed for message %d: %w", i, err)
		}
		scalars[i] = scalar
	}

	return scalars, nil
}

// ================================================================
// Domain calculation utility

// CalculateDomain computes the domain scalar as per BBS spec 4.5
func CalculateDomain(pk []byte, Q1 bls12381.G1Affine, HPoints []bls12381.G1Affine, header []byte, apiID []byte) (fr.Element, error) {
	if header == nil {
		header = []byte{}
	}
	if apiID == nil {
		apiID = []byte{}
	}

	if len(pk) != OCTET_POINT_LENGTH*2 {
		return fr.Element{}, errors.New("INVALID: public key length")
	}

	L := uint64(len(HPoints))

	if Q1.IsInfinity() {
		return fr.Element{}, errors.New("INVALID: Q1 cannot be infinity")
	}
	for i, h := range HPoints {
		if h.IsInfinity() {
			return fr.Element{}, fmt.Errorf("INVALID: H point %d cannot be infinity", i)
		}
	}

	// Step 1: dom_array = (L, Q_1, H_1, ..., H_L)
	domArray := []interface{}{L, Q1}
	for _, h := range HPoints {
		domArray = append(domArray, h)
	}

	// Step 2: dom_octs = serialize(dom_array) || api_id
	domOcts, err := Serialize(domArray...)
	if err != nil {
		return fr.Element{}, err
	}
	domOcts = append(domOcts, apiID...)

	// Step 3: dom_input = PK || dom_octs || I2OSP(length(header), 8) || header
	domInput := append([]byte{}, pk...)
	domInput = append(domInput, domOcts...)
	domInput = append(domInput, I2OSP(len(header), 8)...)
	domInput = append(domInput, header...)

	// Step 4: hash_to_scalar_dst = api_id || "H2S_"
	hashToScalarDST := append(apiID, []byte("H2S_")...)

	// Step 5: return hash_to_scalar(dom_input, hash_to_scalar_dst)
	return hashToScalar(domInput, hashToScalarDST)
}
