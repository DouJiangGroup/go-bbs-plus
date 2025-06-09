// Casting functions to facilitate hashing
package cast

import (
	"math/big"
)

func BigIntToBits(n *big.Int, numBits int) []bool {
	bits := make([]bool, numBits)
	for i := 0; i < numBits; i++ {
		bits[numBits-1-i] = n.Bit(i) == 1
	}
	return bits
}

func BitsToUint32(bits []bool) uint32 {
	var result uint32
	for i, bit := range bits {
		if bit {
			result |= 1 << (31 - i)
		}
	}
	return result
}

func BitsToUint64(bits []bool) uint64 {
	var result uint64
	for i, bit := range bits {
		if bit {
			result |= 1 << (63 - i)
		}
	}
	return result
}

// Helper function to convert string to bits for easy testing
func StringToBits(s string) []bool {
	var bits []bool
	for _, b := range []byte(s) {
		for i := 7; i >= 0; i-- {
			bits = append(bits, (b>>i)&1 == 1)
		}
	}
	return bits
}
