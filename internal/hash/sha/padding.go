// Helper padding functions for sha256 and 512
package sha

import (
	"fmt"
	"math/big"

	"github.com/Iscaraca/goproof/internal/hash/util/cast"
)

// For sha256: blockSize 512
// For sha512: blockSize 1024
func padMessage(message []bool, blockSize uint16) []bool {
	messageLength := uint64(len(message))

	// Determine length field size based on block size
	var lengthFieldBits int
	switch blockSize {
	case 512: // SHA-256
		lengthFieldBits = 64
	case 1024: // SHA-512
		lengthFieldBits = 128
	default:
		panic(fmt.Sprintf("Unsupported block size: %d", blockSize))
	}

	target := int(blockSize) - lengthFieldBits

	padded := make([]bool, len(message))
	copy(padded, message)

	padded = append(padded, true)

	currentLength := len(message) + 1
	k := (target - currentLength) % int(blockSize)
	if k < 0 {
		k += int(blockSize)
	}

	for i := 0; i < k; i++ {
		padded = append(padded, false)
	}

	lengthBits := cast.BigIntToBits(big.NewInt(int64(messageLength)), lengthFieldBits)
	padded = append(padded, lengthBits...)

	return padded
}
