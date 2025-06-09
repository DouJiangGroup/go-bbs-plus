package test

import (
	"fmt"
	"testing"

	"github.com/Iscaraca/goproof/internal/hash/sha"
	"github.com/Iscaraca/goproof/internal/hash/util/cast"
)

// SHA-256 Tests

// TestSHA256Basic tests the SHA-256 implementation with the standard test vector "abc"
func TestSHA256Basic(t *testing.T) {
	// Test with "abc"
	message := cast.StringToBits("abc")
	hash := sha.SHA256(message)

	// Expected result for "abc": ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
	expected := [8]uint32{
		0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223,
		0xb00361a3, 0x96177a9c, 0xb410ff61, 0xf20015ad,
	}

	for i, expectedValue := range expected {
		if hash[i] != expectedValue {
			t.Errorf("SHA-256 hash mismatch at index %d: got %08x, expected %08x", i, hash[i], expectedValue)
		}
	}

	// Print the result for verification
	fmt.Printf("SHA-256 of 'abc':\n")
	for i, h := range hash {
		fmt.Printf("H[%d]: %08x\n", i, h)
	}

	// Print as hex string
	fmt.Printf("Full hash: ")
	for _, h := range hash {
		fmt.Printf("%08x", h)
	}
	fmt.Println()
}

// TestSHA256Empty tests SHA-256 with empty string
func TestSHA256Empty(t *testing.T) {
	// Test with empty string
	message := cast.StringToBits("")
	hash := sha.SHA256(message)

	// Expected result for "": e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
	expected := [8]uint32{
		0xe3b0c442, 0x98fc1c14, 0x9afbf4c8, 0x996fb924,
		0x27ae41e4, 0x649b934c, 0xa495991b, 0x7852b855,
	}

	for i, expectedValue := range expected {
		if hash[i] != expectedValue {
			t.Errorf("SHA-256 hash mismatch at index %d: got %08x, expected %08x", i, hash[i], expectedValue)
		}
	}

	fmt.Printf("SHA-256 of empty string:\n")
	for _, h := range hash {
		fmt.Printf("%08x", h)
	}
	fmt.Println()
}

// TestSHA256LongerMessage tests with a longer message
func TestSHA256LongerMessage(t *testing.T) {
	// Test with "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
	message := cast.StringToBits("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
	hash := sha.SHA256(message)

	// Expected result: 248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1
	expected := [8]uint32{
		0x248d6a61, 0xd20638b8, 0xe5c02693, 0x0c3e6039,
		0xa33ce459, 0x64ff2167, 0xf6ecedd4, 0x19db06c1,
	}

	for i, expectedValue := range expected {
		if hash[i] != expectedValue {
			t.Errorf("SHA-256 hash mismatch at index %d: got %08x, expected %08x", i, hash[i], expectedValue)
		}
	}

	fmt.Printf("SHA-256 of longer message:\n")
	for _, h := range hash {
		fmt.Printf("%08x", h)
	}
	fmt.Println()
}

// SHA-512 Tests

// TestSHA512Basic tests the SHA-512 implementation with the standard test vector "abc"
func TestSHA512Basic(t *testing.T) {
	// Test with "abc"
	message := cast.StringToBits("abc")
	hash := sha.SHA512(message)

	// Expected result for "abc": ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f
	expected := [8]uint64{
		0xddaf35a193617aba, 0xcc417349ae204131, 0x12e6fa4e89a97ea2, 0x0a9eeee64b55d39a,
		0x2192992a274fc1a8, 0x36ba3c23a3feebbd, 0x454d4423643ce80e, 0x2a9ac94fa54ca49f,
	}

	for i, expectedValue := range expected {
		if hash[i] != expectedValue {
			t.Errorf("SHA-512 hash mismatch at index %d: got %016x, expected %016x", i, hash[i], expectedValue)
		}
	}

	// Print the result for verification
	fmt.Printf("SHA-512 of 'abc':\n")
	for i, h := range hash {
		fmt.Printf("H[%d]: %016x\n", i, h)
	}

	// Print as hex string
	fmt.Printf("Full hash: ")
	for _, h := range hash {
		fmt.Printf("%016x", h)
	}
	fmt.Println()
}

// TestSHA512Empty tests SHA-512 with empty string
func TestSHA512Empty(t *testing.T) {
	// Test with empty string
	message := cast.StringToBits("")
	hash := sha.SHA512(message)

	// Expected result for "": cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e
	expected := [8]uint64{
		0xcf83e1357eefb8bd, 0xf1542850d66d8007, 0xd620e4050b5715dc, 0x83f4a921d36ce9ce,
		0x47d0d13c5d85f2b0, 0xff8318d2877eec2f, 0x63b931bd47417a81, 0xa538327af927da3e,
	}

	for i, expectedValue := range expected {
		if hash[i] != expectedValue {
			t.Errorf("SHA-512 hash mismatch at index %d: got %016x, expected %016x", i, hash[i], expectedValue)
		}
	}

	fmt.Printf("SHA-512 of empty string:\n")
	for _, h := range hash {
		fmt.Printf("%016x", h)
	}
	fmt.Println()
}

// TestSHA512LongerMessage tests with a longer message
func TestSHA512LongerMessage(t *testing.T) {
	// Test with "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
	message := cast.StringToBits("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
	hash := sha.SHA512(message)

	// Expected result: 204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445
	expected := [8]uint64{
		0x204a8fc6dda82f0a, 0x0ced7beb8e08a416, 0x57c16ef468b228a8, 0x279be331a703c335,
		0x96fd15c13b1b07f9, 0xaa1d3bea57789ca0, 0x31ad85c7a71dd703, 0x54ec631238ca3445,
	}

	for i, expectedValue := range expected {
		if hash[i] != expectedValue {
			t.Errorf("SHA-512 hash mismatch at index %d: got %016x, expected %016x", i, hash[i], expectedValue)
		}
	}

	fmt.Printf("SHA-512 of longer message:\n")
	for _, h := range hash {
		fmt.Printf("%016x", h)
	}
	fmt.Println()
}

// Benchmarks

// BenchmarkSHA256 benchmarks the SHA-256 implementation
func BenchmarkSHA256(b *testing.B) {
	message := cast.StringToBits("abc")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sha.SHA256(message)
	}
}

// BenchmarkSHA512 benchmarks the SHA-512 implementation
func BenchmarkSHA512(b *testing.B) {
	message := cast.StringToBits("abc")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sha.SHA512(message)
	}
}
