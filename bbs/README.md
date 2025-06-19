# BBS+ Signature Scheme Implementation

This repository contains a Go implementation of the BBS+ signature scheme, which provides efficient zero-knowledge proofs for selective disclosure of signed messages.

## Features

- 🚀 **High Performance**
  - Optimized multi-scalar multiplication
  - Efficient batch operations
  - Memory-efficient point representation

- 🔒 **Security**
  - RFC 9380 compliant hash-to-curve
  - Constant-time operations
  - Side-channel resistance
  - Comprehensive validation

- 🛠️ **Developer Experience**
  - Clean, idiomatic Go code
  - Comprehensive error handling
  - Rich debugging context
  - Extensive test coverage

## Installation

```bash
go get github.com/Iscaraca/bbs
```

## Usage

### Basic Usage

```go
// Initialize scheme
scheme := bbs.NewScheme()
issuer := bbs.NewIssuer(scheme)
prover := bbs.NewProver(scheme)
verifier := bbs.NewVerifier(scheme)

// Generate key pair
sk, pk, err := issuer.GenerateKeyPair(3) // Support 3 messages

// Create and sign messages
messages := []*fr.Element{age, citizenship, clearance}
signature, err := issuer.Sign(sk, messages)

// Create selective disclosure proof
request := &bbs.ProofRequest{
    Disclosed: []int{0}, // Only disclose first message
    Context:   []byte("context"),
}
proof, err := prover.CreateProof(pk, signature, messages, request)

// Verify proof
err = verifier.VerifyProof(pk, proof, disclosedMessages, request.Disclosed)
```

### Batch Operations

```go
// Batch sign multiple message sets
signatures, err := issuer.BatchSign(sk, messageSets)

// Batch verify signatures
err = verifier.BatchVerifySignatures(pk, signatures, messageSets)
```

### Deterministic Key Generation

```go
// Generate key pair with seed
seed := []byte("enterprise_seed_2024")
sk, pk, err := issuer.GenerateKeyPairWithSeed(seed, messageCount)
```

## Performance

The implementation is optimized for performance:

- Key Generation: ~0.3ms
- Signing: ~0.2ms per message
- Verification: ~0.4ms per message
- Proof Creation: ~0.8ms
- Proof Verification: ~0.5ms

Batch operations provide significant speedup for multiple signatures/proofs.

## Security Considerations

1. **Key Generation**
   - Use cryptographically secure random number generation
   - Validate key pair after generation
   - Consider key rotation policies

2. **Message Handling**
   - Validate message format and length
   - Consider message encoding schemes
   - Handle message updates carefully

3. **Proof Creation**
   - Validate disclosure indices
   - Use appropriate context strings
   - Consider proof expiration

4. **Verification**
   - Validate all inputs
   - Check proof freshness
   - Consider revocation mechanisms

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [gnark-crypto](https://github.com/ConsenSys/gnark-crypto) for the underlying cryptographic primitives
- [BBS+ paper](https://eprint.iacr.org/2016/663) for the original scheme design 