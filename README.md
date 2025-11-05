# Dory PCS

A high-performance, modular implementation of the Dory polynomial commitment scheme in Rust.

## Overview

Dory is a transparent polynomial commitment scheme with excellent asymptotic performance, based on the work of Jonathan Lee ([eprint 2020/1274](https://eprint.iacr.org/2020/1274)). This implementation provides a clean, modular architecture with strong performance characteristics and comprehensive test coverage.

**Key Features:**
- **Transparent setup**: No trusted setup ceremony required
- **Logarithmic proof size**: O(log n) group elements
- **Logarithmic verification**: O(log n) GT exps and 5 pairings
- **Modular design**: Pluggable backends for curves and cryptographic primitives
- **Performance-optimized**: Uses vectorized operations via `DoryRoutines` trait

## Architecture

### Core Modules

- **`primitives`** - Core trait abstractions
  - `arithmetic` - Field, group, and pairing curve traits
  - `poly` - Multilinear polynomial traits and operations
  - `transcript` - Fiat-Shamir transcript trait
  - `serialization` - Serialization abstractions

- **`setup`** - Transparent setup generation for prover and verifier

- **`evaluation_proof`** - Evaluation proof creation and verification

- **`reduce_and_fold`** - Inner product protocol (prover/verifier)

- **`messages`** - Protocol message structures (VMV, reduce rounds, scalar product)

- **`proof`** - Complete proof data structure

- **`error`** - Error types

### Backend Implementations

- **`backends::arkworks`** - Modular Arkworks backend with BN254 curve (requires `arkworks` feature)
  - Field wrappers (`ArkFr`)
  - Group wrappers (`ArkG1`, `ArkG2`, `ArkGT`)
  - Polynomial implementation
  - Optimized MSM routines
  - Blake2b transcript
  - Serialization bridge

## How It Works

Dory uses a two-tier (also known as AFGHO) homomorphic commitments:

1. **Polynomial Representation**: Coefficients are arranged as a 2^ν × 2^σ matrix
2. **Row Commitments** (Tier 1): Each row is committed using multi-scalar multiplication in G1
3. **Final Commitment** (Tier 2): Row commitments are combined via pairings with G2 generators
4. **Evaluation Proof**: Uses a VMV (Vector-Matrix-Vector) protocol with reduce-and-fold rounds

The protocol leverages the algebraic structure of bilinear pairings to achieve logarithmic proof sizes and verification times.

## Usage

```rust
use dory::{setup, prove, verify};
use dory::backends::arkworks::{BN254, TestG1Routines, TestG2Routines, ArkworksPolynomial};
use dory::backends::blake2b_transcript::Blake2bTranscript;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = rand::thread_rng();

    // 1. Generate setup for polynomials up to 2^10 coefficients
    let max_log_n = 10;
    let (prover_setup, verifier_setup) = setup::<BN254, _>(&mut rng, max_log_n);

    // 2. Create a polynomial with 256 coefficients (nu=4, sigma=4)
    let coefficients: Vec<_> = (0..256).map(|_| rand::random()).collect();
    let polynomial = ArkworksPolynomial::new(coefficients);

    // 3. Define evaluation point (length = nu + sigma = 8)
    let point: Vec<_> = (0..8).map(|_| rand::random()).collect();

    let nu = 4;     // log₂(rows) = 4 → 16 rows
    let sigma = 4;  // log₂(cols) = 4 → 16 columns

    // 4. Prove: commit to polynomial and create evaluation proof
    let mut prover_transcript = Blake2bTranscript::new(b"dory-example");
    let (commitment, evaluation, proof) = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _>(
        &polynomial,
        &point,
        None,  // DoryCommitment: Will compute if None
        nu,
        sigma,
        &prover_setup,
        &mut prover_transcript,
    )?;

    // 5. Verify: check that the proof is valid
    let mut verifier_transcript = Blake2bTranscript::new(b"dory-example");
    verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        commitment,
        evaluation,
        &point,
        &proof,
        nu,
        sigma,
        verifier_setup,
        &mut verifier_transcript,
    )?;

    println!("Proof verified successfully!");
    Ok(())
}
```

## Development Setup

After cloning the repository, install Git hooks to ensure code quality:

```bash
./scripts/install-hooks.sh
```

This installs a pre-commit hook that:
- Auto-formats code with `cargo fmt`
- Runs `cargo clippy` in strict mode

## Performance Considerations

This implementation is optimized for performance:

- **Vectorized Operations**: The `DoryRoutines` trait provides optimized methods for batch operations:
  - `fixed_base_vector_scalar_mul` - Vectorized scalar multiplication
  - `fixed_scalar_mul_bases_then_add` - Fused multiply-add with base vectors
  - `fixed_scalar_mul_vs_then_add` - Fused multiply-add for vector folding

- **Pluggable Polynomial Implementations**: The `Polynomial` and `MultilinearLagrange` traits are exposed, allowing users to provide custom polynomial representations optimized for their specific use cases (e.g., sparse polynomials)

- **Backend Flexibility**: The modular design allows backend implementations to leverage hardware acceleration and custom high performance arithmetic libraries

## Building and Testing

```bash
# Build with arkworks backend
cargo build --release --features backends

# Run tests
cargo nextest run --features backends

# Run clippy
cargo clippy --features backends -- -D warnings

# Generate documentation
cargo doc --features backends --open
```

## Features

- `backends` - Enable concrete backends. Currently supports Arkworks BN254.

## Project Structure

```
src/
├── lib.rs                          # Main API (setup, prove, verify)
├── primitives/
│   ├── arithmetic.rs              # Core arithmetic traits
│   ├── poly.rs                    # Polynomial traits and operations
│   ├── transcript.rs              # Fiat-Shamir transcript trait
│   └── serialization.rs           # Serialization abstractions
├── backends/
│   ├── mod.rs                     # Backend module exports
│   └── arkworks/                  # Arkworks BN254 backend
│       ├── mod.rs                 # Module exports
│       ├── ark_field.rs           # Field wrapper (ArkFr)
│       ├── ark_group.rs           # Group wrappers (ArkG1, ArkG2, ArkGT)
│       ├── ark_poly.rs            # Polynomial implementation
│       ├── ark_serde.rs           # Serialization bridge
│       └── blake2b_transcript.rs  # Blake2b transcript
├── setup.rs                       # Transparent setup generation
├── evaluation_proof.rs            # Proof creation and verification
├── reduce_and_fold.rs             # Inner product protocol
├── messages.rs                    # Protocol messages
├── proof.rs                       # Proof structure
└── error.rs                       # Error types

tests/arkworks/
├── mod.rs                         # Test utilities
├── setup.rs                       # Setup tests
├── commitment.rs                  # Commitment tests
├── evaluation.rs                  # Evaluation tests
├── integration.rs                 # End-to-end tests
└── soundness.rs                   # Soundness tests
```

## Test Coverage

The implementation includes comprehensive tests covering:
- Setup generation
- Polynomial commitment
- Evaluation proofs
- End-to-end workflows
- Soundness (tampering resistance for all proof components)

## Acknowledgments

This implementation was inspired by the proof of concept Dory PCS implementation by Space and Time Labs:
- Original repository: https://github.com/spaceandtimelabs/sxt-dory
- Research paper: Jonathan Lee, "Dory: Efficient, Transparent arguments for Generalised Inner Products and Polynomial Commitments" ([eprint 2020/1274](https://eprint.iacr.org/2020/1274))

## License

Dory is dual licensed under the following two licenses at your discretion: the MIT License (see [LICENSE-MIT](LICENSE-MIT)), and the Apache License (see [LICENSE-APACHE](LICENSE-APACHE)).

Dory is Copyright (c) a16z 2025. However, certain portions of the Dory codebase are modifications or ports of third party code, as indicated in the applicable code headers for such code or in the copyright attribution notices we have included in the directories for such code.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

### Disclaimer

_This code is being provided as is. No guarantee, representation or warranty is being made, express or implied, as to the safety or correctness of the code. It has not been audited and as such there can be no assurance it will work as intended, and users may experience delays, failures, errors, omissions or loss of transmitted information. Nothing in this repo should be construed as investment advice or legal advice for any particular facts or circumstances and is not meant to replace competent counsel. It is strongly advised for you to contact a reputable attorney in your jurisdiction for any questions or concerns with respect thereto. a16z is not liable for any use of the foregoing, and users should proceed with caution and use at their own risk. See a16z.com/disclosures for more info._
