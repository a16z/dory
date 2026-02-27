# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-02-27

### Added

- **Zero-knowledge mode** (`zk` feature): optional hiding proofs where both commitment and proof are blinded
  - Single GT-level commitment blind (`r_d1 * HT`)
  - VMV messages (C, D2, E1, E2, y_com) blinded with OS randomness
  - Reduce-and-fold messages blinded with OS per-round randomness
  - Final message (E1, E2) blinded to hide folded witness vectors
  - Sigma1 proof: proves E2 and y_com commit to the same evaluation
  - Sigma2 proof: proves consistency of E1 and D2 blinds
  - Scalar product proof: proves (C, D1, D2) are consistent with blinded v1, v2
  - 1 ML + 1 FE verification in ZK mode (vs 4 ML + 1 FE in transparent mode)
- New `zk_e2e` example demonstrating the full ZK workflow
- New `zk_statistical` example with chi-squared uniformity and witness-independence tests (1000 trials)
- ZK test suite: end-to-end proofs, tampering resistance, sigma proof verification, soundness

### Changed

- `Polynomial::commit()` return type changed from `(GT, Vec<G1>, Option<Vec<F>>)` to `(GT, Vec<G1>, F)` — the third element is now a single GT-level blind scalar (zero in Transparent mode)
- `prove()` and `create_evaluation_proof()` now take a `commit_blind: F` parameter
- `DoryProverState::set_initial_blinds()` now takes `r_d1` as its first parameter

## [0.2.0] - 2026-01-29

### Changed
- Optimized verifier pairing check from 5 individual pairings to a size-3 multi-pairing
- Eliminated the separate VMV pairing check by batching it with the final verification
- Cache now intelligently resizes itself when setup size changes

### Fixed

- Append E final terms to the transcript in the reduce-and-fold protocol
- Use d² instead of d for batching the VMV term
- Removed `dirs` crate dependency; cache directory is now determined at runtime

### Added

- New `homomorphic_mixed_sizes` example demonstrating combination of polynomials with different matrix dimensions

## [0.1.0] - 2025-11-15

### Added

- Initial release
- Arkworks BN254 backend
- Prepared point caching for ~20-30% pairing speedup
- Support for square and non-square matrix layouts (nu ≤ sigma)
- Homomorphic commitment properties
- Comprehensive test suite including soundness tests

[0.3.0]: https://github.com/a16z/dory/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/a16z/dory/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/a16z/dory/releases/tag/v0.1.0
