# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.2.0]: https://github.com/a16z/dory/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/a16z/dory/releases/tag/v0.1.0
