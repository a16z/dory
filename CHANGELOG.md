# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **Fixed a critical soundness bug in ZK mode: the evaluation opening point was
  not bound by the verifier.** A ZK evaluation proof created for a point `P`
  verified at *any* point `P'`, letting a malicious prover open a committed
  polynomial to a forged evaluation at an attacker-chosen point. Transparent
  mode was unaffected.

  Root cause: the 0.3.0 ZK final check was a collapsed 1-pairing scalar-product
  argument over the *pre-fold* statement `(C, D₁, D₂)`. The opening point
  reaches the verifier only through the folded scalars `s1_acc`/`s2_acc`, and
  that check never read them — it dropped the point-binding terms (transparent
  Pairs 2 & 3 and the `s1_acc·s2_acc·HT` term) with no zero-knowledge
  replacement.

  Fix: ZK mode now follows the original Dory construction (eprint 2020/1274,
  §4.1 Fold-Scalars then §3.1 Scalar-Product). The prover applies the
  Fold-Scalars reduction to its witness (`v₁ ← v₁ + γ·s₁·H₁`,
  `v₂ ← v₂ + γ⁻¹·s₂·H₂`, `r_C ← r_C + γ·r_E2 + γ⁻¹·r_E1`) *before* running the
  scalar-product Σ-argument, so the argument now opens the point-dependent
  *folded* statement `(C′, D₁′, D₂′)`. The verifier reconstructs `(C′, D₁′, D₂′)`
  from its own point-derived `s1_acc`/`s2_acc` and the E-accumulators, batched
  into a 3-pairing check. This pins the point coefficient to the committed
  witness while the folded coordinates `v₁[0]`/`v₂[0]` stay hidden.

### Changed

- **Breaking (proof format & API):** `DoryProof::final_message` is now
  `Option<ScalarProductMessage>`. Transparent proofs carry `Some(..)` (the
  revealed folded witness); ZK proofs carry `None` (revealing it would break
  hiding — the scalar-product Σ-proof replaces it). ZK proofs from 0.3.0 no
  longer verify and must be regenerated.
- ZK final verification is now a 3-pairing check (was a collapsed 1-pairing
  check). The scalar-product Σ-proof responses `(E₁, E₂, r₁, r₂, r₃)` are now
  absorbed into the Fiat-Shamir transcript before the batching challenge `d` is
  drawn, matching the interactive protocol.
- The fresh final-message blinds `r_final1`/`r_final2` (sampled in
  `compute_final_message`) are removed; they were an unconstrained degree of
  freedom that any point-agnostic fix would have left exploitable.

### Added

- `DoryProverState::apply_fold_scalars` implementing the §4.1 Fold-Scalars
  witness update (used by both transparent and ZK modes).
- `zk_wrong_point` example and `test_zk_wrong_point_rejected` regression test:
  a ZK proof for one point must not verify at another.
- `test_zk_crafted_blind_shift_wrong_point_rejected`: an adversarial wrong-point
  proof that shifts the Σ-proof blinds by the exact public point deltas (the
  attack a naive "prove the residual is in the blinding span" fix would accept)
  is rejected.
- `test_soundness_missing_final_message` /
  `test_zk_soundness_unexpected_final_message`: the clear final message must be
  present iff the proof is transparent.

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
