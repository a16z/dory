//! Proof serialization tests
//!
//! With spongefish, proofs are just `Vec<u8>` NARG strings — no struct
//! serialization needed. These tests verify proof byte properties and
//! round-tripping through prove/verify.

use super::*;
use dory_pcs::primitives::poly::Polynomial;
use dory_pcs::{prove, verify, Transparent};

/// Prove with transparent mode and return the raw proof bytes.
fn make_transparent_proof_bytes(nu: usize, sigma: usize) -> Vec<u8> {
    let setup = test_setup(nu + sigma + 2);
    let poly_size = 1 << (nu + sigma);
    let poly = random_polynomial(poly_size);
    let point = random_point(nu + sigma);
    let (_, tier_1, commit_blind) = poly
        .commit::<BN254, Transparent, TestG1Routines>(nu, sigma, &setup)
        .unwrap();

    let mut prover = test_prover(sigma);
    prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, Transparent>(
        &poly,
        &point,
        tier_1,
        commit_blind,
        nu,
        sigma,
        &setup,
        &mut prover,
    )
    .unwrap();

    prover.check_complete().narg_string().to_vec()
}

#[test]
fn test_proof_bytes_consistent_length() {
    let nu = 2;
    let sigma = 2;

    let lengths: Vec<usize> = (0..3)
        .map(|_| make_transparent_proof_bytes(nu, sigma).len())
        .collect();

    assert!(
        lengths.windows(2).all(|w| w[0] == w[1]),
        "proof byte lengths should be consistent for same parameters, got {lengths:?}"
    );
}

#[test]
fn test_proof_size_matches_expected() {
    let sigma = 2;
    let proof_bytes_a = make_transparent_proof_bytes(2, sigma);
    let proof_bytes_b = make_transparent_proof_bytes(2, sigma);
    assert_eq!(
        proof_bytes_a.len(),
        proof_bytes_b.len(),
        "proof sizes should match for same parameters",
    );
}

#[test]
fn test_proof_size_increases_with_sigma() {
    let small = make_transparent_proof_bytes(2, 2);
    let large = make_transparent_proof_bytes(4, 4);
    assert!(
        large.len() > small.len(),
        "proof with sigma=4 ({}) should be larger than sigma=2 ({})",
        large.len(),
        small.len(),
    );
}

#[test]
fn test_proof_bytes_roundtrip_through_verify() {
    let nu = 2;
    let sigma = 2;
    let (setup, verifier_setup) = test_setup_pair(nu + sigma + 2);

    let poly = random_polynomial(16);
    let point = random_point(4);
    let (tier_2, tier_1, commit_blind) = poly
        .commit::<BN254, Transparent, TestG1Routines>(nu, sigma, &setup)
        .unwrap();

    let mut prover = test_prover(sigma);
    prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, Transparent>(
        &poly,
        &point,
        tier_1,
        commit_blind,
        nu,
        sigma,
        &setup,
        &mut prover,
    )
    .unwrap();
    let proof_bytes = prover.check_complete().narg_string().to_vec();

    let eval = poly.evaluate(&point);
    let mut verifier = test_verifier(sigma, &proof_bytes);
    verify::<_, BN254, TestG1Routines, TestG2Routines, _, Transparent>(
        tier_2,
        eval,
        &point,
        nu,
        sigma,
        verifier_setup,
        &mut verifier,
    )
    .unwrap();
    verifier.check_eof().unwrap();
}

#[test]
fn test_proof_bytes_nonzero() {
    let proof_bytes = make_transparent_proof_bytes(2, 2);

    assert!(!proof_bytes.is_empty(), "proof bytes should not be empty");
    assert!(
        proof_bytes.iter().any(|&b| b != 0),
        "proof bytes should not be all zeros"
    );
}

#[cfg(feature = "zk")]
mod zk_narg {
    use super::*;
    use dory_pcs::{prove, verify, ZK};

    fn make_zk_proof_bytes(nu: usize, sigma: usize) -> Vec<u8> {
        let setup = test_setup(nu + sigma + 2);
        let poly_size = 1 << (nu + sigma);
        let poly = random_polynomial(poly_size);
        let point = random_point(nu + sigma);
        let (_, tier_1, commit_blind) = poly
            .commit::<BN254, ZK, TestG1Routines>(nu, sigma, &setup)
            .unwrap();

        let mut prover = test_prover_zk(sigma);
        prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, ZK>(
            &poly,
            &point,
            tier_1,
            commit_blind,
            nu,
            sigma,
            &setup,
            &mut prover,
        )
        .unwrap();

        prover.check_complete().narg_string().to_vec()
    }

    #[test]
    fn test_zk_proof_size_matches_expected() {
        let sigma = 2;
        let proof_bytes_a = make_zk_proof_bytes(2, sigma);
        let proof_bytes_b = make_zk_proof_bytes(2, sigma);
        assert_eq!(
            proof_bytes_a.len(),
            proof_bytes_b.len(),
            "ZK proof sizes should match for same parameters",
        );
    }

    #[test]
    fn test_zk_proof_bytes_roundtrip_through_verify() {
        let nu = 2;
        let sigma = 2;
        let (setup, verifier_setup) = test_setup_pair(nu + sigma + 2);

        let poly = random_polynomial(16);
        let point = random_point(4);
        let (tier_2, tier_1, commit_blind) = poly
            .commit::<BN254, ZK, TestG1Routines>(nu, sigma, &setup)
            .unwrap();

        let mut prover = test_prover_zk(sigma);
        prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, ZK>(
            &poly,
            &point,
            tier_1,
            commit_blind,
            nu,
            sigma,
            &setup,
            &mut prover,
        )
        .unwrap();
        let proof_bytes = prover.check_complete().narg_string().to_vec();

        let eval = poly.evaluate(&point);
        let mut verifier = test_verifier_zk(sigma, &proof_bytes);
        verify::<_, BN254, TestG1Routines, TestG2Routines, _, ZK>(
            tier_2,
            eval,
            &point,
            nu,
            sigma,
            verifier_setup,
            &mut verifier,
        )
        .unwrap();
        verifier.check_eof().unwrap();
    }

    #[test]
    fn test_zk_proof_larger_than_transparent() {
        let zk = make_zk_proof_bytes(4, 4);
        let transparent = make_transparent_proof_bytes(4, 4);
        assert!(
            zk.len() > transparent.len(),
            "ZK proof ({}) should be larger than transparent ({})",
            zk.len(),
            transparent.len(),
        );
    }
}
