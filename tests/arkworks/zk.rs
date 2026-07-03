//! Zero-knowledge mode tests for Dory PCS

use super::*;
use ark_bn254::{Fq12, Fr, G1Projective, G2Projective};
use ark_ec::pairing::PairingOutput;
use ark_ff::UniformRand;
use dory_pcs::backends::arkworks::{ArkFr, ArkG1, ArkG2, ArkGT};
use dory_pcs::primitives::poly::Polynomial;
use dory_pcs::{create_evaluation_proof, prove, setup, verify, ZK};

#[test]
fn test_zk_full_workflow() {
    let max_log_n = 10;

    let (prover_setup, verifier_setup) = setup::<BN254>(max_log_n);

    let poly = random_polynomial(256);
    let nu = 4;
    let sigma = 4;

    let (tier_2, tier_1, commit_blind) = poly
        .commit::<BN254, ZK, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let point = random_point(8);
    let expected_evaluation = poly.evaluate(&point);

    let mut prover_transcript = fresh_transcript();
    let (proof, _) = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, ZK>(
        &poly,
        &point,
        tier_1,
        commit_blind,
        nu,
        sigma,
        &prover_setup,
        &mut prover_transcript,
    )
    .unwrap();
    let evaluation = poly.evaluate(&point);
    assert_eq!(evaluation, expected_evaluation);

    let mut verifier_transcript = fresh_transcript();
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        tier_2,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(result.is_ok(), "ZK proof verification failed: {:?}", result);
}

#[test]
fn test_zk_small_polynomial() {
    let (prover_setup, verifier_setup) = test_setup_pair(4);

    let poly = random_polynomial(4);
    let nu = 1;
    let sigma = 1;

    let (tier_2, tier_1, commit_blind) = poly
        .commit::<BN254, ZK, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let point = random_point(2);
    let evaluation = poly.evaluate(&point);

    let mut prover_transcript = fresh_transcript();
    let (proof, _) = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, ZK>(
        &poly,
        &point,
        tier_1,
        commit_blind,
        nu,
        sigma,
        &prover_setup,
        &mut prover_transcript,
    )
    .unwrap();

    let mut verifier_transcript = fresh_transcript();
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        tier_2,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(
        result.is_ok(),
        "ZK small polynomial test failed: {:?}",
        result
    );
}

#[test]
fn test_zk_larger_polynomial() {
    let (prover_setup, verifier_setup) = setup::<BN254>(12);

    let poly = random_polynomial(1024);
    let nu = 5;
    let sigma = 5;

    let (tier_2, tier_1, commit_blind) = poly
        .commit::<BN254, ZK, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let point = random_point(10);
    let evaluation = poly.evaluate(&point);

    let mut prover_transcript = fresh_transcript();
    let (proof, _) = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, ZK>(
        &poly,
        &point,
        tier_1,
        commit_blind,
        nu,
        sigma,
        &prover_setup,
        &mut prover_transcript,
    )
    .unwrap();

    let mut verifier_transcript = fresh_transcript();
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        tier_2,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(
        result.is_ok(),
        "ZK larger polynomial test failed: {:?}",
        result
    );
}

#[test]
fn test_zk_non_square_matrix() {
    let (prover_setup, verifier_setup) = setup::<BN254>(10);

    // Non-square: nu=3, sigma=4 (8 rows, 16 columns = 128 coefficients)
    let poly = random_polynomial(128);
    let nu = 3;
    let sigma = 4;

    let (tier_2, tier_1, commit_blind) = poly
        .commit::<BN254, ZK, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let point = random_point(7); // nu + sigma = 7
    let evaluation = poly.evaluate(&point);

    let mut prover_transcript = fresh_transcript();
    let (proof, _) = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, ZK>(
        &poly,
        &point,
        tier_1,
        commit_blind,
        nu,
        sigma,
        &prover_setup,
        &mut prover_transcript,
    )
    .unwrap();

    let mut verifier_transcript = fresh_transcript();
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        tier_2,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(
        result.is_ok(),
        "ZK non-square matrix test failed: {:?}",
        result
    );
}

#[test]
fn test_zk_hidden_evaluation() {
    let (prover_setup, verifier_setup) = test_setup_pair(6);

    let poly = random_polynomial(16);
    let nu = 2;
    let sigma = 2;

    let (tier_2, tier_1, commit_blind) = poly
        .commit::<BN254, ZK, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let point = random_point(4);
    let evaluation = poly.evaluate(&point);

    // Create ZK proof using unified API with ZK mode
    let mut prover_transcript = fresh_transcript();
    let (proof, _) = create_evaluation_proof::<_, BN254, TestG1Routines, TestG2Routines, _, _, ZK>(
        &poly,
        &point,
        Some(tier_1),
        commit_blind,
        nu,
        sigma,
        &prover_setup,
        &mut prover_transcript,
    )
    .unwrap();

    assert!(proof.y_com.is_some(), "ZK proof should contain y_com");
    assert!(proof.e2.is_some(), "ZK proof should contain e2");

    let mut verifier_transcript = fresh_transcript();
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        tier_2,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(
        result.is_ok(),
        "ZK hidden evaluation proof verification failed: {:?}",
        result
    );
}

/// Test that tampered e2 in proof is rejected
#[test]
fn test_zk_tampered_e2_rejected() {
    use dory_pcs::primitives::arithmetic::Group;

    let (prover_setup, verifier_setup) = test_setup_pair(6);

    let poly = random_polynomial(16);
    let nu = 2;
    let sigma = 2;

    let (tier_2, tier_1, commit_blind) = poly
        .commit::<BN254, ZK, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let point = random_point(4);
    let evaluation = poly.evaluate(&point);

    let mut prover_transcript = fresh_transcript();
    let (mut proof, _) =
        create_evaluation_proof::<_, BN254, TestG1Routines, TestG2Routines, _, _, ZK>(
            &poly,
            &point,
            Some(tier_1),
            commit_blind,
            nu,
            sigma,
            &prover_setup,
            &mut prover_transcript,
        )
        .unwrap();

    if let Some(ref mut e2) = proof.e2 {
        *e2 = *e2 + prover_setup.h2.scale(&ArkFr::from_u64(42));
    }

    let mut verifier_transcript = fresh_transcript();
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        tier_2,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(result.is_err(), "Verification should fail with tampered e2");
}

/// Test full ZK with larger polynomial
#[test]
fn test_zk_hidden_evaluation_larger() {
    let (prover_setup, verifier_setup) = setup::<BN254>(10);

    let poly = random_polynomial(256);
    let nu = 4;
    let sigma = 4;

    let (tier_2, tier_1, commit_blind) = poly
        .commit::<BN254, ZK, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let point = random_point(8);
    let evaluation = poly.evaluate(&point);

    let mut prover_transcript = fresh_transcript();
    let (proof, _) = create_evaluation_proof::<_, BN254, TestG1Routines, TestG2Routines, _, _, ZK>(
        &poly,
        &point,
        Some(tier_1),
        commit_blind,
        nu,
        sigma,
        &prover_setup,
        &mut prover_transcript,
    )
    .unwrap();

    let mut verifier_transcript = fresh_transcript();
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        tier_2,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(
        result.is_ok(),
        "ZK hidden evaluation (larger) failed: {:?}",
        result
    );
}

// ---------------------------------------------------------------------------
// ZK Soundness Tests
// ---------------------------------------------------------------------------

#[allow(clippy::type_complexity)]
fn create_valid_zk_proof_components(
    size: usize,
    nu: usize,
    sigma: usize,
) -> (
    VerifierSetup<BN254>,
    Vec<ArkFr>,
    ArkGT,
    ArkFr,
    DoryProof<ArkG1, ArkG2, ArkGT>,
) {
    let (prover_setup, verifier_setup) = test_setup_pair(nu + sigma + 2);

    let poly = random_polynomial(size);
    let point = random_point(nu + sigma);

    let (tier_2, tier_1, commit_blind) = poly
        .commit::<BN254, ZK, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();
    let mut prover_transcript = fresh_transcript();
    let (proof, _) = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, ZK>(
        &poly,
        &point,
        tier_1,
        commit_blind,
        nu,
        sigma,
        &prover_setup,
        &mut prover_transcript,
    )
    .unwrap();
    let evaluation = poly.evaluate(&point);

    (verifier_setup, point, tier_2, evaluation, proof)
}

fn verify_tampered_zk_proof(
    commitment: ArkGT,
    evaluation: ArkFr,
    point: &[ArkFr],
    proof: &DoryProof<ArkG1, ArkG2, ArkGT>,
    verifier_setup: VerifierSetup<BN254>,
) -> Result<(), dory_pcs::DoryError> {
    let mut verifier_transcript = fresh_transcript();
    verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        commitment,
        evaluation,
        point,
        proof,
        verifier_setup,
        &mut verifier_transcript,
    )
}

#[test]
fn test_zk_soundness_missing_sigma1_proof() {
    let (verifier_setup, point, commitment, evaluation, mut proof) =
        create_valid_zk_proof_components(256, 4, 4);

    proof.sigma1_proof = None;

    let result = verify_tampered_zk_proof(commitment, evaluation, &point, &proof, verifier_setup);
    assert!(result.is_err(), "Should fail with missing sigma1_proof");
}

#[test]
fn test_zk_soundness_missing_sigma2_proof() {
    let (verifier_setup, point, commitment, evaluation, mut proof) =
        create_valid_zk_proof_components(256, 4, 4);

    proof.sigma2_proof = None;

    let result = verify_tampered_zk_proof(commitment, evaluation, &point, &proof, verifier_setup);
    assert!(result.is_err(), "Should fail with missing sigma2_proof");
}

#[test]
fn test_zk_soundness_missing_scalar_product_proof() {
    let (verifier_setup, point, commitment, evaluation, mut proof) =
        create_valid_zk_proof_components(256, 4, 4);

    proof.scalar_product_proof = None;

    let result = verify_tampered_zk_proof(commitment, evaluation, &point, &proof, verifier_setup);
    assert!(
        result.is_err(),
        "Should fail with missing scalar_product_proof"
    );
}

#[test]
fn test_zk_soundness_partial_zk_e2_only() {
    let (verifier_setup, point, commitment, evaluation, mut proof) =
        create_valid_zk_proof_components(256, 4, 4);

    proof.y_com = None;

    let result = verify_tampered_zk_proof(commitment, evaluation, &point, &proof, verifier_setup);
    assert!(
        result.is_err(),
        "Should fail with partial ZK fields (e2 only)"
    );
}

#[test]
fn test_zk_soundness_partial_zk_ycom_only() {
    let (verifier_setup, point, commitment, evaluation, mut proof) =
        create_valid_zk_proof_components(256, 4, 4);

    proof.e2 = None;

    let result = verify_tampered_zk_proof(commitment, evaluation, &point, &proof, verifier_setup);
    assert!(
        result.is_err(),
        "Should fail with partial ZK fields (y_com only)"
    );
}

#[test]
fn test_zk_soundness_tampered_sigma1_z1() {
    let (verifier_setup, point, commitment, evaluation, mut proof) =
        create_valid_zk_proof_components(256, 4, 4);

    if let Some(ref mut s) = proof.sigma1_proof {
        s.z1 = ArkFr(Fr::rand(&mut rand::thread_rng()));
    }

    let result = verify_tampered_zk_proof(commitment, evaluation, &point, &proof, verifier_setup);
    assert!(result.is_err(), "Should fail with tampered sigma1 z1");
}

#[test]
fn test_zk_soundness_tampered_sigma1_a1() {
    let (verifier_setup, point, commitment, evaluation, mut proof) =
        create_valid_zk_proof_components(256, 4, 4);

    if let Some(ref mut s) = proof.sigma1_proof {
        s.a1 = ArkG2(G2Projective::rand(&mut rand::thread_rng()));
    }

    let result = verify_tampered_zk_proof(commitment, evaluation, &point, &proof, verifier_setup);
    assert!(result.is_err(), "Should fail with tampered sigma1 a1");
}

#[test]
fn test_zk_soundness_tampered_sigma2_z1() {
    let (verifier_setup, point, commitment, evaluation, mut proof) =
        create_valid_zk_proof_components(256, 4, 4);

    if let Some(ref mut s) = proof.sigma2_proof {
        s.z1 = ArkFr(Fr::rand(&mut rand::thread_rng()));
    }

    let result = verify_tampered_zk_proof(commitment, evaluation, &point, &proof, verifier_setup);
    assert!(result.is_err(), "Should fail with tampered sigma2 z1");
}

#[test]
fn test_zk_soundness_tampered_sigma2_a() {
    let (verifier_setup, point, commitment, evaluation, mut proof) =
        create_valid_zk_proof_components(256, 4, 4);

    if let Some(ref mut s) = proof.sigma2_proof {
        s.a = ArkGT(PairingOutput(Fq12::rand(&mut rand::thread_rng())));
    }

    let result = verify_tampered_zk_proof(commitment, evaluation, &point, &proof, verifier_setup);
    assert!(result.is_err(), "Should fail with tampered sigma2 a");
}

/// z₂ scales HT at the d² slot of the batched final check (the direction the
/// Σ₂ check contributes alongside z₁'s Γ₂₀ direction); it must be bound.
#[test]
fn test_zk_soundness_tampered_sigma2_z2() {
    let (verifier_setup, point, commitment, evaluation, mut proof) =
        create_valid_zk_proof_components(256, 4, 4);

    if let Some(ref mut s) = proof.sigma2_proof {
        s.z2 = ArkFr(Fr::rand(&mut rand::thread_rng()));
    }

    let result = verify_tampered_zk_proof(commitment, evaluation, &point, &proof, verifier_setup);
    assert!(result.is_err(), "Should fail with tampered sigma2 z2");
}

#[test]
fn test_zk_soundness_tampered_sp_e1() {
    let (verifier_setup, point, commitment, evaluation, mut proof) =
        create_valid_zk_proof_components(256, 4, 4);

    if let Some(ref mut sp) = proof.scalar_product_proof {
        sp.e1 = ArkG1(G1Projective::rand(&mut rand::thread_rng()));
    }

    let result = verify_tampered_zk_proof(commitment, evaluation, &point, &proof, verifier_setup);
    assert!(
        result.is_err(),
        "Should fail with tampered scalar product e1"
    );
}

#[test]
fn test_zk_soundness_tampered_sp_p1() {
    let (verifier_setup, point, commitment, evaluation, mut proof) =
        create_valid_zk_proof_components(256, 4, 4);

    if let Some(ref mut sp) = proof.scalar_product_proof {
        sp.p1 = ArkGT(PairingOutput(Fq12::rand(&mut rand::thread_rng())));
    }

    let result = verify_tampered_zk_proof(commitment, evaluation, &point, &proof, verifier_setup);
    assert!(
        result.is_err(),
        "Should fail with tampered scalar product p1"
    );
}

#[test]
fn test_zk_soundness_tampered_sp_r3() {
    let (verifier_setup, point, commitment, evaluation, mut proof) =
        create_valid_zk_proof_components(256, 4, 4);

    if let Some(ref mut sp) = proof.scalar_product_proof {
        sp.r3 = ArkFr(Fr::rand(&mut rand::thread_rng()));
    }

    let result = verify_tampered_zk_proof(commitment, evaluation, &point, &proof, verifier_setup);
    assert!(
        result.is_err(),
        "Should fail with tampered scalar product r3"
    );
}

/// Complete per-component coverage of the batched final equation: every
/// remaining scalar-product proof field, one at a time. e2 enters Pair 1's G2
/// slot; p2/q/r enter the RHS commitment terms; r1/r2 enter the merged
/// HT scalar (r₃ + d·r₂ + d⁻¹·r₁) alongside r3 above.
#[test]
fn test_zk_soundness_tampered_sp_e2() {
    let (verifier_setup, point, commitment, evaluation, mut proof) =
        create_valid_zk_proof_components(256, 4, 4);

    if let Some(ref mut sp) = proof.scalar_product_proof {
        sp.e2 = ArkG2(G2Projective::rand(&mut rand::thread_rng()));
    }

    let result = verify_tampered_zk_proof(commitment, evaluation, &point, &proof, verifier_setup);
    assert!(
        result.is_err(),
        "Should fail with tampered scalar product e2"
    );
}

#[test]
fn test_zk_soundness_tampered_sp_p2() {
    let (verifier_setup, point, commitment, evaluation, mut proof) =
        create_valid_zk_proof_components(256, 4, 4);

    if let Some(ref mut sp) = proof.scalar_product_proof {
        sp.p2 = ArkGT(PairingOutput(Fq12::rand(&mut rand::thread_rng())));
    }

    let result = verify_tampered_zk_proof(commitment, evaluation, &point, &proof, verifier_setup);
    assert!(
        result.is_err(),
        "Should fail with tampered scalar product p2"
    );
}

#[test]
fn test_zk_soundness_tampered_sp_q() {
    let (verifier_setup, point, commitment, evaluation, mut proof) =
        create_valid_zk_proof_components(256, 4, 4);

    if let Some(ref mut sp) = proof.scalar_product_proof {
        sp.q = ArkGT(PairingOutput(Fq12::rand(&mut rand::thread_rng())));
    }

    let result = verify_tampered_zk_proof(commitment, evaluation, &point, &proof, verifier_setup);
    assert!(
        result.is_err(),
        "Should fail with tampered scalar product q"
    );
}

#[test]
fn test_zk_soundness_tampered_sp_r() {
    let (verifier_setup, point, commitment, evaluation, mut proof) =
        create_valid_zk_proof_components(256, 4, 4);

    if let Some(ref mut sp) = proof.scalar_product_proof {
        sp.r = ArkGT(PairingOutput(Fq12::rand(&mut rand::thread_rng())));
    }

    let result = verify_tampered_zk_proof(commitment, evaluation, &point, &proof, verifier_setup);
    assert!(
        result.is_err(),
        "Should fail with tampered scalar product r"
    );
}

#[test]
fn test_zk_soundness_tampered_sp_r1() {
    let (verifier_setup, point, commitment, evaluation, mut proof) =
        create_valid_zk_proof_components(256, 4, 4);

    if let Some(ref mut sp) = proof.scalar_product_proof {
        sp.r1 = ArkFr(Fr::rand(&mut rand::thread_rng()));
    }

    let result = verify_tampered_zk_proof(commitment, evaluation, &point, &proof, verifier_setup);
    assert!(
        result.is_err(),
        "Should fail with tampered scalar product r1"
    );
}

#[test]
fn test_zk_soundness_tampered_sp_r2() {
    let (verifier_setup, point, commitment, evaluation, mut proof) =
        create_valid_zk_proof_components(256, 4, 4);

    if let Some(ref mut sp) = proof.scalar_product_proof {
        sp.r2 = ArkFr(Fr::rand(&mut rand::thread_rng()));
    }

    let result = verify_tampered_zk_proof(commitment, evaluation, &point, &proof, verifier_setup);
    assert!(
        result.is_err(),
        "Should fail with tampered scalar product r2"
    );
}

#[test]
fn test_zk_soundness_tampered_vmv_c() {
    let (verifier_setup, point, commitment, evaluation, mut proof) =
        create_valid_zk_proof_components(256, 4, 4);

    proof.vmv_message.c = ArkGT(PairingOutput(Fq12::rand(&mut rand::thread_rng())));

    let result = verify_tampered_zk_proof(commitment, evaluation, &point, &proof, verifier_setup);
    assert!(result.is_err(), "Should fail with tampered VMV c in ZK");
}

#[test]
fn test_zk_soundness_tampered_vmv_d2() {
    let (verifier_setup, point, commitment, evaluation, mut proof) =
        create_valid_zk_proof_components(256, 4, 4);

    proof.vmv_message.d2 = ArkGT(PairingOutput(Fq12::rand(&mut rand::thread_rng())));

    let result = verify_tampered_zk_proof(commitment, evaluation, &point, &proof, verifier_setup);
    assert!(result.is_err(), "Should fail with tampered VMV d2 in ZK");
}

#[test]
fn test_zk_soundness_tampered_vmv_e1() {
    let (verifier_setup, point, commitment, evaluation, mut proof) =
        create_valid_zk_proof_components(256, 4, 4);

    proof.vmv_message.e1 = ArkG1(G1Projective::rand(&mut rand::thread_rng()));

    let result = verify_tampered_zk_proof(commitment, evaluation, &point, &proof, verifier_setup);
    assert!(result.is_err(), "Should fail with tampered VMV e1 in ZK");
}

#[test]
fn test_zk_soundness_tampered_e2() {
    let (verifier_setup, point, commitment, evaluation, mut proof) =
        create_valid_zk_proof_components(256, 4, 4);

    proof.e2 = Some(ArkG2(G2Projective::rand(&mut rand::thread_rng())));

    let result = verify_tampered_zk_proof(commitment, evaluation, &point, &proof, verifier_setup);
    assert!(result.is_err(), "Should fail with tampered e2 in ZK");
}

#[test]
fn test_zk_soundness_tampered_y_com() {
    let (verifier_setup, point, commitment, evaluation, mut proof) =
        create_valid_zk_proof_components(256, 4, 4);

    proof.y_com = Some(ArkG1(G1Projective::rand(&mut rand::thread_rng())));

    let result = verify_tampered_zk_proof(commitment, evaluation, &point, &proof, verifier_setup);
    assert!(result.is_err(), "Should fail with tampered y_com in ZK");
}

// ---------------------------------------------------------------------------
// Opening-point binding regression tests
//
// Regression tests for the ZK soundness fix: the evaluation point reaches the
// verifier only through the folded scalars s1_acc/s2_acc, and the ZK final
// check must bind them (via the Fold-Scalars-updated statement, Dory paper
// §4.1 + §3.1). Before the fix the ZK final check never read them, so a proof
// created for one point verified at every point.
// ---------------------------------------------------------------------------

/// Primary regression: an honest ZK proof created for `point` must NOT verify
/// at any other point.
#[test]
fn test_zk_wrong_point_rejected() {
    for (nu, sigma) in [(1usize, 1usize), (2, 2), (2, 3)] {
        let size = 1 << (nu + sigma);
        let (verifier_setup, point, commitment, evaluation, proof) =
            create_valid_zk_proof_components(size, nu, sigma);

        // Sanity: the honest point verifies.
        assert!(
            verify_tampered_zk_proof(
                commitment,
                evaluation,
                &point,
                &proof,
                verifier_setup.clone()
            )
            .is_ok(),
            "honest ZK proof must verify at its own point (nu={nu}, sigma={sigma})"
        );

        // A proof for `point` must not verify at a shifted point.
        let mut wrong_point = point.clone();
        wrong_point[0] = wrong_point[0] + ArkFr::one();
        assert!(
            verify_tampered_zk_proof(
                commitment,
                evaluation,
                &wrong_point,
                &proof,
                verifier_setup.clone()
            )
            .is_err(),
            "ZK proof accepted at a shifted point (nu={nu}, sigma={sigma})"
        );

        // Nor at an unrelated random point.
        let random_pt = random_point(nu + sigma);
        assert!(
            verify_tampered_zk_proof(commitment, evaluation, &random_pt, &proof, verifier_setup)
                .is_err(),
            "ZK proof accepted at a random point (nu={nu}, sigma={sigma})"
        );
    }
}

/// Replay the verifier's Fiat-Shamir transcript over an honest ZK proof and
/// return the per-round `alpha` challenges together with `gamma`, the
/// scalar-product challenge `sigma_c`, and the batching challenge `d`.
/// Mirrors the append/challenge sequence of `verify_evaluation_proof` (which
/// the honest `fresh_transcript` domain makes reproducible).
fn replay_zk_transcript(
    proof: &DoryProof<ArkG1, ArkG2, ArkGT>,
) -> (Vec<ArkFr>, ArkFr, ArkFr, ArkFr) {
    use dory_pcs::primitives::transcript::Transcript;

    let mut t = fresh_transcript();
    t.append_serde(b"vmv_c", &proof.vmv_message.c);
    t.append_serde(b"vmv_d2", &proof.vmv_message.d2);
    t.append_serde(b"vmv_e1", &proof.vmv_message.e1);

    t.append_serde(b"vmv_e2", proof.e2.as_ref().unwrap());
    t.append_serde(b"vmv_y_com", proof.y_com.as_ref().unwrap());

    let s1p = proof.sigma1_proof.as_ref().unwrap();
    t.append_serde(b"sigma1_a1", &s1p.a1);
    t.append_serde(b"sigma1_a2", &s1p.a2);
    let _ = t.challenge_scalar(b"sigma1_c");

    let s2p = proof.sigma2_proof.as_ref().unwrap();
    t.append_serde(b"sigma2_a", &s2p.a);
    let _ = t.challenge_scalar(b"sigma2_c");
    t.append_serde(b"sigma2_z1", &s2p.z1);
    t.append_serde(b"sigma2_z2", &s2p.z2);

    let mut alphas = Vec::new();
    for (first, second) in proof.first_messages.iter().zip(&proof.second_messages) {
        t.append_serde(b"d1_left", &first.d1_left);
        t.append_serde(b"d1_right", &first.d1_right);
        t.append_serde(b"d2_left", &first.d2_left);
        t.append_serde(b"d2_right", &first.d2_right);
        t.append_serde(b"e1_beta", &first.e1_beta);
        t.append_serde(b"e2_beta", &first.e2_beta);
        let _beta = t.challenge_scalar(b"beta");

        t.append_serde(b"c_plus", &second.c_plus);
        t.append_serde(b"c_minus", &second.c_minus);
        t.append_serde(b"e1_plus", &second.e1_plus);
        t.append_serde(b"e1_minus", &second.e1_minus);
        t.append_serde(b"e2_plus", &second.e2_plus);
        t.append_serde(b"e2_minus", &second.e2_minus);
        alphas.push(t.challenge_scalar(b"alpha"));
    }

    let gamma = t.challenge_scalar(b"gamma");

    let sp = proof.scalar_product_proof.as_ref().unwrap();
    t.append_serde(b"sigma_p1", &sp.p1);
    t.append_serde(b"sigma_p2", &sp.p2);
    t.append_serde(b"sigma_q", &sp.q);
    t.append_serde(b"sigma_r", &sp.r);
    let sigma_c = t.challenge_scalar(b"sigma_c");
    t.append_serde(b"sigma_e1", &sp.e1);
    t.append_serde(b"sigma_e2", &sp.e2);
    t.append_serde(b"sigma_r1", &sp.r1);
    t.append_serde(b"sigma_r2", &sp.r2);
    t.append_serde(b"sigma_r3", &sp.r3);
    let d = t.challenge_scalar(b"d");

    (alphas, gamma, sigma_c, d)
}

/// Fold the evaluation-point tensors with the round challenges, mirroring the
/// `s1_acc`/`s2_acc` accumulation in `DoryVerifierState::process_round`
/// (coordinates consumed MSB-first).
fn fold_point_scalars(
    point: &[ArkFr],
    nu: usize,
    sigma: usize,
    alphas: &[ArkFr],
) -> (ArkFr, ArkFr) {
    let one = ArkFr::one();
    let s1_coords = &point[..sigma];
    let mut s2_coords = vec![ArkFr::zero(); sigma];
    s2_coords[..nu].copy_from_slice(&point[sigma..sigma + nu]);

    let mut s1_acc = one;
    let mut s2_acc = one;
    for (round, alpha) in alphas.iter().enumerate() {
        let idx = sigma - 1 - round;
        let alpha_inv = alpha.inv().unwrap();
        let (y_t, x_t) = (s1_coords[idx], s2_coords[idx]);
        s1_acc = s1_acc * (*alpha * (one - y_t) + y_t);
        s2_acc = s2_acc * (alpha_inv * (one - x_t) + x_t);
    }
    (s1_acc, s2_acc)
}

/// Advisory-§5-style crafted attack: a correct fix must *constrain* the
/// blinding of the final scalar-product responses, not merely prove knowledge
/// of free coefficients. Starting from an honest proof for `point`, shift the
/// Σ-proof responses along the blinding directions by exactly the public
/// wrong-point deltas:
///
/// ```text
/// E₁σ += δ₁·H₁,  δ₁ = c·γ·(s1_acc(P') − s1_acc(P))
/// E₂σ += δ₂·H₂,  δ₂ = c·γ⁻¹·(s2_acc(P') − s2_acc(P))
/// r₃  += c²·(s1s2_acc(P') − s1s2_acc(P)) − δ₁·δ₂
/// ```
///
/// These shifts cancel the point-dependent `e(H₁,Γ₂₀)`, `e(Γ₁₀,H₂)` and `HT`
/// components of the verification difference — the exact degrees of freedom a
/// naive "prove the residual lies in the blinding span" fix would leave free.
/// The fixed check entangles the responses with the hidden folded witness:
/// the shift additionally perturbs Pair 1 by `δ₁·e(H₁, E₂σ) + δ₂·e(E₁σ, H₂)`,
/// which no proof element absorbed after the challenge `c` can cancel. The
/// crafted proof must therefore be rejected.
#[test]
fn test_zk_crafted_blind_shift_wrong_point_rejected() {
    use dory_pcs::primitives::arithmetic::Group;

    let (verifier_setup, point, commitment, evaluation, proof) =
        create_valid_zk_proof_components(16, 2, 2);

    // Honest baseline verifies.
    assert!(verify_tampered_zk_proof(
        commitment,
        evaluation,
        &point,
        &proof,
        verifier_setup.clone()
    )
    .is_ok());

    // Shift both a column coordinate (feeds s1_acc) and a row coordinate
    // (feeds s2_acc) so both cancellation directions (B3 and B4) are exercised.
    let (nu, sigma) = (proof.nu, proof.sigma);
    let mut wrong_point = point.clone();
    wrong_point[0] = wrong_point[0] + ArkFr::one();
    wrong_point[sigma] = wrong_point[sigma] + ArkFr::one();

    // Recover the Fiat-Shamir challenges the verifier will derive (the
    // shifted responses are only absorbed after sigma_c, so the challenges
    // used below are unchanged by the crafting).
    let (alphas, gamma, sigma_c, _d) = replay_zk_transcript(&proof);
    let (s1_h, s2_h) = fold_point_scalars(&point, nu, sigma, &alphas);
    let (s1_w, s2_w) = fold_point_scalars(&wrong_point, nu, sigma, &alphas);

    let gamma_inv = gamma.inv().unwrap();
    let delta1 = sigma_c * gamma * (s1_w - s1_h);
    let delta2 = sigma_c * gamma_inv * (s2_w - s2_h);
    let rho3 = sigma_c * sigma_c * (s1_w * s2_w - s1_h * s2_h) - delta1 * delta2;
    assert!(
        !delta1.is_zero() && !delta2.is_zero(),
        "attack deltas must be non-trivial"
    );

    let mut crafted = proof.clone();
    let sp = crafted.scalar_product_proof.as_mut().unwrap();
    sp.e1 = sp.e1 + verifier_setup.h1.scale(&delta1);
    sp.e2 = sp.e2 + verifier_setup.h2.scale(&delta2);
    sp.r3 = sp.r3 + rho3;

    // The crafted proof must be rejected at the wrong point...
    assert!(
        verify_tampered_zk_proof(
            commitment,
            evaluation,
            &wrong_point,
            &crafted,
            verifier_setup.clone()
        )
        .is_err(),
        "crafted blind-shift proof accepted at the wrong point"
    );

    // ...and, being tampered, at the honest point as well.
    assert!(
        verify_tampered_zk_proof(commitment, evaluation, &point, &crafted, verifier_setup).is_err(),
        "crafted blind-shift proof accepted at the honest point"
    );
}

/// Batching-soundness regression for the Σ₂-into-final-check batching: the Σ₂
/// responses `(z₁, z₂)` must be absorbed into the transcript before the
/// batching challenge `d` is drawn.
///
/// If they were not, they would be free variables of the batched final
/// equation, choosable *after* `d` is known. They scale exactly `e(H₁, Γ₂₀)`
/// (via `z₁`) and `HT` (via `z₂`) at the `d²` slot — precisely the two
/// directions in which the final check shifts when an honest proof for `P` is
/// verified at a wrong point `P'` that changes `s1_acc` but not `s2_acc`:
///
/// ```text
/// z₁ += c·γ·d⁻¹·Δs₁ / d²      cancels the Pair 2 e(H₁, Γ₂₀) residual
/// z₂ += c²·Δs₁·s₂ / d²        cancels the RHS (s₁·s₂)·HT residual
/// ```
///
/// Because `d` binds `(z₁, z₂)`, an attacker must compute these shifts against
/// a stale `d`; the verifier re-derives a different `d` from the shifted
/// responses and the crafted proof must be rejected.
#[test]
fn test_zk_crafted_sigma2_response_shift_wrong_point_rejected() {
    let (verifier_setup, point, commitment, evaluation, proof) =
        create_valid_zk_proof_components(16, 2, 2);

    // Honest baseline verifies.
    assert!(verify_tampered_zk_proof(
        commitment,
        evaluation,
        &point,
        &proof,
        verifier_setup.clone()
    )
    .is_ok());

    // Shift only a column coordinate: s1_acc changes, s2_acc does not, so the
    // wrong-point residual lies entirely in span{e(H₁, Γ₂₀), HT} — the exact
    // span the Σ₂ responses control.
    let (nu, sigma) = (proof.nu, proof.sigma);
    let mut wrong_point = point.clone();
    wrong_point[0] = wrong_point[0] + ArkFr::one();

    let (alphas, gamma, sigma_c, d) = replay_zk_transcript(&proof);
    let (s1_h, s2_h) = fold_point_scalars(&point, nu, sigma, &alphas);
    let (s1_w, s2_w) = fold_point_scalars(&wrong_point, nu, sigma, &alphas);
    assert_eq!(s2_h, s2_w, "row folding must be unaffected");
    let delta_s1 = s1_w - s1_h;
    assert!(!delta_s1.is_zero(), "attack delta must be non-trivial");

    let d_inv = d.inv().unwrap();
    let d_sq_inv = (d * d).inv().unwrap();
    let dz1 = sigma_c * gamma * d_inv * delta_s1 * d_sq_inv;
    let dz2 = sigma_c * sigma_c * delta_s1 * s2_h * d_sq_inv;

    let mut crafted = proof.clone();
    let s2p = crafted.sigma2_proof.as_mut().unwrap();
    s2p.z1 = s2p.z1 + dz1;
    s2p.z2 = s2p.z2 + dz2;

    // The crafted proof must be rejected at the wrong point...
    assert!(
        verify_tampered_zk_proof(
            commitment,
            evaluation,
            &wrong_point,
            &crafted,
            verifier_setup.clone()
        )
        .is_err(),
        "crafted Σ₂-response-shift proof accepted at the wrong point"
    );

    // ...and, being tampered, at the honest point as well.
    assert!(
        verify_tampered_zk_proof(commitment, evaluation, &point, &crafted, verifier_setup).is_err(),
        "crafted Σ₂-response-shift proof accepted at the honest point"
    );
}

/// ZK proofs must not carry a clear final message: a proof that includes one
/// is malformed and must be rejected outright.
#[test]
fn test_zk_soundness_unexpected_final_message() {
    use dory_pcs::ScalarProductMessage;

    let (verifier_setup, point, commitment, evaluation, mut proof) =
        create_valid_zk_proof_components(16, 2, 2);

    assert!(
        proof.final_message.is_none(),
        "ZK proofs must not contain a clear final message"
    );
    proof.final_message = Some(ScalarProductMessage {
        e1: ArkG1(G1Projective::rand(&mut rand::thread_rng())),
        e2: ArkG2(G2Projective::rand(&mut rand::thread_rng())),
    });

    let result = verify_tampered_zk_proof(commitment, evaluation, &point, &proof, verifier_setup);
    assert!(
        result.is_err(),
        "Should fail when a ZK proof carries a clear final message"
    );
}
