//! Zero-knowledge mode tests for Dory PCS

use super::*;
use ark_bn254::{Fq12, Fr, G1Projective, G2Projective};
use ark_ff::UniformRand;
use dory_pcs::backends::arkworks::{ArkFr, ArkG1, ArkG2, ArkGT};
use dory_pcs::primitives::poly::Polynomial;
use dory_pcs::{create_evaluation_proof, prove, setup, verify, Transparent, ZK};

#[test]
fn test_zk_full_workflow() {
    let max_log_n = 10;

    let (prover_setup, verifier_setup) = setup::<BN254>(max_log_n);

    let poly = random_polynomial(256);
    let nu = 4;
    let sigma = 4;

    let (tier_2, tier_1, _) = poly
        .commit::<BN254, Transparent, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let point = random_point(8);
    let expected_evaluation = poly.evaluate(&point);

    let mut prover_transcript = fresh_transcript();
    let (proof, _) = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, ZK>(
        &poly,
        &point,
        tier_1,
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

    let (tier_2, tier_1, _) = poly
        .commit::<BN254, Transparent, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let point = random_point(2);
    let evaluation = poly.evaluate(&point);

    let mut prover_transcript = fresh_transcript();
    let (proof, _) = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, ZK>(
        &poly,
        &point,
        tier_1,
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

    let (tier_2, tier_1, _) = poly
        .commit::<BN254, Transparent, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let point = random_point(10);
    let evaluation = poly.evaluate(&point);

    let mut prover_transcript = fresh_transcript();
    let (proof, _) = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, ZK>(
        &poly,
        &point,
        tier_1,
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

    let (tier_2, tier_1, _) = poly
        .commit::<BN254, Transparent, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let point = random_point(7); // nu + sigma = 7
    let evaluation = poly.evaluate(&point);

    let mut prover_transcript = fresh_transcript();
    let (proof, _) = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, ZK>(
        &poly,
        &point,
        tier_1,
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

    let (tier_2, tier_1, _) = poly
        .commit::<BN254, Transparent, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let point = random_point(4);
    let evaluation = poly.evaluate(&point);

    // Create ZK proof using unified API with ZK mode
    let mut prover_transcript = fresh_transcript();
    let (proof, _) = create_evaluation_proof::<_, BN254, TestG1Routines, TestG2Routines, _, _, ZK>(
        &poly,
        &point,
        Some(tier_1),
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

    let (tier_2, tier_1, _) = poly
        .commit::<BN254, Transparent, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let point = random_point(4);
    let evaluation = poly.evaluate(&point);

    let mut prover_transcript = fresh_transcript();
    let (mut proof, _) =
        create_evaluation_proof::<_, BN254, TestG1Routines, TestG2Routines, _, _, ZK>(
            &poly,
            &point,
            Some(tier_1),
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

    let (tier_2, tier_1, _) = poly
        .commit::<BN254, Transparent, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let point = random_point(8);
    let evaluation = poly.evaluate(&point);

    let mut prover_transcript = fresh_transcript();
    let (proof, _) = create_evaluation_proof::<_, BN254, TestG1Routines, TestG2Routines, _, _, ZK>(
        &poly,
        &point,
        Some(tier_1),
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

    let (tier_2, tier_1, _) = poly
        .commit::<BN254, Transparent, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();
    let mut prover_transcript = fresh_transcript();
    let (proof, _) = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, ZK>(
        &poly,
        &point,
        tier_1,
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
        s.a = ArkGT(Fq12::rand(&mut rand::thread_rng()));
    }

    let result = verify_tampered_zk_proof(commitment, evaluation, &point, &proof, verifier_setup);
    assert!(result.is_err(), "Should fail with tampered sigma2 a");
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
        sp.p1 = ArkGT(Fq12::rand(&mut rand::thread_rng()));
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

#[test]
fn test_zk_soundness_tampered_vmv_c() {
    let (verifier_setup, point, commitment, evaluation, mut proof) =
        create_valid_zk_proof_components(256, 4, 4);

    proof.vmv_message.c = ArkGT(Fq12::rand(&mut rand::thread_rng()));

    let result = verify_tampered_zk_proof(commitment, evaluation, &point, &proof, verifier_setup);
    assert!(result.is_err(), "Should fail with tampered VMV c in ZK");
}

#[test]
fn test_zk_soundness_tampered_vmv_d2() {
    let (verifier_setup, point, commitment, evaluation, mut proof) =
        create_valid_zk_proof_components(256, 4, 4);

    proof.vmv_message.d2 = ArkGT(Fq12::rand(&mut rand::thread_rng()));

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
