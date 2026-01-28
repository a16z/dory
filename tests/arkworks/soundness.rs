//! Comprehensive soundness tests for Dory PCS

use super::*;
use ark_bn254::{Fq12, Fr, G1Projective, G2Projective};
use ark_ff::UniformRand;
use dory_pcs::backends::arkworks::{ArkFr, ArkG1, ArkG2, ArkGT};
use dory_pcs::primitives::poly::Polynomial;
use dory_pcs::{prove, verify, Transparent};
use std::mem::swap;

#[allow(clippy::type_complexity)]
fn create_valid_proof_components(
    size: usize,
    nu: usize,
    sigma: usize,
) -> (
    ProverSetup<BN254>,
    VerifierSetup<BN254>,
    ArkworksPolynomial,
    Vec<ArkFr>,
    ArkGT,
    ArkFr,
    DoryProof<ArkG1, ArkG2, ArkGT>,
) {
    let (prover_setup, verifier_setup) = test_setup_pair(nu + sigma + 2);

    let poly = random_polynomial(size);
    let point = random_point(nu + sigma);

    let (tier_2, tier_1) = poly
        .commit::<BN254, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let mut rng = rand::thread_rng();
    let mut prover_transcript = fresh_transcript();
    let (proof, _) = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, Transparent, _>(
        &poly,
        &point,
        tier_1,
        nu,
        sigma,
        &prover_setup,
        &mut prover_transcript,
        &mut rng,
    )
    .unwrap();
    let evaluation = poly.evaluate(&point);

    (
        prover_setup,
        verifier_setup,
        poly,
        point,
        tier_2,
        evaluation,
        proof,
    )
}

#[test]
fn test_soundness_tamper_vmv_c() {
    let (_, verifier_setup, _, point, commitment, evaluation, mut proof) =
        create_valid_proof_components(256, 4, 4);

    proof.vmv_message.c = ArkGT(Fq12::rand(&mut rand::thread_rng()));

    let mut verifier_transcript = fresh_transcript();
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        commitment,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(result.is_err(), "Should fail with tampered VMV C");
}

#[test]
fn test_soundness_tamper_vmv_d2() {
    let (_, verifier_setup, _, point, commitment, evaluation, mut proof) =
        create_valid_proof_components(256, 4, 4);

    proof.vmv_message.d2 = ArkGT(Fq12::rand(&mut rand::thread_rng()));

    let mut verifier_transcript = fresh_transcript();
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        commitment,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(result.is_err(), "Should fail with tampered VMV D2");
}

#[test]
fn test_soundness_tamper_vmv_e1() {
    let (_, verifier_setup, _, point, commitment, evaluation, mut proof) =
        create_valid_proof_components(256, 4, 4);

    proof.vmv_message.e1 = ArkG1(G1Projective::rand(&mut rand::thread_rng()));

    let mut verifier_transcript = fresh_transcript();
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        commitment,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(result.is_err(), "Should fail with tampered VMV E1");
}

#[test]
fn test_soundness_tamper_d1_left() {
    let (_, verifier_setup, _, point, commitment, evaluation, mut proof) =
        create_valid_proof_components(256, 4, 4);

    if !proof.first_messages.is_empty() {
        proof.first_messages[0].d1_left = ArkGT(Fq12::rand(&mut rand::thread_rng()));
    }

    let mut verifier_transcript = fresh_transcript();
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        commitment,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(result.is_err(), "Should fail with tampered d1_left");
}

#[test]
fn test_soundness_tamper_d1_right() {
    let (_, verifier_setup, _, point, commitment, evaluation, mut proof) =
        create_valid_proof_components(256, 4, 4);

    if !proof.first_messages.is_empty() {
        proof.first_messages[0].d1_right = ArkGT(Fq12::rand(&mut rand::thread_rng()));
    }

    let mut verifier_transcript = fresh_transcript();
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        commitment,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(result.is_err(), "Should fail with tampered d1_right");
}

#[test]
fn test_soundness_tamper_d2_left() {
    let (_, verifier_setup, _, point, commitment, evaluation, mut proof) =
        create_valid_proof_components(256, 4, 4);

    if !proof.first_messages.is_empty() {
        proof.first_messages[0].d2_left = ArkGT(Fq12::rand(&mut rand::thread_rng()));
    }

    let mut verifier_transcript = fresh_transcript();
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        commitment,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(result.is_err(), "Should fail with tampered d2_left");
}

#[test]
fn test_soundness_tamper_d2_right() {
    let (_, verifier_setup, _, point, commitment, evaluation, mut proof) =
        create_valid_proof_components(256, 4, 4);

    if !proof.first_messages.is_empty() {
        proof.first_messages[0].d2_right = ArkGT(Fq12::rand(&mut rand::thread_rng()));
    }

    let mut verifier_transcript = fresh_transcript();
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        commitment,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(result.is_err(), "Should fail with tampered d2_right");
}

#[test]
fn test_soundness_tamper_e1_beta() {
    let (_, verifier_setup, _, point, commitment, evaluation, mut proof) =
        create_valid_proof_components(256, 4, 4);

    if !proof.first_messages.is_empty() {
        proof.first_messages[0].e1_beta = ArkG1(G1Projective::rand(&mut rand::thread_rng()));
    }

    let mut verifier_transcript = fresh_transcript();
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        commitment,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(result.is_err(), "Should fail with tampered e1_beta");
}

#[test]
fn test_soundness_tamper_e2_beta() {
    let (_, verifier_setup, _, point, commitment, evaluation, mut proof) =
        create_valid_proof_components(256, 4, 4);

    if !proof.first_messages.is_empty() {
        proof.first_messages[0].e2_beta = ArkG2(G2Projective::rand(&mut rand::thread_rng()));
    }

    let mut verifier_transcript = fresh_transcript();
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        commitment,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(result.is_err(), "Should fail with tampered e2_beta");
}

#[test]
fn test_soundness_tamper_c_plus() {
    let (_, verifier_setup, _, point, commitment, evaluation, mut proof) =
        create_valid_proof_components(256, 4, 4);

    if !proof.second_messages.is_empty() {
        proof.second_messages[0].c_plus = ArkGT(Fq12::rand(&mut rand::thread_rng()));
    }

    let mut verifier_transcript = fresh_transcript();
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        commitment,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(result.is_err(), "Should fail with tampered c_plus");
}

#[test]
fn test_soundness_tamper_c_minus() {
    let (_, verifier_setup, _, point, commitment, evaluation, mut proof) =
        create_valid_proof_components(256, 4, 4);

    if !proof.second_messages.is_empty() {
        proof.second_messages[0].c_minus = ArkGT(Fq12::rand(&mut rand::thread_rng()));
    }

    let mut verifier_transcript = fresh_transcript();
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        commitment,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(result.is_err(), "Should fail with tampered c_minus");
}

#[test]
fn test_soundness_tamper_e1_plus() {
    let (_, verifier_setup, _, point, commitment, evaluation, mut proof) =
        create_valid_proof_components(256, 4, 4);

    if !proof.second_messages.is_empty() {
        proof.second_messages[0].e1_plus = ArkG1(G1Projective::rand(&mut rand::thread_rng()));
    }

    let mut verifier_transcript = fresh_transcript();
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        commitment,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(result.is_err(), "Should fail with tampered e1_plus");
}

#[test]
fn test_soundness_tamper_e1_minus() {
    let (_, verifier_setup, _, point, commitment, evaluation, mut proof) =
        create_valid_proof_components(256, 4, 4);

    if !proof.second_messages.is_empty() {
        proof.second_messages[0].e1_minus = ArkG1(G1Projective::rand(&mut rand::thread_rng()));
    }

    let mut verifier_transcript = fresh_transcript();
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        commitment,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(result.is_err(), "Should fail with tampered e1_minus");
}

#[test]
fn test_soundness_tamper_e2_plus() {
    let (_, verifier_setup, _, point, commitment, evaluation, mut proof) =
        create_valid_proof_components(256, 4, 4);

    if !proof.second_messages.is_empty() {
        proof.second_messages[0].e2_plus = ArkG2(G2Projective::rand(&mut rand::thread_rng()));
    }

    let mut verifier_transcript = fresh_transcript();
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        commitment,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(result.is_err(), "Should fail with tampered e2_plus");
}

#[test]
fn test_soundness_tamper_e2_minus() {
    let (_, verifier_setup, _, point, commitment, evaluation, mut proof) =
        create_valid_proof_components(256, 4, 4);

    if !proof.second_messages.is_empty() {
        proof.second_messages[0].e2_minus = ArkG2(G2Projective::rand(&mut rand::thread_rng()));
    }

    let mut verifier_transcript = fresh_transcript();
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        commitment,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(result.is_err(), "Should fail with tampered e2_minus");
}

#[test]
fn test_soundness_tamper_final_e1() {
    let (_, verifier_setup, _, point, commitment, evaluation, mut proof) =
        create_valid_proof_components(256, 4, 4);

    proof.final_message.e1 = ArkG1(G1Projective::rand(&mut rand::thread_rng()));

    let mut verifier_transcript = fresh_transcript();
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        commitment,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(result.is_err(), "Should fail with tampered final e1");
}

#[test]
fn test_soundness_tamper_final_e2() {
    let (_, verifier_setup, _, point, commitment, evaluation, mut proof) =
        create_valid_proof_components(256, 4, 4);

    proof.final_message.e2 = ArkG2(G2Projective::rand(&mut rand::thread_rng()));

    let mut verifier_transcript = fresh_transcript();
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        commitment,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(result.is_err(), "Should fail with tampered final e2");
}

#[test]
fn test_soundness_tamper_both_final_elements() {
    let (_, verifier_setup, _, point, commitment, evaluation, mut proof) =
        create_valid_proof_components(256, 4, 4);

    proof.final_message.e1 = ArkG1(G1Projective::rand(&mut rand::thread_rng()));
    proof.final_message.e2 = ArkG2(G2Projective::rand(&mut rand::thread_rng()));

    let mut verifier_transcript = fresh_transcript();
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        commitment,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(
        result.is_err(),
        "Should fail with both final elements tampered"
    );
}

#[test]
fn test_soundness_swap_d1_values() {
    let (_, verifier_setup, _, point, commitment, evaluation, mut proof) =
        create_valid_proof_components(256, 4, 4);

    if !proof.first_messages.is_empty() {
        let msg = &mut proof.first_messages[0];
        swap(&mut msg.d1_left, &mut msg.d1_right);
    }

    let mut verifier_transcript = fresh_transcript();
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        commitment,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(result.is_err(), "Should fail with swapped d1 values");
}

#[test]
fn test_soundness_swap_c_values() {
    let (_, verifier_setup, _, point, commitment, evaluation, mut proof) =
        create_valid_proof_components(256, 4, 4);

    if !proof.second_messages.is_empty() {
        let msg = &mut proof.second_messages[0];
        swap(&mut msg.c_plus, &mut msg.c_minus);
    }

    let mut verifier_transcript = fresh_transcript();
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        commitment,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(result.is_err(), "Should fail with swapped c values");
}

#[test]
fn test_soundness_scale_d1_values() {
    let (_, verifier_setup, _, point, commitment, evaluation, mut proof) =
        create_valid_proof_components(256, 4, 4);

    if !proof.first_messages.is_empty() {
        use dory_pcs::primitives::arithmetic::Group;

        let scale = ArkFr(Fr::rand(&mut rand::thread_rng()));
        proof.first_messages[0].d1_left = proof.first_messages[0].d1_left.scale(&scale);
        proof.first_messages[0].d1_right = proof.first_messages[0].d1_right.scale(&scale);
    }

    let mut verifier_transcript = fresh_transcript();
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        commitment,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(result.is_err(), "Should fail with scaled d1 values");
}

#[test]
fn test_soundness_multi_round_tampering() {
    let (_, verifier_setup, _, point, commitment, evaluation, mut proof) =
        create_valid_proof_components(256, 4, 4);

    if proof.first_messages.len() >= 2 {
        proof.first_messages[0].d1_left = ArkGT(Fq12::rand(&mut rand::thread_rng()));
        proof.first_messages[1].e2_beta = ArkG2(G2Projective::rand(&mut rand::thread_rng()));
    }

    let mut verifier_transcript = fresh_transcript();
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        commitment,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(result.is_err(), "Should fail with multi-round tampering");
}

#[test]
fn test_soundness_last_round_tampering() {
    let (_, verifier_setup, _, point, commitment, evaluation, mut proof) =
        create_valid_proof_components(256, 4, 4);

    let last_round = proof.first_messages.len().saturating_sub(1);
    if !proof.first_messages.is_empty() {
        proof.first_messages[last_round].d2_right = ArkGT(Fq12::rand(&mut rand::thread_rng()));
    }

    let mut verifier_transcript = fresh_transcript();
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        commitment,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(result.is_err(), "Should fail with last round tampering");
}

#[test]
fn test_soundness_identity_elements() {
    let (_, verifier_setup, _, point, commitment, evaluation, mut proof) =
        create_valid_proof_components(256, 4, 4);

    use dory_pcs::primitives::arithmetic::Group;
    proof.final_message.e1 = ArkG1::identity();
    proof.final_message.e2 = ArkG2::identity();

    let mut verifier_transcript = fresh_transcript();
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        commitment,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(result.is_err(), "Should fail with identity elements");
}

#[test]
fn test_soundness_wrong_evaluation() {
    let (_, verifier_setup, _, point, commitment, _, proof) =
        create_valid_proof_components(256, 4, 4);

    let wrong_evaluation = ArkFr(Fr::rand(&mut rand::thread_rng()));

    let mut verifier_transcript = fresh_transcript();
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        commitment,
        wrong_evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(result.is_err(), "Should fail with wrong evaluation");
}

#[test]
fn test_soundness_mixed_proofs() {
    let (_, _, _, _point1, _, _, proof1) = create_valid_proof_components(256, 4, 4);
    let (_, verifier_setup, _, point2, commitment2, evaluation2, mut proof2) =
        create_valid_proof_components(256, 4, 4);

    if !proof1.first_messages.is_empty() && !proof2.first_messages.is_empty() {
        proof2.first_messages[0].d1_left = proof1.first_messages[0].d1_left;
    }

    let mut verifier_transcript = fresh_transcript();
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        commitment2,
        evaluation2,
        &point2,
        &proof2,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(result.is_err(), "Should fail with mixed proof elements");
}

#[test]
fn test_soundness_different_transcript() {
    let (_, verifier_setup, _, point, commitment, evaluation, proof) =
        create_valid_proof_components(256, 4, 4);

    let mut verifier_transcript = Blake2bTranscript::new(b"different-domain");
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        commitment,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(result.is_err(), "Should fail with different transcript");
}
