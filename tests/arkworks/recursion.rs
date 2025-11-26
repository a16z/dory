//! Integration tests for recursion feature (witness generation and hint-based verification)

use std::rc::Rc;

use super::*;
use dory_pcs::backends::arkworks::{SimpleWitnessBackend, SimpleWitnessGenerator};
use dory_pcs::primitives::poly::Polynomial;
use dory_pcs::recursion::TraceContext;
use dory_pcs::{prove, setup, verify_recursive};

type TestCtx = TraceContext<SimpleWitnessBackend, BN254, SimpleWitnessGenerator>;

#[test]
fn test_witness_gen_roundtrip() {
    let mut rng = rand::thread_rng();
    let max_log_n = 10;

    let (prover_setup, verifier_setup) = setup::<BN254, _>(&mut rng, max_log_n);

    let poly = random_polynomial(256);
    let nu = 4;
    let sigma = 4;

    let (tier_2, tier_1) = poly
        .commit::<BN254, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let point = random_point(8);

    let mut prover_transcript = fresh_transcript();
    let proof = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _>(
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

    // Phase 1: Witness generation
    let ctx = Rc::new(TestCtx::for_witness_gen());
    let mut witness_transcript = fresh_transcript();

    verify_recursive::<_, BN254, TestG1Routines, TestG2Routines, _, _, _>(
        tier_2,
        evaluation,
        &point,
        &proof,
        verifier_setup.clone(),
        &mut witness_transcript,
        ctx.clone(),
    )
    .expect("Witness-generating verification should succeed");

    let collection = Rc::try_unwrap(ctx)
        .ok()
        .expect("Should have sole ownership")
        .finalize()
        .expect("Should have witnesses");

    // Phase 2: Hint-based verification
    let hints = collection.to_hints::<BN254>();
    let ctx = Rc::new(TestCtx::for_hints(hints));
    let mut hint_transcript = fresh_transcript();

    let result = verify_recursive::<_, BN254, TestG1Routines, TestG2Routines, _, _, _>(
        tier_2,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut hint_transcript,
        ctx,
    );

    assert!(result.is_ok(), "Hint-based verification should succeed");
}

#[test]
fn test_witness_collection_contents() {
    let mut rng = rand::thread_rng();
    let max_log_n = 6;

    let (prover_setup, verifier_setup) = setup::<BN254, _>(&mut rng, max_log_n);

    let poly = random_polynomial(16);
    let nu = 2;
    let sigma = 2;

    let (tier_2, tier_1) = poly
        .commit::<BN254, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let point = random_point(4);

    let mut prover_transcript = fresh_transcript();
    let proof = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _>(
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

    let ctx = Rc::new(TestCtx::for_witness_gen());
    let mut witness_transcript = fresh_transcript();

    verify_recursive::<_, BN254, TestG1Routines, TestG2Routines, _, _, _>(
        tier_2,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut witness_transcript,
        ctx.clone(),
    )
    .expect("Witness-generating verification should succeed");

    let collection = Rc::try_unwrap(ctx)
        .ok()
        .expect("Should have sole ownership")
        .finalize()
        .expect("Should have witnesses");

    // Verify the collection contains expected operation types
    assert!(
        !collection.gt_exp.is_empty(),
        "Should have GT exponentiation witnesses"
    );
    assert!(
        !collection.pairing.is_empty() || !collection.multi_pairing.is_empty(),
        "Should have pairing witnesses"
    );

    tracing::info!(
        gt_exp = collection.gt_exp.len(),
        g1_scalar_mul = collection.g1_scalar_mul.len(),
        g2_scalar_mul = collection.g2_scalar_mul.len(),
        gt_mul = collection.gt_mul.len(),
        pairing = collection.pairing.len(),
        multi_pairing = collection.multi_pairing.len(),
        msm_g1 = collection.msm_g1.len(),
        msm_g2 = collection.msm_g2.len(),
        total = collection.total_witnesses(),
        rounds = collection.num_rounds,
        "Witness collection stats"
    );
}

#[test]
fn test_hint_verification_with_missing_hints() {
    let mut rng = rand::thread_rng();
    let max_log_n = 6;

    let (prover_setup, verifier_setup) = setup::<BN254, _>(&mut rng, max_log_n);

    // Create two different polynomials
    let poly1 = random_polynomial(16);
    let poly2 = random_polynomial(16);
    let nu = 2;
    let sigma = 2;

    let (tier_2_1, tier_1_1) = poly1
        .commit::<BN254, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let (tier_2_2, tier_1_2) = poly2
        .commit::<BN254, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let point = random_point(4);

    // Create proof for poly1
    let mut prover_transcript1 = fresh_transcript();
    let proof1 = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _>(
        &poly1,
        &point,
        tier_1_1,
        nu,
        sigma,
        &prover_setup,
        &mut prover_transcript1,
    )
    .unwrap();
    let evaluation1 = poly1.evaluate(&point);

    // Create proof for poly2
    let mut prover_transcript2 = fresh_transcript();
    let proof2 = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _>(
        &poly2,
        &point,
        tier_1_2,
        nu,
        sigma,
        &prover_setup,
        &mut prover_transcript2,
    )
    .unwrap();
    let evaluation2 = poly2.evaluate(&point);

    // Generate hints for poly1's verification
    let ctx = Rc::new(TestCtx::for_witness_gen());
    let mut witness_transcript = fresh_transcript();

    verify_recursive::<_, BN254, TestG1Routines, TestG2Routines, _, _, _>(
        tier_2_1,
        evaluation1,
        &point,
        &proof1,
        verifier_setup.clone(),
        &mut witness_transcript,
        ctx.clone(),
    )
    .expect("Witness-generating verification should succeed");

    let collection = Rc::try_unwrap(ctx)
        .ok()
        .expect("Should have sole ownership")
        .finalize()
        .expect("Should have witnesses");

    let hints = collection.to_hints::<BN254>();

    // Try to use poly1's hints for poly2's verification
    let ctx = Rc::new(TestCtx::for_hints(hints));
    let mut hint_transcript = fresh_transcript();

    let result = verify_recursive::<_, BN254, TestG1Routines, TestG2Routines, _, _, _>(
        tier_2_2,
        evaluation2,
        &point,
        &proof2,
        verifier_setup,
        &mut hint_transcript,
        ctx.clone(),
    );

    // The verification should fail because the hints don't match the proof
    assert!(result.is_err(), "Verification with wrong hints should fail");
}

#[test]
fn test_hint_map_size_reduction() {
    let mut rng = rand::thread_rng();
    let max_log_n = 8;

    let (prover_setup, verifier_setup) = setup::<BN254, _>(&mut rng, max_log_n);

    let poly = random_polynomial(64);
    let nu = 3;
    let sigma = 3;

    let (tier_2, tier_1) = poly
        .commit::<BN254, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let point = random_point(6);

    let mut prover_transcript = fresh_transcript();
    let proof = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _>(
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

    let ctx = Rc::new(TestCtx::for_witness_gen());
    let mut witness_transcript = fresh_transcript();

    verify_recursive::<_, BN254, TestG1Routines, TestG2Routines, _, _, _>(
        tier_2,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut witness_transcript,
        ctx.clone(),
    )
    .expect("Verification should succeed");

    let collection = Rc::try_unwrap(ctx)
        .ok()
        .expect("Should have sole ownership")
        .finalize()
        .expect("Should have witnesses");

    let hints = collection.to_hints::<BN254>();

    // Verify hint count matches total operations
    let total_ops = collection.total_witnesses();
    tracing::info!(
        total_ops,
        hint_map_size = hints.len(),
        "Hint map conversion stats"
    );

    // HintMap should have same number of entries as total witnesses
    assert_eq!(
        hints.len(),
        total_ops,
        "HintMap should have one entry per operation"
    );
}
