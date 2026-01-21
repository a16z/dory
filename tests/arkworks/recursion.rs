//! Integration tests for recursion feature (witness generation, hint-based verification, AST generation)

use std::rc::Rc;

use super::*;
use dory_pcs::backends::arkworks::{SimpleWitnessBackend, SimpleWitnessGenerator};
use dory_pcs::primitives::poly::Polynomial;
use dory_pcs::recursion::ast::ValueType;
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

#[test]
fn test_ast_generation() {
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

    // Create context with AST generation enabled
    let ctx = Rc::new(TestCtx::for_witness_gen_with_ast());
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

    // Extract and validate the AST
    let ctx_owned = Rc::try_unwrap(ctx)
        .ok()
        .expect("Should have sole ownership");
    let ast_graph = ctx_owned.take_ast().expect("Should have AST");

    // Validate the AST structure
    let result = ast_graph.validate();
    assert!(result.is_ok(), "AST validation failed: {:?}", result.err());

    // Check that the AST has meaningful content
    assert!(
        !ast_graph.nodes.is_empty(),
        "AST should have nodes after verification"
    );

    // Count node types
    let mut g1_count = 0usize;
    let mut g2_count = 0usize;
    let mut gt_count = 0usize;
    let mut input_count = 0usize;

    for node in &ast_graph.nodes {
        match node.out_ty {
            ValueType::G1 => g1_count += 1,
            ValueType::G2 => g2_count += 1,
            ValueType::GT => gt_count += 1,
        }
        if matches!(node.op, dory_pcs::recursion::ast::AstOp::Input { .. }) {
            input_count += 1;
        }
    }

    println!("\n========== AST GENERATION RESULTS ==========");
    println!("Total nodes: {}", ast_graph.nodes.len());
    println!("  G1 nodes: {}", g1_count);
    println!("  G2 nodes: {}", g2_count);
    println!("  GT nodes: {}", gt_count);
    println!("  Input nodes: {}", input_count);
    println!("\n--- First 30 AST Nodes ---");
    for (i, node) in ast_graph.nodes.iter().take(30).enumerate() {
        let op_str = match &node.op {
            dory_pcs::recursion::ast::AstOp::Input { source } => format!("Input({:?})", source),
            dory_pcs::recursion::ast::AstOp::G1Add { a, b } => format!("G1Add({}, {})", a.0, b.0),
            dory_pcs::recursion::ast::AstOp::G1Neg { a } => format!("G1Neg({})", a.0),
            dory_pcs::recursion::ast::AstOp::G1ScalarMul { point, scalar, .. } => {
                let name = scalar.name.unwrap_or("anon");
                format!("G1ScalarMul({}, scalar={})", point.0, name)
            }
            dory_pcs::recursion::ast::AstOp::G2Add { a, b } => format!("G2Add({}, {})", a.0, b.0),
            dory_pcs::recursion::ast::AstOp::G2Neg { a } => format!("G2Neg({})", a.0),
            dory_pcs::recursion::ast::AstOp::G2ScalarMul { point, scalar, .. } => {
                let name = scalar.name.unwrap_or("anon");
                format!("G2ScalarMul({}, scalar={})", point.0, name)
            }
            dory_pcs::recursion::ast::AstOp::GTMul { lhs, rhs, .. } => format!("GTMul({}, {})", lhs.0, rhs.0),
            dory_pcs::recursion::ast::AstOp::GTExp { base, scalar, .. } => {
                let name = scalar.name.unwrap_or("anon");
                format!("GTExp({}, scalar={})", base.0, name)
            }
            dory_pcs::recursion::ast::AstOp::GTNeg { a } => format!("GTNeg({})", a.0),
            dory_pcs::recursion::ast::AstOp::Pairing { g1, g2, .. } => format!("Pairing({}, {})", g1.0, g2.0),
            dory_pcs::recursion::ast::AstOp::MultiPairing { g1s, g2s, .. } => {
                format!("MultiPairing(g1s={:?}, g2s={:?})", 
                    g1s.iter().map(|v| v.0).collect::<Vec<_>>(),
                    g2s.iter().map(|v| v.0).collect::<Vec<_>>())
            }
            dory_pcs::recursion::ast::AstOp::MsmG1 { points, scalars, .. } => {
                format!("MsmG1(points={:?}, {} scalars)", 
                    points.iter().map(|v| v.0).collect::<Vec<_>>(), scalars.len())
            }
            dory_pcs::recursion::ast::AstOp::MsmG2 { points, scalars, .. } => {
                format!("MsmG2(points={:?}, {} scalars)", 
                    points.iter().map(|v| v.0).collect::<Vec<_>>(), scalars.len())
            }
        };
        println!("[{:3}] {:?} -> {} = {}", i, node.out_ty, node.out.0, op_str);
    }
    if ast_graph.nodes.len() > 30 {
        println!("... ({} nodes in middle) ...", ast_graph.nodes.len() - 40);
        println!("\n--- Last 10 AST Nodes ---");
        let start = ast_graph.nodes.len().saturating_sub(10);
        for (i, node) in ast_graph.nodes.iter().skip(start).enumerate() {
            let idx = start + i;
            let op_str = match &node.op {
                dory_pcs::recursion::ast::AstOp::Input { source } => format!("Input({:?})", source),
                dory_pcs::recursion::ast::AstOp::G1Add { a, b } => format!("G1Add({}, {})", a.0, b.0),
                dory_pcs::recursion::ast::AstOp::G1Neg { a } => format!("G1Neg({})", a.0),
                dory_pcs::recursion::ast::AstOp::G1ScalarMul { point, scalar, .. } => {
                    let name = scalar.name.unwrap_or("anon");
                    format!("G1ScalarMul({}, scalar={})", point.0, name)
                }
                dory_pcs::recursion::ast::AstOp::G2Add { a, b } => format!("G2Add({}, {})", a.0, b.0),
                dory_pcs::recursion::ast::AstOp::G2Neg { a } => format!("G2Neg({})", a.0),
                dory_pcs::recursion::ast::AstOp::G2ScalarMul { point, scalar, .. } => {
                    let name = scalar.name.unwrap_or("anon");
                    format!("G2ScalarMul({}, scalar={})", point.0, name)
                }
                dory_pcs::recursion::ast::AstOp::GTMul { lhs, rhs, .. } => format!("GTMul({}, {})", lhs.0, rhs.0),
                dory_pcs::recursion::ast::AstOp::GTExp { base, scalar, .. } => {
                    let name = scalar.name.unwrap_or("anon");
                    format!("GTExp({}, scalar={})", base.0, name)
                }
                dory_pcs::recursion::ast::AstOp::GTNeg { a } => format!("GTNeg({})", a.0),
                dory_pcs::recursion::ast::AstOp::Pairing { g1, g2, .. } => format!("Pairing({}, {})", g1.0, g2.0),
                dory_pcs::recursion::ast::AstOp::MultiPairing { g1s, g2s, .. } => {
                    format!("MultiPairing(g1s={:?}, g2s={:?})", 
                        g1s.iter().map(|v| v.0).collect::<Vec<_>>(),
                        g2s.iter().map(|v| v.0).collect::<Vec<_>>())
                }
                dory_pcs::recursion::ast::AstOp::MsmG1 { points, scalars, .. } => {
                    format!("MsmG1(points={:?}, {} scalars)", 
                        points.iter().map(|v| v.0).collect::<Vec<_>>(), scalars.len())
                }
                dory_pcs::recursion::ast::AstOp::MsmG2 { points, scalars, .. } => {
                    format!("MsmG2(points={:?}, {} scalars)", 
                        points.iter().map(|v| v.0).collect::<Vec<_>>(), scalars.len())
                }
            };
            println!("[{:3}] {:?} -> {} = {}", idx, node.out_ty, node.out.0, op_str);
        }
    }
    println!("=============================================\n");

    // We expect nodes of each type given the verification process
    assert!(gt_count > 0, "Should have GT nodes for GT exponentiation and multiplication");
    assert!(input_count > 0, "Should have input nodes for setup and proof elements");
}

#[test]
fn test_ast_input_interning() {
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

    // Run verification with AST
    let ctx = Rc::new(TestCtx::for_witness_gen_with_ast());
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

    let ctx_owned = Rc::try_unwrap(ctx)
        .ok()
        .expect("Should have sole ownership");
    let ast_graph = ctx_owned.take_ast().expect("Should have AST");

    // Check interning: count unique input sources
    use std::collections::HashSet;
    let mut input_sources = HashSet::new();

    for node in &ast_graph.nodes {
        if let dory_pcs::recursion::ast::AstOp::Input { ref source } = node.op {
            input_sources.insert(format!("{:?}", source));
        }
    }

    // Each unique input source should appear exactly once due to interning
    let input_count = ast_graph.nodes.iter()
        .filter(|n| matches!(n.op, dory_pcs::recursion::ast::AstOp::Input { .. }))
        .count();

    assert_eq!(
        input_count,
        input_sources.len(),
        "Input interning should deduplicate identical sources"
    );

    tracing::info!(
        unique_input_sources = input_sources.len(),
        "Interned input sources"
    );
}
