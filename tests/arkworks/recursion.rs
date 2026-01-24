//! Integration tests for recursion feature (witness generation, hint-based verification, AST generation)

use std::rc::Rc;

use super::*;
use dory_pcs::backends::arkworks::{SimpleWitnessBackend, SimpleWitnessGenerator};
use dory_pcs::primitives::poly::Polynomial;
use dory_pcs::recursion::ast::{AstOp, ValueType};
use dory_pcs::recursion::{precompute_challenges, ChallengeSet, TraceContext};
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
            dory_pcs::recursion::ast::AstOp::G1Add { op_id, a, b } => {
                format!("G1Add({}, {}, op_id={:?})", a.0, b.0, op_id)
            }
            dory_pcs::recursion::ast::AstOp::G1ScalarMul { point, scalar, .. } => {
                let name = scalar.name.unwrap_or("anon");
                format!("G1ScalarMul({}, scalar={})", point.0, name)
            }
            dory_pcs::recursion::ast::AstOp::G2Add { op_id, a, b } => {
                format!("G2Add({}, {}, op_id={:?})", a.0, b.0, op_id)
            }
            dory_pcs::recursion::ast::AstOp::G2ScalarMul { point, scalar, .. } => {
                let name = scalar.name.unwrap_or("anon");
                format!("G2ScalarMul({}, scalar={})", point.0, name)
            }
            dory_pcs::recursion::ast::AstOp::GTMul { lhs, rhs, .. } => format!("GTMul({}, {})", lhs.0, rhs.0),
            dory_pcs::recursion::ast::AstOp::GTExp { base, scalar, .. } => {
                let name = scalar.name.unwrap_or("anon");
                format!("GTExp({}, scalar={})", base.0, name)
            }
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
                dory_pcs::recursion::ast::AstOp::G1Add { op_id, a, b } => {
                format!("G1Add({}, {}, op_id={:?})", a.0, b.0, op_id)
            }
                dory_pcs::recursion::ast::AstOp::G1ScalarMul { point, scalar, .. } => {
                    let name = scalar.name.unwrap_or("anon");
                    format!("G1ScalarMul({}, scalar={})", point.0, name)
                }
                dory_pcs::recursion::ast::AstOp::G2Add { op_id, a, b } => {
                format!("G2Add({}, {}, op_id={:?})", a.0, b.0, op_id)
            }
                dory_pcs::recursion::ast::AstOp::G2ScalarMul { point, scalar, .. } => {
                    let name = scalar.name.unwrap_or("anon");
                    format!("G2ScalarMul({}, scalar={})", point.0, name)
                }
                dory_pcs::recursion::ast::AstOp::GTMul { lhs, rhs, .. } => format!("GTMul({}, {})", lhs.0, rhs.0),
                dory_pcs::recursion::ast::AstOp::GTExp { base, scalar, .. } => {
                    let name = scalar.name.unwrap_or("anon");
                    format!("GTExp({}, scalar={})", base.0, name)
                }
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

    // Verify the final equality constraint was recorded
    assert_eq!(
        ast_graph.constraints.len(),
        1,
        "Should have exactly one constraint (final pairing equality)"
    );

    // Test wiring extraction with precise input slots
    let wires = ast_graph.wires();
    assert!(
        !wires.is_empty(),
        "Should have wires connecting operations"
    );
    println!("Wire count: {}", wires.len());

    // Show some wires with precise operation kinds and input slots
    println!("\n--- Sample Wires (first 10) ---");
    for wire in wires.iter().take(10) {
        println!("  {}", wire);
    }
    println!("--- Last 10 Wires ---");
    for wire in wires.iter().rev().take(10).collect::<Vec<_>>().into_iter().rev() {
        println!("  {}", wire);
    }
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

/// Test that AST structure is identical whether running in witness-gen or hint-based mode.
/// This ensures the AST is deterministic and independent of execution mode.
#[test]
fn test_ast_structural_equivalence() {
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

    // Phase 1: Witness generation with AST
    let ctx1 = Rc::new(TestCtx::for_witness_gen_with_ast());
    let mut transcript1 = fresh_transcript();

    verify_recursive::<_, BN254, TestG1Routines, TestG2Routines, _, _, _>(
        tier_2,
        evaluation,
        &point,
        &proof,
        verifier_setup.clone(),
        &mut transcript1,
        ctx1.clone(),
    )
    .expect("Witness-gen verification should succeed");

    let ctx1_owned = Rc::try_unwrap(ctx1).ok().expect("Should have sole ownership");
    let (witnesses, ast1) = ctx1_owned.finalize_with_ast();
    let witnesses = witnesses.expect("Should have witnesses");
    let ast1 = ast1.expect("Should have AST");

    // Phase 2: Hint-based verification with AST
    let hints = witnesses.to_hints::<BN254>();
    let ctx2 = Rc::new(TestCtx::for_hints(hints).with_ast());
    let mut transcript2 = fresh_transcript();

    verify_recursive::<_, BN254, TestG1Routines, TestG2Routines, _, _, _>(
        tier_2,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut transcript2,
        ctx2.clone(),
    )
    .expect("Hint-based verification should succeed");

    let ctx2_owned = Rc::try_unwrap(ctx2).ok().expect("Should have sole ownership");
    let ast2 = ctx2_owned.take_ast().expect("Should have AST");

    // Compare AST structures
    assert_eq!(
        ast1.nodes.len(),
        ast2.nodes.len(),
        "AST node counts should match between witness-gen and hint-based modes"
    );

    assert_eq!(
        ast1.constraints.len(),
        ast2.constraints.len(),
        "AST constraint counts should match"
    );

    // Compare each node's structure (not values, just structure)
    for (i, (n1, n2)) in ast1.nodes.iter().zip(ast2.nodes.iter()).enumerate() {
        assert_eq!(
            n1.out, n2.out,
            "Node {} ValueId mismatch: {:?} vs {:?}",
            i, n1.out, n2.out
        );
        assert_eq!(
            n1.out_ty, n2.out_ty,
            "Node {} ValueType mismatch: {:?} vs {:?}",
            i, n1.out_ty, n2.out_ty
        );

        // Compare operation structure (input ValueIds match)
        let inputs1 = n1.op.input_ids();
        let inputs2 = n2.op.input_ids();
        assert_eq!(
            inputs1, inputs2,
            "Node {} input ValueIds mismatch: {:?} vs {:?}",
            i, inputs1, inputs2
        );

        // Compare operation kind
        let kind1 = std::mem::discriminant(&n1.op);
        let kind2 = std::mem::discriminant(&n2.op);
        assert_eq!(
            kind1, kind2,
            "Node {} operation kind mismatch",
            i
        );
    }

    // Compare OpId -> ValueId mapping
    assert_eq!(
        ast1.opid_to_value.len(),
        ast2.opid_to_value.len(),
        "OpId mapping sizes should match"
    );

    for (opid, valueid1) in &ast1.opid_to_value {
        let valueid2 = ast2.opid_to_value.get(opid);
        assert_eq!(
            Some(valueid1),
            valueid2,
            "OpId {:?} ValueId mismatch: {:?} vs {:?}",
            opid, valueid1, valueid2
        );
    }

    println!("\n========== AST STRUCTURAL EQUIVALENCE ==========");
    println!("Witness-gen AST nodes: {}", ast1.nodes.len());
    println!("Hint-based AST nodes: {}", ast2.nodes.len());
    println!("OpId mappings: {}", ast1.opid_to_value.len());
    println!("All structures match ✓");
}

/// Test that all OpIds in the AST have corresponding entries in WitnessCollection.
/// This ensures the AST and witness system are properly synchronized.
#[test]
fn test_ast_opid_witness_join() {
    use dory_pcs::recursion::ast::AstOp;

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

    // Run verification with both AST and witness generation
    let ctx = Rc::new(TestCtx::for_witness_gen_with_ast());
    let mut transcript = fresh_transcript();

    verify_recursive::<_, BN254, TestG1Routines, TestG2Routines, _, _, _>(
        tier_2,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut transcript,
        ctx.clone(),
    )
    .expect("Verification should succeed");

    let ctx_owned = Rc::try_unwrap(ctx).ok().expect("Should have sole ownership");
    let (witnesses, ast) = ctx_owned.finalize_with_ast();
    let witnesses = witnesses.expect("Should have witnesses");
    let ast = ast.expect("Should have AST");
    let hints = witnesses.to_hints::<BN254>();

    // For each node with an OpId, verify the OpId exists in witnesses/hints
    let mut verified_opids = 0;
    let mut missing_opids = Vec::new();

    for node in &ast.nodes {
        let op_id = match &node.op {
            AstOp::G1ScalarMul { op_id, .. } => op_id.as_ref(),
            AstOp::G2ScalarMul { op_id, .. } => op_id.as_ref(),
            AstOp::GTMul { op_id, .. } => op_id.as_ref(),
            AstOp::GTExp { op_id, .. } => op_id.as_ref(),
            AstOp::Pairing { op_id, .. } => op_id.as_ref(),
            AstOp::MultiPairing { op_id, .. } => op_id.as_ref(),
            AstOp::MsmG1 { op_id, .. } => op_id.as_ref(),
            AstOp::MsmG2 { op_id, .. } => op_id.as_ref(),
            AstOp::G1Add { op_id, .. } | AstOp::G2Add { op_id, .. } => op_id.as_ref(),
            AstOp::Input { .. } => None,
        };

        if let Some(opid) = op_id {
            // Verify the OpId exists in the hint map
            if hints.contains(*opid) {
                verified_opids += 1;
            } else {
                missing_opids.push(*opid);
            }
        }
    }

    // Also check the opid_to_value mapping
    for opid in ast.opid_to_value.keys() {
        if !hints.contains(*opid) {
            if !missing_opids.contains(opid) {
                missing_opids.push(*opid);
            }
        }
    }

    println!("\n========== OPID-WITNESS JOIN TEST ==========");
    println!("AST nodes with OpId: {}", verified_opids + missing_opids.len());
    println!("Verified OpIds in hints: {}", verified_opids);
    println!("Missing OpIds: {}", missing_opids.len());
    if !missing_opids.is_empty() {
        println!("Missing: {:?}", missing_opids);
    }

    assert!(
        missing_opids.is_empty(),
        "All OpIds in AST should have corresponding witness entries. Missing: {:?}",
        missing_opids
    );
    assert!(
        verified_opids > 0,
        "Should have verified at least one OpId"
    );
    println!("All OpIds have witness entries ✓");
}

/// Test level computation for parallel AST traversal.
#[test]
fn test_ast_level_computation() {
    use dory_pcs::recursion::ast::ValueType;

    let mut rng = rand::thread_rng();
    
    // Standard test: 4 rounds (sigma=4, nu=4)
    // Matrix is 16 x 16, poly size = 256
    let max_log_n = 10;
    let nu = 4;
    let sigma = 4;
    let poly_size = 1 << (nu + sigma); // 2^8 = 256
    let point_size = nu + sigma;       // 8

    println!("\n========== LEVEL PARALLELISM TEST (σ={} rounds) ==========", sigma);

    let (prover_setup, verifier_setup) = setup::<BN254, _>(&mut rng, max_log_n);

    let poly = random_polynomial(poly_size);

    let (tier_2, tier_1) = poly
        .commit::<BN254, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let point = random_point(point_size);

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
    let ast = ctx_owned.take_ast().expect("Should have AST");

    // Test level computation
    let node_levels = ast.compute_levels();
    assert_eq!(node_levels.len(), ast.len(), "Should have level for each node");

    // All input nodes should be at level 0
    for (idx, node) in ast.nodes.iter().enumerate() {
        if matches!(node.op, AstOp::Input { .. }) {
            assert_eq!(node_levels[idx], 0, "Input nodes should be at level 0");
        } else {
            assert!(node_levels[idx] > 0, "Non-input nodes should be at level > 0");
        }
    }

    // Debug: show operations at Level 1 to understand the parallelism
    println!("\n--- Level 1 Operations (detail) ---");
    for (idx, node) in ast.nodes.iter().enumerate() {
        if node_levels[idx] == 1 {
            let op_str = match &node.op {
                AstOp::Input { .. } => "Input".to_string(),
                AstOp::G1Add { a, b, .. } => format!("G1Add(v{}, v{})", a.0, b.0),
                AstOp::G1ScalarMul { point, scalar, .. } => {
                    format!("G1ScalarMul(v{}, {})", point.0, scalar.name.unwrap_or("?"))
                }
                AstOp::G2Add { a, b, .. } => format!("G2Add(v{}, v{})", a.0, b.0),
                AstOp::G2ScalarMul { point, scalar, .. } => {
                    format!("G2ScalarMul(v{}, {})", point.0, scalar.name.unwrap_or("?"))
                }
                AstOp::GTMul { lhs, rhs, .. } => format!("GTMul(v{}, v{})", lhs.0, rhs.0),
                AstOp::GTExp { base, scalar, .. } => {
                    format!("GTExp(v{}, {})", base.0, scalar.name.unwrap_or("?"))
                }
                AstOp::Pairing { g1, g2, .. } => format!("Pairing(v{}, v{})", g1.0, g2.0),
                AstOp::MultiPairing { g1s, g2s, .. } => {
                    format!("MultiPairing({} pairs)", g1s.len().min(g2s.len()))
                }
                AstOp::MsmG1 { points, .. } => format!("MsmG1({} points)", points.len()),
                AstOp::MsmG2 { points, .. } => format!("MsmG2({} points)", points.len()),
            };
            println!("  v{}: {}", idx, op_str);
        }
    }

    // Test levels() grouping
    let levels = ast.levels();
    println!("\n========== LEVEL COMPUTATION TEST ==========");
    println!("Total nodes: {}", ast.len());
    println!("Number of levels: {}", levels.len());
    println!();

    let mut total_from_levels = 0;
    for (level_idx, nodes) in levels.iter().enumerate() {
        total_from_levels += nodes.len();
        println!("Level {}: {} nodes", level_idx, nodes.len());
    }
    assert_eq!(total_from_levels, ast.len(), "All nodes should be in exactly one level");

    // Test levels_by_type()
    let levels_by_type = ast.levels_by_type();
    println!("\n--- Levels by Type ---");
    for (level_idx, type_map) in levels_by_type.iter().enumerate() {
        let g1_count = type_map.get(&ValueType::G1).map_or(0, |v| v.len());
        let g2_count = type_map.get(&ValueType::G2).map_or(0, |v| v.len());
        let gt_count = type_map.get(&ValueType::GT).map_or(0, |v| v.len());
        if g1_count + g2_count + gt_count > 0 {
            println!("  Level {}: G1={}, G2={}, GT={}", level_idx, g1_count, g2_count, gt_count);
        }
    }

    // Test level_stats()
    let stats = ast.level_stats();
    println!("\n--- Level Stats ---");
    for (level_idx, (total, g1, g2, gt)) in stats.iter().enumerate() {
        if *total > 0 {
            println!("  Level {}: total={}, g1={}, g2={}, gt={}", level_idx, total, g1, g2, gt);
        }
    }

    // Verify topological ordering: each node's level should be > max level of its inputs
    for (idx, node) in ast.nodes.iter().enumerate() {
        let node_level = node_levels[idx];
        for input_id in node.op.input_ids() {
            let input_level = node_levels[input_id.0 as usize];
            assert!(
                node_level > input_level,
                "Node at level {} has input at level {} (should be strictly less)",
                node_level,
                input_level
            );
        }
    }
    println!("\nTopological ordering verified ✓");

    // Check that we have good parallelism opportunities
    let max_parallelism = levels.iter().map(|l| l.len()).max().unwrap_or(0);
    println!("Maximum parallelism (nodes in widest level): {}", max_parallelism);
    assert!(max_parallelism > 1, "Should have at least some parallel opportunities");
}

/// Test that challenge precomputation produces identical results to inline derivation.
#[test]
fn test_challenge_precomputation() {
    use dory_pcs::primitives::transcript::Transcript;

    let mut rng = rand::thread_rng();
    let max_log_n = 8;
    let nu = 3;
    let sigma = 3;
    let poly_size = 1 << (nu + sigma);
    let point_size = nu + sigma;

    println!("\n========== CHALLENGE PRECOMPUTATION TEST ==========");

    let (prover_setup, _verifier_setup) = setup::<BN254, _>(&mut rng, max_log_n);

    let poly = random_polynomial(poly_size);
    let point = random_point(point_size);

    let (_tier_2, tier_1) = poly
        .commit::<BN254, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    // Generate proof
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

    // Pre-compute challenges
    let mut transcript1 = fresh_transcript();
    let challenges: ChallengeSet<_> =
        precompute_challenges::<_, BN254, _>(&proof, &mut transcript1).unwrap();

    // Verify structure
    assert_eq!(challenges.num_rounds(), sigma);
    println!("Number of rounds: {}", challenges.num_rounds());

    // Manually derive challenges inline and compare
    let mut transcript2 = fresh_transcript();

    // VMV
    transcript2.append_serde(b"vmv_c", &proof.vmv_message.c);
    transcript2.append_serde(b"vmv_d2", &proof.vmv_message.d2);
    transcript2.append_serde(b"vmv_e1", &proof.vmv_message.e1);

    for (round, round_challenges) in challenges.rounds.iter().enumerate() {
        let first_msg = &proof.first_messages[round];
        let second_msg = &proof.second_messages[round];

        transcript2.append_serde(b"d1_left", &first_msg.d1_left);
        transcript2.append_serde(b"d1_right", &first_msg.d1_right);
        transcript2.append_serde(b"d2_left", &first_msg.d2_left);
        transcript2.append_serde(b"d2_right", &first_msg.d2_right);
        transcript2.append_serde(b"e1_beta", &first_msg.e1_beta);
        transcript2.append_serde(b"e2_beta", &first_msg.e2_beta);
        let beta_inline = transcript2.challenge_scalar(b"beta");

        assert_eq!(
            round_challenges.beta, beta_inline,
            "beta mismatch at round {}",
            round
        );

        transcript2.append_serde(b"c_plus", &second_msg.c_plus);
        transcript2.append_serde(b"c_minus", &second_msg.c_minus);
        transcript2.append_serde(b"e1_plus", &second_msg.e1_plus);
        transcript2.append_serde(b"e1_minus", &second_msg.e1_minus);
        transcript2.append_serde(b"e2_plus", &second_msg.e2_plus);
        transcript2.append_serde(b"e2_minus", &second_msg.e2_minus);
        let alpha_inline = transcript2.challenge_scalar(b"alpha");

        assert_eq!(
            round_challenges.alpha, alpha_inline,
            "alpha mismatch at round {}",
            round
        );

        println!(
            "Round {}: beta ✓, alpha ✓",
            round
        );
    }

    let gamma_inline = transcript2.challenge_scalar(b"gamma");
    assert_eq!(challenges.gamma, gamma_inline, "gamma mismatch");
    println!("gamma ✓");

    transcript2.append_serde(b"final_e1", &proof.final_message.e1);
    transcript2.append_serde(b"final_e2", &proof.final_message.e2);
    let d_inline = transcript2.challenge_scalar(b"d");
    assert_eq!(challenges.d, d_inline, "d mismatch");
    println!("d ✓");

    // Test derived values
    let (gamma_inv, d_inv) = challenges.final_derived();
    assert_eq!(
        challenges.gamma * gamma_inv,
        ArkFr::from_u64(1),
        "gamma_inv should be inverse of gamma"
    );
    assert_eq!(
        challenges.d * d_inv,
        ArkFr::from_u64(1),
        "d_inv should be inverse of d"
    );
    println!("Derived values (gamma_inv, d_inv) ✓");

    // Test round derived values
    for (round, round_challenges) in challenges.rounds.iter().enumerate() {
        let (alpha_inv, beta_inv, alpha_beta, alpha_inv_beta_inv) = round_challenges.derived();
        assert_eq!(
            round_challenges.alpha * alpha_inv,
            ArkFr::from_u64(1),
            "alpha_inv should be inverse at round {}",
            round
        );
        assert_eq!(
            round_challenges.beta * beta_inv,
            ArkFr::from_u64(1),
            "beta_inv should be inverse at round {}",
            round
        );
        assert_eq!(
            alpha_beta,
            round_challenges.alpha * round_challenges.beta,
            "alpha_beta should be product at round {}",
            round
        );
        assert_eq!(
            alpha_inv_beta_inv,
            alpha_inv * beta_inv,
            "alpha_inv_beta_inv should be product at round {}",
            round
        );
    }
    println!("Round derived values (alpha_inv, beta_inv, products) ✓");

    println!("\nChallenge precomputation matches inline derivation ✓");
}

/// Test deferred mode: records AST + hints without witness expansion.
#[test]
fn test_deferred_mode() {
    let mut rng = rand::thread_rng();
    let max_log_n = 8;
    let nu = 3;
    let sigma = 3;
    let poly_size = 1 << (nu + sigma);
    let point_size = nu + sigma;

    println!("\n========== DEFERRED MODE TEST ==========");

    let (prover_setup, verifier_setup) = setup::<BN254, _>(&mut rng, max_log_n);

    let poly = random_polynomial(poly_size);
    let point = random_point(point_size);

    let (_tier_2, tier_1) = poly
        .commit::<BN254, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

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
    let commitment = _tier_2;

    // Run verification in deferred mode
    let ctx = Rc::new(TestCtx::for_deferred());
    let mut transcript = fresh_transcript();

    verify_recursive::<_, BN254, TestG1Routines, TestG2Routines, _, _, _>(
        commitment,
        evaluation,
        &point,
        &proof,
        verifier_setup.clone(),
        &mut transcript,
        ctx.clone(),
    )
    .expect("Verification should succeed in deferred mode");

    // Get AST and hints
    let ctx_owned = Rc::try_unwrap(ctx)
        .ok()
        .expect("Should have sole ownership");
    let ast = ctx_owned.take_ast().expect("Should have AST in deferred mode");
    let hints = ctx_owned.take_deferred_hints().expect("Should have hints in deferred mode");

    // Verify we got meaningful data
    assert!(!ast.is_empty(), "AST should not be empty");
    assert!(hints.len() > 0, "Should have recorded hints");

    println!("AST nodes: {}", ast.len());
    println!("Hints recorded: {}", hints.len());

    // Verify AST structure
    ast.validate().expect("AST should be valid");

    // Verify hints cover the operations
    let mut g1_ops = 0;
    let mut g2_ops = 0;
    let mut gt_ops = 0;
    let mut pairing_ops = 0;

    for node in &ast.nodes {
        match &node.op {
            AstOp::G1ScalarMul { op_id: Some(id), .. } => {
                assert!(hints.get_g1(*id).is_some(), "G1ScalarMul hint should exist");
                g1_ops += 1;
            }
            AstOp::G1Add { op_id: Some(id), .. } => {
                assert!(hints.get_g1(*id).is_some(), "G1Add hint should exist");
                g1_ops += 1;
            }
            AstOp::G2ScalarMul { op_id: Some(id), .. } => {
                assert!(hints.get_g2(*id).is_some(), "G2ScalarMul hint should exist");
                g2_ops += 1;
            }
            AstOp::G2Add { op_id: Some(id), .. } => {
                assert!(hints.get_g2(*id).is_some(), "G2Add hint should exist");
                g2_ops += 1;
            }
            AstOp::GTExp { op_id: Some(id), .. } => {
                assert!(hints.get_gt(*id).is_some(), "GTExp hint should exist");
                gt_ops += 1;
            }
            AstOp::GTMul { op_id: Some(id), .. } => {
                assert!(hints.get_gt(*id).is_some(), "GTMul hint should exist");
                gt_ops += 1;
            }
            AstOp::Pairing { op_id: Some(id), .. } => {
                assert!(hints.get_gt(*id).is_some(), "Pairing hint should exist");
                pairing_ops += 1;
            }
            AstOp::MultiPairing { op_id: Some(id), .. } => {
                assert!(hints.get_gt(*id).is_some(), "MultiPairing hint should exist");
                pairing_ops += 1;
            }
            _ => {}
        }
    }

    println!("Operations with hints:");
    println!("  G1 ops: {}", g1_ops);
    println!("  G2 ops: {}", g2_ops);
    println!("  GT ops: {}", gt_ops);
    println!("  Pairing ops: {}", pairing_ops);

    assert!(g1_ops > 0, "Should have G1 operations");
    assert!(g2_ops > 0, "Should have G2 operations");
    assert!(gt_ops > 0, "Should have GT operations");
    assert!(pairing_ops > 0, "Should have pairing operations");

    println!("\nDeferred mode verification successful ✓");
    println!("Phase 2 (parallel witness expansion) would be handled by upstream crate");
}
