//! Quick script to print the AST from a small Dory verification

use std::rc::Rc;

use dory_pcs::backends::arkworks::{
    ArkFr, ArkworksPolynomial, Blake2bTranscript, G1Routines, G2Routines, SimpleWitnessBackend,
    SimpleWitnessGenerator, BN254,
};
use dory_pcs::primitives::arithmetic::Field;
use dory_pcs::primitives::poly::Polynomial;
use dory_pcs::recursion::ast::{AstConstraint, AstOp, ValueType};
use dory_pcs::recursion::TraceContext;
use dory_pcs::{prove, setup, verify_recursive};
use rand::thread_rng;

type Ctx = TraceContext<SimpleWitnessBackend, BN254, SimpleWitnessGenerator>;

fn main() {
    let mut rng = thread_rng();

    // Small setup for fast execution
    let max_log_n = 4;
    let (prover_setup, verifier_setup) = setup::<BN254, _>(&mut rng, max_log_n);

    // Tiny polynomial: 2x2 matrix (nu=1, sigma=1, 4 coefficients)
    let nu = 1;
    let sigma = 1;
    let poly_size = 1 << (nu + sigma); // 4 coefficients

    let coefficients: Vec<ArkFr> = (0..poly_size)
        .map(|i| ArkFr::from_u64(i as u64 + 1))
        .collect();
    let poly = ArkworksPolynomial::new(coefficients);

    let (tier_2, tier_1) = poly
        .commit::<BN254, G1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    // Evaluation point
    let point: Vec<ArkFr> = vec![ArkFr::from_u64(2), ArkFr::from_u64(3)];

    // Create proof
    let mut prover_transcript = Blake2bTranscript::new(b"ast-demo");
    let proof = prove::<_, BN254, G1Routines, G2Routines, _, _>(
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

    // Run symbolic verification
    let ctx = Rc::new(Ctx::for_symbolic());
    let mut transcript = Blake2bTranscript::new(b"ast-demo");

    verify_recursive::<_, BN254, G1Routines, G2Routines, _, _, _>(
        tier_2,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut transcript,
        ctx.clone(),
    )
    .expect("Verification should succeed");

    let ctx_owned = Rc::try_unwrap(ctx)
        .ok()
        .expect("Should have sole ownership");
    let ast = ctx_owned.take_ast().expect("Should have AST");

    // Print formatted AST
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║                    DORY VERIFICATION AST                      ║");
    println!("║           (nu=1, sigma=1, 4-coeff polynomial)                 ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!(
        "║ Total nodes: {:3}                                             ║",
        ast.nodes.len()
    );
    println!(
        "║ Constraints: {:3}                                             ║",
        ast.constraints.len()
    );
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    // Count by type
    let mut inputs = Vec::new();
    let mut g1_ops = Vec::new();
    let mut g2_ops = Vec::new();
    let mut gt_ops = Vec::new();
    let mut pairing_ops = Vec::new();

    for (i, node) in ast.nodes.iter().enumerate() {
        match &node.op {
            AstOp::Input { source } => inputs.push((i, node, source)),
            AstOp::G1ScalarMul { .. } | AstOp::G1Add { .. } | AstOp::MsmG1 { .. } => {
                g1_ops.push((i, node));
            }
            AstOp::G2ScalarMul { .. } | AstOp::G2Add { .. } | AstOp::MsmG2 { .. } => {
                g2_ops.push((i, node));
            }
            AstOp::GTExp { .. } | AstOp::GTMul { .. } => {
                gt_ops.push((i, node));
            }
            AstOp::Pairing { .. } | AstOp::MultiPairing { .. } => {
                pairing_ops.push((i, node));
            }
        }
    }

    println!("┌─────────────────────────────────────────────────────────────┐");
    println!(
        "│ INPUTS ({} nodes)                                           │",
        inputs.len()
    );
    println!("├─────────────────────────────────────────────────────────────┤");
    for (i, node, source) in inputs.iter().take(15) {
        let ty = match node.out_ty {
            ValueType::G1 => "G1",
            ValueType::G2 => "G2",
            ValueType::GT => "GT",
        };
        println!("│ v{:<3} : {} = {:?}", i, ty, source);
    }
    if inputs.len() > 15 {
        println!("│ ... and {} more inputs", inputs.len() - 15);
    }
    println!("└─────────────────────────────────────────────────────────────┘");
    println!();

    println!("┌─────────────────────────────────────────────────────────────┐");
    println!(
        "│ G1 OPERATIONS ({} nodes)                                    │",
        g1_ops.len()
    );
    println!("├─────────────────────────────────────────────────────────────┤");
    for (i, node) in g1_ops.iter().take(10) {
        match &node.op {
            AstOp::G1ScalarMul { point, scalar, .. } => {
                let name = scalar.name.unwrap_or("?");
                println!("│ v{:<3} = v{} * {}", i, point.0, name);
            }
            AstOp::G1Add { a, b, .. } => {
                println!("│ v{:<3} = v{} + v{}", i, a.0, b.0);
            }
            AstOp::MsmG1 {
                points, scalars, ..
            } => {
                let names: Vec<_> = scalars.iter().map(|s| s.name.unwrap_or("?")).collect();
                println!(
                    "│ v{:<3} = MSM({:?}, {:?})",
                    i,
                    points.iter().map(|p| p.0).collect::<Vec<_>>(),
                    names
                );
            }
            _ => {}
        }
    }
    if g1_ops.len() > 10 {
        println!("│ ... and {} more G1 ops", g1_ops.len() - 10);
    }
    println!("└─────────────────────────────────────────────────────────────┘");
    println!();

    println!("┌─────────────────────────────────────────────────────────────┐");
    println!(
        "│ G2 OPERATIONS ({} nodes)                                    │",
        g2_ops.len()
    );
    println!("├─────────────────────────────────────────────────────────────┤");
    for (i, node) in g2_ops.iter().take(10) {
        match &node.op {
            AstOp::G2ScalarMul { point, scalar, .. } => {
                let name = scalar.name.unwrap_or("?");
                println!("│ v{:<3} = v{} * {}", i, point.0, name);
            }
            AstOp::G2Add { a, b, .. } => {
                println!("│ v{:<3} = v{} + v{}", i, a.0, b.0);
            }
            AstOp::MsmG2 {
                points, scalars, ..
            } => {
                let names: Vec<_> = scalars.iter().map(|s| s.name.unwrap_or("?")).collect();
                println!(
                    "│ v{:<3} = MSM({:?}, {:?})",
                    i,
                    points.iter().map(|p| p.0).collect::<Vec<_>>(),
                    names
                );
            }
            _ => {}
        }
    }
    if g2_ops.len() > 10 {
        println!("│ ... and {} more G2 ops", g2_ops.len() - 10);
    }
    println!("└─────────────────────────────────────────────────────────────┘");
    println!();

    println!("┌─────────────────────────────────────────────────────────────┐");
    println!(
        "│ GT OPERATIONS ({} nodes)                                    │",
        gt_ops.len()
    );
    println!("├─────────────────────────────────────────────────────────────┤");
    for (i, node) in gt_ops.iter().take(15) {
        match &node.op {
            AstOp::GTExp { base, scalar, .. } => {
                let name = scalar.name.unwrap_or("?");
                println!("│ v{:<3} = v{}^{}", i, base.0, name);
            }
            AstOp::GTMul { lhs, rhs, .. } => {
                println!("│ v{:<3} = v{} · v{}", i, lhs.0, rhs.0);
            }
            _ => {}
        }
    }
    if gt_ops.len() > 15 {
        println!("│ ... and {} more GT ops", gt_ops.len() - 15);
    }
    println!("└─────────────────────────────────────────────────────────────┘");
    println!();

    println!("┌─────────────────────────────────────────────────────────────┐");
    println!(
        "│ PAIRING OPERATIONS ({} nodes)                               │",
        pairing_ops.len()
    );
    println!("├─────────────────────────────────────────────────────────────┤");
    for (i, node) in pairing_ops.iter() {
        match &node.op {
            AstOp::Pairing { g1, g2, .. } => {
                println!("│ v{:<3} = e(v{}, v{})", i, g1.0, g2.0);
            }
            AstOp::MultiPairing { g1s, g2s, .. } => {
                let g1_ids: Vec<_> = g1s.iter().map(|v| v.0).collect();
                let g2_ids: Vec<_> = g2s.iter().map(|v| v.0).collect();
                println!("│ v{:<3} = Π e(v{:?}, v{:?})", i, g1_ids, g2_ids);
            }
            _ => {}
        }
    }
    println!("└─────────────────────────────────────────────────────────────┘");
    println!();
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!(
        "│ CONSTRAINTS ({})                                            │",
        ast.constraints.len()
    );
    println!("├─────────────────────────────────────────────────────────────┤");
    for constraint in &ast.constraints {
        match constraint {
            AstConstraint::AssertEq { lhs, rhs, what } => {
                println!("│ ASSERT: v{} == v{}  ({})", lhs.0, rhs.0, what);
            }
        }
    }
    println!("└─────────────────────────────────────────────────────────────┘");
}
