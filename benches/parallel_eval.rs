//! Benchmark for parallel AST evaluation
//!
//! Compares sequential vs parallel (work-stealing) evaluation of the
//! Dory verification AST.
//!
//! Run with: cargo bench --bench parallel_eval --features backends,parallel,recursion

#![allow(missing_docs)]

use std::collections::HashMap;
use std::rc::Rc;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use dory_pcs::backends::arkworks::{
    ArkFr, ArkG1, ArkG2, ArkGT, ArkworksPolynomial, Blake2bTranscript, G1Routines, G2Routines,
    SimpleWitnessBackend, SimpleWitnessGenerator, BN254,
};
use dory_pcs::primitives::arithmetic::{DoryRoutines, Field, PairingCurve};
use dory_pcs::primitives::poly::Polynomial;
use dory_pcs::recursion::ast::{AstGraph, AstNode, AstOp, ValueId};
use dory_pcs::recursion::{EvalResult, InputProvider, OperationEvaluator, TaskExecutor, TraceContext};
use dory_pcs::{prove, setup, verify_recursive};
use rand::{thread_rng, Rng};

use ark_ec::PrimeGroup;
use ark_ff::PrimeField;

type TestCtx = TraceContext<SimpleWitnessBackend, BN254, SimpleWitnessGenerator>;

/// Input provider that looks up values from a pre-computed map.
struct MapInputProvider {
    inputs: HashMap<ValueId, EvalResult<BN254>>,
}

impl InputProvider<BN254> for MapInputProvider {
    fn get_input(&self, node: &AstNode<BN254>) -> Option<EvalResult<BN254>> {
        self.inputs.get(&node.out).cloned()
    }
}

/// Operation evaluator using arkworks backend.
struct ArkworksEvaluator;

impl OperationEvaluator<BN254> for ArkworksEvaluator {
    fn g1_add(&self, a: &ArkG1, b: &ArkG1) -> ArkG1 {
        *a + *b
    }

    fn g1_scalar_mul(&self, point: &ArkG1, scalar: &ArkFr) -> ArkG1 {
        ArkG1(point.0 * scalar.0)
    }

    fn g1_msm(&self, points: &[ArkG1], scalars: &[ArkFr]) -> ArkG1 {
        G1Routines::msm(points, scalars)
    }

    fn g2_add(&self, a: &ArkG2, b: &ArkG2) -> ArkG2 {
        *a + *b
    }

    fn g2_scalar_mul(&self, point: &ArkG2, scalar: &ArkFr) -> ArkG2 {
        ArkG2(point.0 * scalar.0)
    }

    fn g2_msm(&self, points: &[ArkG2], scalars: &[ArkFr]) -> ArkG2 {
        G2Routines::msm(points, scalars)
    }

    fn gt_mul(&self, lhs: &ArkGT, rhs: &ArkGT) -> ArkGT {
        ArkGT(lhs.0 * rhs.0)
    }

    fn gt_exp(&self, base: &ArkGT, scalar: &ArkFr) -> ArkGT {
        use ark_ff::Field;
        ArkGT(base.0.pow(scalar.0.into_bigint()))
    }

    fn pairing(&self, g1: &ArkG1, g2: &ArkG2) -> ArkGT {
        BN254::pair(g1, g2)
    }

    fn multi_pairing(&self, g1s: &[ArkG1], g2s: &[ArkG2]) -> ArkGT {
        BN254::multi_pair(g1s, g2s)
    }
}

/// Generate test data: AST graph and input values.
fn generate_test_data(
    sigma: usize,
) -> (AstGraph<BN254>, HashMap<ValueId, EvalResult<BN254>>) {
    let mut rng = thread_rng();

    // Setup sizes based on sigma (number of rounds)
    let nu = 4;
    let max_log_n = 2 * sigma.max(nu);
    let poly_size = 1 << (nu + sigma);
    let point_size = nu + sigma;

    let (prover_setup, verifier_setup) = setup::<BN254, _>(&mut rng, max_log_n);

    // Create polynomial
    let coefficients: Vec<ArkFr> = (0..poly_size).map(|_| ArkFr::random(&mut rng)).collect();
    let poly = ArkworksPolynomial::new(coefficients);

    let point: Vec<ArkFr> = (0..point_size).map(|_| ArkFr::random(&mut rng)).collect();

    // Commit
    let (tier_2, tier_1) = poly
        .commit::<BN254, G1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    // Prove
    let mut prover_transcript = Blake2bTranscript::new(b"dory-bench");
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

    // Run verification with AST tracing to get the graph
    let ctx = Rc::new(TestCtx::for_witness_gen_with_ast());
    let mut witness_transcript = Blake2bTranscript::new(b"dory-bench");

    verify_recursive::<_, BN254, G1Routines, G2Routines, _, _, _>(
        tier_2,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut witness_transcript,
        ctx.clone(),
    )
    .expect("Verification should succeed");

    let ctx_owned = Rc::try_unwrap(ctx).ok().expect("Should have sole ownership");
    let ast = ctx_owned.take_ast().expect("Should have AST");

    // Extract input values from the graph by evaluating input nodes
    // For benchmarking, we'll use dummy values for inputs
    let mut inputs = HashMap::new();
    for (idx, node) in ast.nodes.iter().enumerate() {
        if matches!(node.op, AstOp::Input { .. }) {
            let id = ValueId(idx as u32);
            // Generate appropriate dummy values based on type
            let value = match node.out_ty {
                dory_pcs::recursion::ast::ValueType::G1 => {
                    let g1 = ark_bn254::G1Projective::generator() * ark_bn254::Fr::from(rng.gen::<u64>());
                    EvalResult::G1(ArkG1(g1))
                }
                dory_pcs::recursion::ast::ValueType::G2 => {
                    let g2 = ark_bn254::G2Projective::generator() * ark_bn254::Fr::from(rng.gen::<u64>());
                    EvalResult::G2(ArkG2(g2))
                }
                dory_pcs::recursion::ast::ValueType::GT => {
                    EvalResult::GT(BN254::pair(
                        &ArkG1(ark_bn254::G1Projective::generator()),
                        &ArkG2(ark_bn254::G2Projective::generator()),
                    ))
                }
            };
            inputs.insert(id, value);
        }
    }

    (ast, inputs)
}

/// Sequential evaluation (baseline).
fn evaluate_sequential(
    graph: &AstGraph<BN254>,
    inputs: &HashMap<ValueId, EvalResult<BN254>>,
) -> HashMap<ValueId, EvalResult<BN254>> {
    let ops = ArkworksEvaluator;
    let mut results = inputs.clone();

    for (idx, node) in graph.nodes.iter().enumerate() {
        let id = ValueId(idx as u32);
        if results.contains_key(&id) {
            continue; // Already an input
        }

        let result = evaluate_node_seq(node, &results, &ops);
        results.insert(id, result);
    }

    results
}

fn evaluate_node_seq(
    node: &AstNode<BN254>,
    results: &HashMap<ValueId, EvalResult<BN254>>,
    ops: &ArkworksEvaluator,
) -> EvalResult<BN254> {
    let get = |id: ValueId| -> &EvalResult<BN254> {
        results.get(&id).expect("Dependency must exist")
    };

    match &node.op {
        AstOp::Input { .. } => panic!("Should not evaluate input nodes"),

        AstOp::G1Add { a, b, .. } => {
            EvalResult::G1(ops.g1_add(get(*a).as_g1(), get(*b).as_g1()))
        }

        AstOp::G1ScalarMul { point, scalar, .. } => {
            EvalResult::G1(ops.g1_scalar_mul(get(*point).as_g1(), &scalar.value))
        }

        AstOp::MsmG1 { points, scalars, .. } => {
            let pts: Vec<ArkG1> = points.iter().map(|id| get(*id).as_g1().clone()).collect();
            let scs: Vec<_> = scalars.iter().map(|s| s.value.clone()).collect();
            EvalResult::G1(ops.g1_msm(&pts, &scs))
        }

        AstOp::G2Add { a, b, .. } => {
            EvalResult::G2(ops.g2_add(get(*a).as_g2(), get(*b).as_g2()))
        }

        AstOp::G2ScalarMul { point, scalar, .. } => {
            EvalResult::G2(ops.g2_scalar_mul(get(*point).as_g2(), &scalar.value))
        }

        AstOp::MsmG2 { points, scalars, .. } => {
            let pts: Vec<ArkG2> = points.iter().map(|id| get(*id).as_g2().clone()).collect();
            let scs: Vec<_> = scalars.iter().map(|s| s.value.clone()).collect();
            EvalResult::G2(ops.g2_msm(&pts, &scs))
        }

        AstOp::GTMul { lhs, rhs, .. } => {
            EvalResult::GT(ops.gt_mul(get(*lhs).as_gt(), get(*rhs).as_gt()))
        }

        AstOp::GTExp { base, scalar, .. } => {
            EvalResult::GT(ops.gt_exp(get(*base).as_gt(), &scalar.value))
        }

        AstOp::Pairing { g1, g2, .. } => {
            EvalResult::GT(ops.pairing(get(*g1).as_g1(), get(*g2).as_g2()))
        }

        AstOp::MultiPairing { g1s, g2s, .. } => {
            let g1_vals: Vec<ArkG1> = g1s.iter().map(|id| get(*id).as_g1().clone()).collect();
            let g2_vals: Vec<ArkG2> = g2s.iter().map(|id| get(*id).as_g2().clone()).collect();
            EvalResult::GT(ops.multi_pairing(&g1_vals, &g2_vals))
        }
    }
}

/// Parallel evaluation using TaskExecutor.
fn evaluate_parallel(
    graph: &AstGraph<BN254>,
    inputs: &HashMap<ValueId, EvalResult<BN254>>,
) -> HashMap<ValueId, EvalResult<BN254>> {
    let provider = MapInputProvider { inputs: inputs.clone() };
    let ops = ArkworksEvaluator;

    let executor = TaskExecutor::new(graph, &provider, &ops);
    executor.execute()
}

fn bench_evaluation(c: &mut Criterion) {
    let mut group = c.benchmark_group("ast_evaluation");

    for sigma in [4, 6, 8] {
        let (graph, inputs) = generate_test_data(sigma);
        let num_nodes = graph.len();

        group.bench_with_input(
            BenchmarkId::new("sequential", format!("σ={}_nodes={}", sigma, num_nodes)),
            &(&graph, &inputs),
            |b, (graph, inputs)| {
                b.iter(|| {
                    black_box(evaluate_sequential(graph, inputs))
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("parallel", format!("σ={}_nodes={}", sigma, num_nodes)),
            &(&graph, &inputs),
            |b, (graph, inputs)| {
                b.iter(|| {
                    black_box(evaluate_parallel(graph, inputs))
                })
            },
        );
    }

    group.finish();
}

fn bench_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("parallel_scaling");

    // Test with σ=6 (moderate size)
    let (graph, inputs) = generate_test_data(6);
    let num_nodes = graph.len();

    println!("Benchmarking with {} nodes", num_nodes);

    group.bench_function("parallel_workstealing", |b| {
        b.iter(|| {
            black_box(evaluate_parallel(&graph, &inputs))
        })
    });

    group.bench_function("sequential_baseline", |b| {
        b.iter(|| {
            black_box(evaluate_sequential(&graph, &inputs))
        })
    });

    group.finish();
}

criterion_group!(benches, bench_evaluation, bench_scaling);
criterion_main!(benches);
