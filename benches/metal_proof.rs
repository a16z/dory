//! Metal GPU vs CPU proof generation benchmark
//!
//! Compares `MetalBN254` (GPU pairings) against `BN254` (CPU pairings)
//! using identical parameters: nu=12, sigma=12, 2^24 coefficients.
//!
//! Run with: cargo bench --bench metal_proof --features backends,metal-gpu,cache,parallel

#![allow(missing_docs)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dory_pcs::backends::arkworks::{
    ArkFr, ArkworksPolynomial, Blake2bTranscript, G1Routines, G2Routines, BN254,
};
use dory_pcs::backends::metal::MetalBN254;
use dory_pcs::mode::Transparent;
use dory_pcs::primitives::arithmetic::Field;
use dory_pcs::primitives::poly::Polynomial;
use dory_pcs::{prove, setup, verify};

#[cfg(feature = "cache")]
use dory_pcs::backends::arkworks::init_cache;

const NU: usize = 12;
const SIGMA: usize = 12;
const NUM_VARS: usize = NU + SIGMA;
const POLY_SIZE: usize = 1 << NUM_VARS;

fn setup_metal() -> (
    ArkworksPolynomial,
    Vec<ArkFr>,
    dory_pcs::setup::ProverSetup<MetalBN254>,
    dory_pcs::setup::VerifierSetup<MetalBN254>,
) {
    let (prover_setup, verifier_setup) = setup::<MetalBN254>(NUM_VARS);

    #[cfg(feature = "cache")]
    {
        if !dory_pcs::backends::arkworks::is_cached() {
            init_cache(&prover_setup.g1_vec, &prover_setup.g2_vec);
        }
    }

    let coefficients: Vec<ArkFr> = (0..POLY_SIZE).map(|_| ArkFr::random()).collect();
    let poly = ArkworksPolynomial::new(coefficients);
    let point: Vec<ArkFr> = (0..NUM_VARS).map(|_| ArkFr::random()).collect();

    (poly, point, prover_setup, verifier_setup)
}

fn setup_cpu() -> (
    ArkworksPolynomial,
    Vec<ArkFr>,
    dory_pcs::setup::ProverSetup<BN254>,
    dory_pcs::setup::VerifierSetup<BN254>,
) {
    let (prover_setup, verifier_setup) = setup::<BN254>(NUM_VARS);

    #[cfg(feature = "cache")]
    {
        if !dory_pcs::backends::arkworks::is_cached() {
            init_cache(&prover_setup.g1_vec, &prover_setup.g2_vec);
        }
    }

    let coefficients: Vec<ArkFr> = (0..POLY_SIZE).map(|_| ArkFr::random()).collect();
    let poly = ArkworksPolynomial::new(coefficients);
    let point: Vec<ArkFr> = (0..NUM_VARS).map(|_| ArkFr::random()).collect();

    (poly, point, prover_setup, verifier_setup)
}

fn bench_prove(c: &mut Criterion) {
    let mut group = c.benchmark_group("prove_2^24");
    group.sample_size(10);

    // CPU baseline
    {
        let (poly, point, prover_setup, _) = setup_cpu();
        let (_, tier_1, commit_blind) = poly
            .commit::<BN254, Transparent, G1Routines>(NU, SIGMA, &prover_setup)
            .unwrap();

        group.bench_function("cpu", |b| {
            b.iter(|| {
                let mut transcript = Blake2bTranscript::<BN254>::new(b"dory-bench");
                prove::<_, BN254, G1Routines, G2Routines, _, _, Transparent>(
                    black_box(&poly),
                    black_box(&point),
                    black_box(tier_1.clone()),
                    black_box(commit_blind),
                    black_box(NU),
                    black_box(SIGMA),
                    black_box(&prover_setup),
                    black_box(&mut transcript),
                )
                .unwrap()
            })
        });
    }

    // Metal GPU
    {
        let (poly, point, prover_setup, _) = setup_metal();
        let (_, tier_1, commit_blind) = poly
            .commit::<MetalBN254, Transparent, G1Routines>(NU, SIGMA, &prover_setup)
            .unwrap();

        group.bench_function("metal", |b| {
            b.iter(|| {
                let mut transcript = Blake2bTranscript::<MetalBN254>::new(b"dory-bench");
                prove::<_, MetalBN254, G1Routines, G2Routines, _, _, Transparent>(
                    black_box(&poly),
                    black_box(&point),
                    black_box(tier_1.clone()),
                    black_box(commit_blind),
                    black_box(NU),
                    black_box(SIGMA),
                    black_box(&prover_setup),
                    black_box(&mut transcript),
                )
                .unwrap()
            })
        });
    }

    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify_2^24");
    group.sample_size(10);

    // CPU baseline
    {
        let (poly, point, prover_setup, verifier_setup) = setup_cpu();
        let (tier_2, tier_1, commit_blind) = poly
            .commit::<BN254, Transparent, G1Routines>(NU, SIGMA, &prover_setup)
            .unwrap();

        let mut pt = Blake2bTranscript::<BN254>::new(b"dory-bench");
        let (proof, _) = prove::<_, BN254, G1Routines, G2Routines, _, _, Transparent>(
            &poly,
            &point,
            tier_1,
            commit_blind,
            NU,
            SIGMA,
            &prover_setup,
            &mut pt,
        )
        .unwrap();
        let evaluation = poly.evaluate(&point);

        group.bench_function("cpu", |b| {
            b.iter(|| {
                let mut transcript = Blake2bTranscript::<BN254>::new(b"dory-bench");
                verify::<_, BN254, G1Routines, G2Routines, _>(
                    black_box(tier_2),
                    black_box(evaluation),
                    black_box(&point),
                    black_box(&proof),
                    black_box(verifier_setup.clone()),
                    black_box(&mut transcript),
                )
                .unwrap()
            })
        });
    }

    // Metal GPU
    {
        let (poly, point, prover_setup, verifier_setup) = setup_metal();
        let (tier_2, tier_1, commit_blind) = poly
            .commit::<MetalBN254, Transparent, G1Routines>(NU, SIGMA, &prover_setup)
            .unwrap();

        let mut pt = Blake2bTranscript::<MetalBN254>::new(b"dory-bench");
        let (proof, _) = prove::<_, MetalBN254, G1Routines, G2Routines, _, _, Transparent>(
            &poly,
            &point,
            tier_1,
            commit_blind,
            NU,
            SIGMA,
            &prover_setup,
            &mut pt,
        )
        .unwrap();
        let evaluation = poly.evaluate(&point);

        group.bench_function("metal", |b| {
            b.iter(|| {
                let mut transcript = Blake2bTranscript::<MetalBN254>::new(b"dory-bench");
                verify::<_, MetalBN254, G1Routines, G2Routines, _>(
                    black_box(tier_2),
                    black_box(evaluation),
                    black_box(&point),
                    black_box(&proof),
                    black_box(verifier_setup.clone()),
                    black_box(&mut transcript),
                )
                .unwrap()
            })
        });
    }

    group.finish();
}

criterion_group!(benches, bench_prove, bench_verify);
criterion_main!(benches);
