//! Benchmark: Metal GPU MSM vs arkworks CPU MSM
//!
//! Run with: cargo bench --bench metal_msm --features metal-gpu,arkworks
//!
//! Two benchmark groups:
//!   1. `msm_gpu_vs_cpu` — GPU vs CPU at each size (finds crossover point)
//!   2. `msm_window_sweep` — GPU MSM with varying window size c (finds optimal c)

#![allow(missing_docs)]

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::time::Duration;

use ark_bn254::{Fr as ArkFr, G1Affine, G1Projective};
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::{PrimeField, UniformRand};
use dory_pcs::backends::metal::gpu::{FpLimbs, G1AffineLimbs, MsmParams};
use dory_pcs::backends::metal::MetalGpu;

fn ark_fq_to_limbs(f: &ark_bn254::Fq) -> FpLimbs {
    let limbs64: [u64; 4] = unsafe { std::mem::transmute(*f) };
    let mut limbs = [0u32; 8];
    for (i, &w) in limbs64.iter().enumerate() {
        limbs[2 * i] = w as u32;
        limbs[2 * i + 1] = (w >> 32) as u32;
    }
    FpLimbs { limbs }
}

fn g1_affine_to_gpu(p: &G1Affine) -> G1AffineLimbs {
    use ark_ec::AffineRepr;
    if p.is_zero() {
        return G1AffineLimbs {
            x: FpLimbs { limbs: [0; 8] },
            y: FpLimbs { limbs: [0; 8] },
            is_inf: 1,
        };
    }
    G1AffineLimbs {
        x: ark_fq_to_limbs(&p.x),
        y: ark_fq_to_limbs(&p.y),
        is_inf: 0,
    }
}

fn fr_to_raw_limbs(s: &ArkFr) -> [u32; 8] {
    let bigint = s.into_bigint();
    let mut limbs = [0u32; 8];
    for (i, &w) in bigint.0.iter().enumerate() {
        limbs[2 * i] = w as u32;
        limbs[2 * i + 1] = (w >> 32) as u32;
    }
    limbs
}

struct MsmTestData {
    points_ark: Vec<G1Affine>,
    scalars_ark: Vec<ArkFr>,
    points_gpu: Vec<G1AffineLimbs>,
    scalars_gpu: Vec<[u32; 8]>,
}

/// Generate one large dataset at `max_n` and slice it for smaller sizes.
fn gen_msm_data(max_n: usize) -> MsmTestData {
    let mut rng = ark_std::test_rng();
    let points_ark: Vec<G1Affine> = (0..max_n)
        .map(|_| G1Projective::rand(&mut rng).into_affine())
        .collect();
    let scalars_ark: Vec<ArkFr> = (0..max_n).map(|_| ArkFr::rand(&mut rng)).collect();
    let points_gpu: Vec<G1AffineLimbs> = points_ark.iter().map(|p| g1_affine_to_gpu(p)).collect();
    let scalars_gpu: Vec<[u32; 8]> = scalars_ark.iter().map(|s| fr_to_raw_limbs(s)).collect();
    MsmTestData {
        points_ark,
        scalars_ark,
        points_gpu,
        scalars_gpu,
    }
}

// ── Group 1: GPU vs CPU crossover ────────────────────────────────────

const SIZES: &[usize] = &[1 << 8, 1 << 10, 1 << 12, 1 << 14, 1 << 16, 1 << 18];

fn bench_gpu_vs_cpu(c: &mut Criterion) {
    let max_n = *SIZES.last().unwrap();
    eprintln!("Generating {max_n} random points + scalars...");
    let data = gen_msm_data(max_n);
    eprintln!("Data generation complete.");

    let mut gpu = MetalGpu::new();
    let mut group = c.benchmark_group("msm_gpu_vs_cpu");
    group.sample_size(10);
    group.warm_up_time(Duration::from_millis(500));
    group.measurement_time(Duration::from_secs(5));

    for &n in SIZES {
        let pts_ark = &data.points_ark[..n];
        let sca_ark = &data.scalars_ark[..n];
        let pts_gpu = &data.points_gpu[..n];
        let sca_gpu = &data.scalars_gpu[..n];

        // CPU
        group.bench_with_input(BenchmarkId::new("cpu", n), &n, |bench, _| {
            bench.iter(|| black_box(G1Projective::msm(pts_ark, sca_ark).unwrap()));
        });

        // GPU (dispatch only, pre-allocated)
        let optimal_c = MsmParams::optimal_c(n as u32);
        let bufs = gpu.alloc_msm(pts_gpu, sca_gpu, optimal_c);

        group.bench_with_input(BenchmarkId::new("gpu", n), &n, |bench, _| {
            bench.iter(|| {
                gpu.dispatch_msm(&bufs);
                black_box(MetalGpu::read_msm_result(&bufs));
            });
        });

        // GPU end-to-end (alloc + dispatch + read)
        group.bench_with_input(BenchmarkId::new("gpu_e2e", n), &n, |bench, _| {
            bench.iter(|| black_box(gpu.run_g1_msm(pts_gpu, sca_gpu)));
        });
    }

    group.finish();
}

// ── Group 2: Window size sweep ───────────────────────────────────────

const SWEEP_SIZES: &[usize] = &[1 << 14, 1 << 16, 1 << 18];
const WINDOW_SIZES: &[u32] = &[8, 10, 12, 14, 16];

fn bench_window_sweep(c: &mut Criterion) {
    let max_n = *SWEEP_SIZES.last().unwrap();
    eprintln!("Window sweep: generating {max_n} random points + scalars...");
    let data = gen_msm_data(max_n);
    eprintln!("Data generation complete.");

    let mut gpu = MetalGpu::new();
    let mut group = c.benchmark_group("msm_window_sweep");
    group.sample_size(10);
    group.warm_up_time(Duration::from_millis(500));
    group.measurement_time(Duration::from_secs(5));

    for &n in SWEEP_SIZES {
        let pts_gpu = &data.points_gpu[..n];
        let sca_gpu = &data.scalars_gpu[..n];

        for &w in WINDOW_SIZES {
            let bufs = gpu.alloc_msm(pts_gpu, sca_gpu, w);

            group.bench_with_input(BenchmarkId::new(format!("c={w}"), n), &n, |bench, _| {
                bench.iter(|| {
                    gpu.dispatch_msm(&bufs);
                    black_box(MetalGpu::read_msm_result(&bufs));
                });
            });
        }
    }

    group.finish();
}

criterion_group!(benches, bench_gpu_vs_cpu, bench_window_sweep);
criterion_main!(benches);
