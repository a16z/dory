//! Benchmark: Metal GPU vector operations vs arkworks CPU
//!
//! Measures throughput for the three AXPY-pattern kernels used in Dory
//! reduce-and-fold: G1/G2 scale-and-add, and Fr field AXPY.
//!
//! Run with: cargo bench --bench metal_vec_ops --features metal-gpu,arkworks

#![allow(missing_docs)]

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use ark_bn254::{Fq as ArkFq, Fq2 as ArkFq2, Fr as ArkFr, G1Projective, G2Projective};
use ark_ff::{PrimeField, UniformRand};
use dory_pcs::backends::metal::glv::decompose_scalar_g1;
use dory_pcs::backends::metal::gpu::{
    Fp2Limbs, FpLimbs, FrLimbs, G1JacobianLimbs, G2JacobianLimbs,
};
use dory_pcs::backends::metal::MetalGpu;

// ── Conversion helpers ──────────────────────────────────────────────

fn ark_fq_to_limbs(f: &ArkFq) -> FpLimbs {
    let limbs64: [u64; 4] = unsafe { std::mem::transmute(*f) };
    let mut limbs = [0u32; 8];
    for (i, &w) in limbs64.iter().enumerate() {
        limbs[2 * i] = w as u32;
        limbs[2 * i + 1] = (w >> 32) as u32;
    }
    FpLimbs { limbs }
}

fn ark_fq2_to_limbs(f: &ArkFq2) -> Fp2Limbs {
    Fp2Limbs {
        c0: ark_fq_to_limbs(&f.c0),
        c1: ark_fq_to_limbs(&f.c1),
    }
}

fn ark_fr_to_gpu(f: &ArkFr) -> FrLimbs {
    let limbs64: [u64; 4] = unsafe { std::mem::transmute(*f) };
    let mut limbs = [0u32; 8];
    for (i, &w) in limbs64.iter().enumerate() {
        limbs[2 * i] = w as u32;
        limbs[2 * i + 1] = (w >> 32) as u32;
    }
    FrLimbs { limbs }
}

fn ark_fr_to_raw_limbs(f: &ArkFr) -> FrLimbs {
    let bigint = f.into_bigint();
    let mut limbs = [0u32; 8];
    for (i, &w) in bigint.0.iter().enumerate() {
        limbs[2 * i] = w as u32;
        limbs[2 * i + 1] = (w >> 32) as u32;
    }
    FrLimbs { limbs }
}

fn g1_proj_to_jacobian(p: &G1Projective) -> G1JacobianLimbs {
    G1JacobianLimbs {
        x: ark_fq_to_limbs(&p.x),
        y: ark_fq_to_limbs(&p.y),
        z: ark_fq_to_limbs(&p.z),
    }
}

fn g2_proj_to_jacobian(p: &G2Projective) -> G2JacobianLimbs {
    G2JacobianLimbs {
        x: ark_fq2_to_limbs(&p.x),
        y: ark_fq2_to_limbs(&p.y),
        z: ark_fq2_to_limbs(&p.z),
    }
}

// ── G1 scale_bases_add benchmark ────────────────────────────────────

const G1_SIZES: &[usize] = &[256, 4096];
const G2_SIZES: &[usize] = &[64, 1024];
const FR_SIZES: &[usize] = &[4096, 16384, 65536, 262144, 524288];

fn bench_g1_scale_bases_add(c: &mut Criterion) {
    let mut gpu = MetalGpu::new();
    let pipeline = gpu.pipeline("g1_scale_bases_add").clone();
    let mut group = c.benchmark_group("g1_scale_bases_add");
    group.sample_size(10);

    let mut rng = ark_std::test_rng();
    let scalar = ArkFr::rand(&mut rng);
    let scalar_raw = ark_fr_to_raw_limbs(&scalar);
    let glv = decompose_scalar_g1(&scalar_raw);

    for &n in G1_SIZES {
        let bases: Vec<G1Projective> = (0..n).map(|_| G1Projective::rand(&mut rng)).collect();
        let vs: Vec<G1Projective> = (0..n).map(|_| G1Projective::rand(&mut rng)).collect();

        let bases_gpu: Vec<G1JacobianLimbs> = bases.iter().map(g1_proj_to_jacobian).collect();
        let vs_gpu: Vec<G1JacobianLimbs> = vs.iter().map(g1_proj_to_jacobian).collect();

        let bufs = gpu.alloc_vec_op(&bases_gpu, &vs_gpu, &glv);
        group.throughput(Throughput::Elements(n as u64));

        group.bench_with_input(BenchmarkId::new("cpu", n), &n, |bench, _| {
            bench.iter(|| {
                for i in 0..n {
                    let _ = black_box(vs[i] + bases[i] * scalar);
                }
            });
        });

        group.bench_with_input(BenchmarkId::new("gpu", n), &n, |bench, _| {
            bench.iter(|| {
                gpu.dispatch_vec_op_bufs(&pipeline, &bufs);
            });
        });
    }

    group.finish();
}

fn bench_g1_scale_vs_add(c: &mut Criterion) {
    let mut gpu = MetalGpu::new();
    let pipeline = gpu.pipeline("g1_scale_vs_add").clone();
    let mut group = c.benchmark_group("g1_scale_vs_add");
    group.sample_size(10);

    let mut rng = ark_std::test_rng();
    let scalar = ArkFr::rand(&mut rng);
    let scalar_raw = ark_fr_to_raw_limbs(&scalar);
    let glv = decompose_scalar_g1(&scalar_raw);

    for &n in G1_SIZES {
        let vs: Vec<G1Projective> = (0..n).map(|_| G1Projective::rand(&mut rng)).collect();
        let addends: Vec<G1Projective> = (0..n).map(|_| G1Projective::rand(&mut rng)).collect();

        let vs_gpu: Vec<G1JacobianLimbs> = vs.iter().map(g1_proj_to_jacobian).collect();
        let addends_gpu: Vec<G1JacobianLimbs> = addends.iter().map(g1_proj_to_jacobian).collect();

        let bufs = gpu.alloc_vec_op(&vs_gpu, &addends_gpu, &glv);
        group.throughput(Throughput::Elements(n as u64));

        group.bench_with_input(BenchmarkId::new("cpu", n), &n, |bench, _| {
            bench.iter(|| {
                for i in 0..n {
                    let _ = black_box(vs[i] * scalar + addends[i]);
                }
            });
        });

        group.bench_with_input(BenchmarkId::new("gpu", n), &n, |bench, _| {
            bench.iter(|| {
                gpu.dispatch_vec_op_bufs(&pipeline, &bufs);
            });
        });
    }

    group.finish();
}

// ── G2 benchmarks ───────────────────────────────────────────────────

fn bench_g2_scale_bases_add(c: &mut Criterion) {
    let mut gpu = MetalGpu::new();
    let pipeline = gpu.pipeline("g2_scale_bases_add").clone();
    let mut group = c.benchmark_group("g2_scale_bases_add");
    group.sample_size(10);

    let mut rng = ark_std::test_rng();
    let scalar = ArkFr::rand(&mut rng);
    let scalar_raw = ark_fr_to_raw_limbs(&scalar);

    for &n in G2_SIZES {
        let bases: Vec<G2Projective> = (0..n).map(|_| G2Projective::rand(&mut rng)).collect();
        let vs: Vec<G2Projective> = (0..n).map(|_| G2Projective::rand(&mut rng)).collect();

        let bases_gpu: Vec<G2JacobianLimbs> = bases.iter().map(g2_proj_to_jacobian).collect();
        let vs_gpu: Vec<G2JacobianLimbs> = vs.iter().map(g2_proj_to_jacobian).collect();

        let bufs = gpu.alloc_vec_op(&bases_gpu, &vs_gpu, &scalar_raw);
        group.throughput(Throughput::Elements(n as u64));

        group.bench_with_input(BenchmarkId::new("cpu", n), &n, |bench, _| {
            bench.iter(|| {
                for i in 0..n {
                    let _ = black_box(vs[i] + bases[i] * scalar);
                }
            });
        });

        group.bench_with_input(BenchmarkId::new("gpu", n), &n, |bench, _| {
            bench.iter(|| {
                gpu.dispatch_vec_op_bufs(&pipeline, &bufs);
            });
        });
    }

    group.finish();
}

fn bench_g2_scale_vs_add(c: &mut Criterion) {
    let mut gpu = MetalGpu::new();
    let pipeline = gpu.pipeline("g2_scale_vs_add").clone();
    let mut group = c.benchmark_group("g2_scale_vs_add");
    group.sample_size(10);

    let mut rng = ark_std::test_rng();
    let scalar = ArkFr::rand(&mut rng);
    let scalar_raw = ark_fr_to_raw_limbs(&scalar);

    for &n in G2_SIZES {
        let vs: Vec<G2Projective> = (0..n).map(|_| G2Projective::rand(&mut rng)).collect();
        let addends: Vec<G2Projective> = (0..n).map(|_| G2Projective::rand(&mut rng)).collect();

        let vs_gpu: Vec<G2JacobianLimbs> = vs.iter().map(g2_proj_to_jacobian).collect();
        let addends_gpu: Vec<G2JacobianLimbs> = addends.iter().map(g2_proj_to_jacobian).collect();

        let bufs = gpu.alloc_vec_op(&vs_gpu, &addends_gpu, &scalar_raw);
        group.throughput(Throughput::Elements(n as u64));

        group.bench_with_input(BenchmarkId::new("cpu", n), &n, |bench, _| {
            bench.iter(|| {
                for i in 0..n {
                    let _ = black_box(vs[i] * scalar + addends[i]);
                }
            });
        });

        group.bench_with_input(BenchmarkId::new("gpu", n), &n, |bench, _| {
            bench.iter(|| {
                gpu.dispatch_vec_op_bufs(&pipeline, &bufs);
            });
        });
    }

    group.finish();
}

// ── Fr AXPY benchmark ───────────────────────────────────────────────

fn bench_fr_axpy(c: &mut Criterion) {
    let mut gpu = MetalGpu::new();
    let pipeline = gpu.pipeline("fr_axpy").clone();
    let mut group = c.benchmark_group("fr_axpy");

    let mut rng = ark_std::test_rng();
    let scalar = ArkFr::rand(&mut rng);
    let scalar_gpu = ark_fr_to_gpu(&scalar);

    for &n in FR_SIZES {
        let left: Vec<ArkFr> = (0..n).map(|_| ArkFr::rand(&mut rng)).collect();
        let right: Vec<ArkFr> = (0..n).map(|_| ArkFr::rand(&mut rng)).collect();

        let left_gpu: Vec<FrLimbs> = left.iter().map(ark_fr_to_gpu).collect();
        let right_gpu: Vec<FrLimbs> = right.iter().map(ark_fr_to_gpu).collect();

        let bufs = gpu.alloc_vec_op(&left_gpu, &right_gpu, &scalar_gpu);
        group.throughput(Throughput::Elements(n as u64));

        group.bench_with_input(BenchmarkId::new("cpu", n), &n, |bench, _| {
            bench.iter(|| {
                for i in 0..n {
                    let _ = black_box(scalar * left[i] + right[i]);
                }
            });
        });

        group.bench_with_input(BenchmarkId::new("gpu", n), &n, |bench, _| {
            bench.iter(|| {
                gpu.dispatch_vec_op_bufs(&pipeline, &bufs);
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_g1_scale_bases_add,
    bench_g1_scale_vs_add,
    bench_g2_scale_bases_add,
    bench_g2_scale_vs_add,
    bench_fr_axpy,
);
criterion_main!(benches);
