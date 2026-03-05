//! Benchmark: Metal GPU Fp2 arithmetic vs arkworks CPU
//!
//! Run with: cargo bench --bench metal_fp2 --features metal-gpu,arkworks

#![allow(missing_docs)]

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use ark_bn254::Fq2 as ArkFq2;
use ark_ff::UniformRand;
use dory_pcs::backends::metal::gpu::{Fp2Limbs, FpLimbs};
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

fn ark_to_gpu(f: &ArkFq2) -> Fp2Limbs {
    Fp2Limbs {
        c0: ark_fq_to_limbs(&f.c0),
        c1: ark_fq_to_limbs(&f.c1),
    }
}

const SIZES: &[usize] = &[
    1 << 16, // 64K
    1 << 18, // 256K
    1 << 19, // 512K
    1 << 20, // 1M
];

fn bench_fp2_mul(c: &mut Criterion) {
    let mut gpu = MetalGpu::new();
    let pipeline = gpu.pipeline("fp2_mul_test").clone();
    let mut group = c.benchmark_group("fp2_mul");

    for &n in SIZES {
        let mut rng = ark_std::test_rng();
        let a_ark: Vec<ArkFq2> = (0..n).map(|_| ArkFq2::rand(&mut rng)).collect();
        let b_ark: Vec<ArkFq2> = (0..n).map(|_| ArkFq2::rand(&mut rng)).collect();
        let a_gpu: Vec<Fp2Limbs> = a_ark.iter().map(ark_to_gpu).collect();
        let b_gpu: Vec<Fp2Limbs> = b_ark.iter().map(ark_to_gpu).collect();

        let bufs = gpu.alloc_binary(&a_gpu, &b_gpu);
        group.throughput(Throughput::Elements(n as u64));

        group.bench_with_input(BenchmarkId::new("cpu", n), &n, |bench, _| {
            bench.iter(|| {
                for (a, b) in a_ark.iter().zip(&b_ark) {
                    black_box(*a * *b);
                }
            });
        });

        group.bench_with_input(BenchmarkId::new("gpu", n), &n, |bench, _| {
            bench.iter(|| {
                gpu.dispatch_binary(&pipeline, &bufs);
            });
        });
    }

    group.finish();
}

fn bench_fp2_sqr(c: &mut Criterion) {
    let mut gpu = MetalGpu::new();
    let pipeline = gpu.pipeline("fp2_sqr_test").clone();
    let mut group = c.benchmark_group("fp2_sqr");

    for &n in SIZES {
        let mut rng = ark_std::test_rng();
        let a_ark: Vec<ArkFq2> = (0..n).map(|_| ArkFq2::rand(&mut rng)).collect();
        let a_gpu: Vec<Fp2Limbs> = a_ark.iter().map(ark_to_gpu).collect();
        let dummy: Vec<Fp2Limbs> = a_gpu.clone();

        let bufs = gpu.alloc_binary(&a_gpu, &dummy);
        group.throughput(Throughput::Elements(n as u64));

        group.bench_with_input(BenchmarkId::new("cpu", n), &n, |bench, _| {
            bench.iter(|| {
                for a in &a_ark {
                    black_box(*a * *a);
                }
            });
        });

        group.bench_with_input(BenchmarkId::new("gpu", n), &n, |bench, _| {
            bench.iter(|| {
                gpu.dispatch_binary(&pipeline, &bufs);
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_fp2_mul, bench_fp2_sqr);
criterion_main!(benches);
