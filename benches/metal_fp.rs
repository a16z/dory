//! Benchmark: Metal GPU Fp arithmetic vs arkworks CPU
//!
//! Measures throughput for batched Fp mul at sizes relevant to Dory
//! (multi-pairing inputs range from 2^14 to 2^19).
//!
//! The GPU benchmark pre-allocates buffers and caches the pipeline,
//! so we measure only dispatch + kernel execution + wait.
//!
//! Run with: cargo bench --bench metal_fp --features metal-gpu,arkworks

#![allow(missing_docs)]

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use ark_bn254::Fq as ArkFq;
use ark_ff::UniformRand;
use dory_pcs::backends::metal::gpu::FpLimbs;
use dory_pcs::backends::metal::MetalGpu;

fn ark_to_gpu(f: &ArkFq) -> FpLimbs {
    let limbs64: [u64; 4] = unsafe { std::mem::transmute(*f) };
    let mut limbs = [0u32; 8];
    for (i, &w) in limbs64.iter().enumerate() {
        limbs[2 * i] = w as u32;
        limbs[2 * i + 1] = (w >> 32) as u32;
    }
    FpLimbs { limbs }
}

const SIZES: &[usize] = &[
    1 << 16, // 64K  — crossover region
    1 << 18, // 256K
    1 << 19, // 512K — max practical multi-pairing size
    1 << 20, // 1M   — saturation test
];

fn bench_fp_mul(c: &mut Criterion) {
    let mut gpu = MetalGpu::new();
    let pipeline = gpu.pipeline("fp_mul_test").clone();
    let mut group = c.benchmark_group("fp_mul");

    for &n in SIZES {
        let mut rng = ark_std::test_rng();
        let a_ark: Vec<ArkFq> = (0..n).map(|_| ArkFq::rand(&mut rng)).collect();
        let b_ark: Vec<ArkFq> = (0..n).map(|_| ArkFq::rand(&mut rng)).collect();
        let a_gpu: Vec<FpLimbs> = a_ark.iter().map(ark_to_gpu).collect();
        let b_gpu: Vec<FpLimbs> = b_ark.iter().map(ark_to_gpu).collect();

        // Pre-allocate GPU buffers (shared memory — no copy cost on Apple Silicon)
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

fn bench_fp_add(c: &mut Criterion) {
    let mut gpu = MetalGpu::new();
    let pipeline = gpu.pipeline("fp_add_test").clone();
    let mut group = c.benchmark_group("fp_add");

    for &n in SIZES {
        let mut rng = ark_std::test_rng();
        let a_ark: Vec<ArkFq> = (0..n).map(|_| ArkFq::rand(&mut rng)).collect();
        let b_ark: Vec<ArkFq> = (0..n).map(|_| ArkFq::rand(&mut rng)).collect();
        let a_gpu: Vec<FpLimbs> = a_ark.iter().map(ark_to_gpu).collect();
        let b_gpu: Vec<FpLimbs> = b_ark.iter().map(ark_to_gpu).collect();

        let bufs = gpu.alloc_binary(&a_gpu, &b_gpu);

        group.throughput(Throughput::Elements(n as u64));

        group.bench_with_input(BenchmarkId::new("cpu", n), &n, |bench, _| {
            bench.iter(|| {
                for (a, b) in a_ark.iter().zip(&b_ark) {
                    black_box(*a + *b);
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

criterion_group!(benches, bench_fp_mul, bench_fp_add);
criterion_main!(benches);
