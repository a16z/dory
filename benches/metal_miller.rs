//! Benchmark: Metal GPU Miller loop vs arkworks CPU
//!
//! Run with: cargo bench --bench metal_miller --features metal-gpu,arkworks

#![allow(missing_docs)]

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use ark_bn254::{
    Bn254, Fq as ArkFq, Fq2 as ArkFq2, G1Affine, G1Projective, G2Affine, G2Projective,
};
use ark_ec::{pairing::Pairing, CurveGroup};
use ark_ff::UniformRand;
use dory_pcs::backends::metal::gpu::{EllCoeffLimbs, Fp2Limbs, FpLimbs, NUM_ELL_COEFFS};
use dory_pcs::backends::metal::MetalGpu;

fn ark_fq_to_limbs(f: &ArkFq) -> FpLimbs {
    let limbs64: [u64; 4] = unsafe { std::mem::transmute(*f) };
    let mut limbs = [0u32; 8];
    for (i, &w) in limbs64.iter().enumerate() {
        limbs[2 * i] = w as u32;
        limbs[2 * i + 1] = (w >> 32) as u32;
    }
    FpLimbs { limbs }
}

fn ark_fq2_to_gpu(f: &ArkFq2) -> Fp2Limbs {
    Fp2Limbs {
        c0: ark_fq_to_limbs(&f.c0),
        c1: ark_fq_to_limbs(&f.c1),
    }
}

fn prepared_to_gpu(g2_prep: &<Bn254 as Pairing>::G2Prepared) -> Vec<EllCoeffLimbs> {
    g2_prep
        .ell_coeffs
        .iter()
        .map(|(c0, c1, c2)| EllCoeffLimbs {
            c0: ark_fq2_to_gpu(c0),
            c1: ark_fq2_to_gpu(c1),
            c2: ark_fq2_to_gpu(c2),
        })
        .collect()
}

const SIZES: &[usize] = &[1 << 10, 1 << 12, 1 << 14];

fn bench_miller_loop(c: &mut Criterion) {
    let mut gpu = MetalGpu::new();
    let mut group = c.benchmark_group("miller_loop");
    group.sample_size(10);

    for &n in SIZES {
        let mut rng = ark_std::test_rng();
        let g1s: Vec<G1Affine> = (0..n)
            .map(|_| G1Projective::rand(&mut rng).into_affine())
            .collect();
        let g2s: Vec<G2Affine> = (0..n)
            .map(|_| G2Projective::rand(&mut rng).into_affine())
            .collect();

        let g2_preps: Vec<_> = g2s
            .iter()
            .map(|q| <Bn254 as Pairing>::G2Prepared::from(*q))
            .collect();

        let mut g1_xy = Vec::with_capacity(2 * n);
        let mut all_coeffs = Vec::with_capacity(n * NUM_ELL_COEFFS);
        for i in 0..n {
            g1_xy.push(ark_fq_to_limbs(&g1s[i].x));
            g1_xy.push(ark_fq_to_limbs(&g1s[i].y));
            all_coeffs.extend_from_slice(&prepared_to_gpu(&g2_preps[i]));
        }

        // Pre-allocate GPU buffers
        let bufs = gpu.alloc_miller(&g1_xy, &all_coeffs);
        let pipeline = gpu.pipeline("miller_loop").clone();

        group.throughput(Throughput::Elements(n as u64));

        group.bench_with_input(BenchmarkId::new("cpu", n), &n, |bench, _| {
            bench.iter(|| {
                for i in 0..n {
                    black_box(Bn254::miller_loop(g1s[i], g2s[i]));
                }
            });
        });

        group.bench_with_input(BenchmarkId::new("gpu", n), &n, |bench, _| {
            bench.iter(|| {
                gpu.dispatch_miller(&pipeline, &bufs);
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_miller_loop);
criterion_main!(benches);
