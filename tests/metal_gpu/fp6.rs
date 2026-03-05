//! Tests for Metal GPU Fp6 arithmetic against arkworks CPU reference.

use ark_bn254::{Fq as ArkFq, Fq2 as ArkFq2, Fq6 as ArkFq6};
use ark_ff::UniformRand;
use dory_pcs::backends::metal::gpu::{Fp2Limbs, Fp6Limbs, FpLimbs};
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

fn ark_fq6_to_gpu(f: &ArkFq6) -> Fp6Limbs {
    Fp6Limbs {
        c0: ark_fq2_to_gpu(&f.c0),
        c1: ark_fq2_to_gpu(&f.c1),
        c2: ark_fq2_to_gpu(&f.c2),
    }
}

fn limbs_to_fq(l: &FpLimbs) -> ArkFq {
    let mut limbs64 = [0u64; 4];
    for i in 0..4 {
        limbs64[i] = l.limbs[2 * i] as u64 | ((l.limbs[2 * i + 1] as u64) << 32);
    }
    unsafe { std::mem::transmute::<[u64; 4], ArkFq>(limbs64) }
}

fn gpu_to_fq2(fp: &Fp2Limbs) -> ArkFq2 {
    ArkFq2::new(limbs_to_fq(&fp.c0), limbs_to_fq(&fp.c1))
}

fn gpu_to_fq6(fp: &Fp6Limbs) -> ArkFq6 {
    ArkFq6::new(gpu_to_fq2(&fp.c0), gpu_to_fq2(&fp.c1), gpu_to_fq2(&fp.c2))
}

#[test]
fn test_fp6_mul() {
    let mut gpu = MetalGpu::new();
    let mut rng = ark_std::test_rng();
    let n = 512;

    let a_vals: Vec<ArkFq6> = (0..n).map(|_| ArkFq6::rand(&mut rng)).collect();
    let b_vals: Vec<ArkFq6> = (0..n).map(|_| ArkFq6::rand(&mut rng)).collect();
    let expected: Vec<ArkFq6> = a_vals.iter().zip(&b_vals).map(|(a, b)| *a * *b).collect();

    let a_gpu: Vec<Fp6Limbs> = a_vals.iter().map(ark_fq6_to_gpu).collect();
    let b_gpu: Vec<Fp6Limbs> = b_vals.iter().map(ark_fq6_to_gpu).collect();

    let results: Vec<Fp6Limbs> = gpu.run_binary_kernel("fp6_mul_test", &a_gpu, &b_gpu);

    for i in 0..n {
        let got = gpu_to_fq6(&results[i]);
        assert_eq!(got, expected[i], "GPU fp6_mul mismatch at index {i}");
    }
}

#[test]
fn test_fp6_sqr() {
    let mut gpu = MetalGpu::new();
    let mut rng = ark_std::test_rng();
    let n = 512;

    let a_vals: Vec<ArkFq6> = (0..n).map(|_| ArkFq6::rand(&mut rng)).collect();
    let expected: Vec<ArkFq6> = a_vals.iter().map(|a| *a * *a).collect();

    let a_gpu: Vec<Fp6Limbs> = a_vals.iter().map(ark_fq6_to_gpu).collect();
    let dummy: Vec<Fp6Limbs> = a_gpu.clone();

    let results: Vec<Fp6Limbs> = gpu.run_binary_kernel("fp6_sqr_test", &a_gpu, &dummy);

    for i in 0..n {
        let got = gpu_to_fq6(&results[i]);
        assert_eq!(got, expected[i], "GPU fp6_sqr mismatch at index {i}");
    }
}

#[test]
fn test_fp6_add_sub() {
    let mut gpu = MetalGpu::new();
    let mut rng = ark_std::test_rng();
    let n = 256;

    let a_vals: Vec<ArkFq6> = (0..n).map(|_| ArkFq6::rand(&mut rng)).collect();
    let b_vals: Vec<ArkFq6> = (0..n).map(|_| ArkFq6::rand(&mut rng)).collect();

    let a_gpu: Vec<Fp6Limbs> = a_vals.iter().map(ark_fq6_to_gpu).collect();
    let b_gpu: Vec<Fp6Limbs> = b_vals.iter().map(ark_fq6_to_gpu).collect();

    let add_results: Vec<Fp6Limbs> = gpu.run_binary_kernel("fp6_add_test", &a_gpu, &b_gpu);
    for i in 0..n {
        let expected = a_vals[i] + b_vals[i];
        let got = gpu_to_fq6(&add_results[i]);
        assert_eq!(got, expected, "GPU fp6_add mismatch at index {i}");
    }

    let sub_results: Vec<Fp6Limbs> = gpu.run_binary_kernel("fp6_sub_test", &a_gpu, &b_gpu);
    for i in 0..n {
        let expected = a_vals[i] - b_vals[i];
        let got = gpu_to_fq6(&sub_results[i]);
        assert_eq!(got, expected, "GPU fp6_sub mismatch at index {i}");
    }
}

#[test]
fn test_fp6_edge_cases() {
    let mut gpu = MetalGpu::new();
    let mut rng = ark_std::test_rng();

    let zero = ArkFq6::from(0u64);
    let one = ArkFq6::from(1u64);
    let rand_a = ArkFq6::rand(&mut rng);

    let cases: Vec<(ArkFq6, ArkFq6, &str)> = vec![
        (zero, zero, "0 * 0"),
        (one, one, "1 * 1"),
        (rand_a, one, "a * 1 = a"),
        (rand_a, zero, "a * 0 = 0"),
    ];

    for (a, b, label) in cases {
        let expected = a * b;
        let result: Vec<Fp6Limbs> =
            gpu.run_binary_kernel("fp6_mul_test", &[ark_fq6_to_gpu(&a)], &[ark_fq6_to_gpu(&b)]);
        let got = gpu_to_fq6(&result[0]);
        assert_eq!(got, expected, "GPU fp6_mul edge case failed: {label}");
    }
}
