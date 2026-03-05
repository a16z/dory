//! Tests for Metal GPU Fp2 arithmetic against arkworks CPU reference.

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

fn gpu_to_ark(fp: &Fp2Limbs) -> ArkFq2 {
    let to_fq = |l: &FpLimbs| -> ark_bn254::Fq {
        let mut limbs64 = [0u64; 4];
        for i in 0..4 {
            limbs64[i] = l.limbs[2 * i] as u64 | ((l.limbs[2 * i + 1] as u64) << 32);
        }
        unsafe { std::mem::transmute::<[u64; 4], ark_bn254::Fq>(limbs64) }
    };
    ArkFq2::new(to_fq(&fp.c0), to_fq(&fp.c1))
}

#[test]
fn test_fp2_mul() {
    let mut gpu = MetalGpu::new();
    let mut rng = ark_std::test_rng();
    let n = 1024;

    let a_vals: Vec<ArkFq2> = (0..n).map(|_| ArkFq2::rand(&mut rng)).collect();
    let b_vals: Vec<ArkFq2> = (0..n).map(|_| ArkFq2::rand(&mut rng)).collect();
    let expected: Vec<ArkFq2> = a_vals.iter().zip(&b_vals).map(|(a, b)| *a * *b).collect();

    let a_gpu: Vec<Fp2Limbs> = a_vals.iter().map(ark_to_gpu).collect();
    let b_gpu: Vec<Fp2Limbs> = b_vals.iter().map(ark_to_gpu).collect();

    let results: Vec<Fp2Limbs> = gpu.run_binary_kernel("fp2_mul_test", &a_gpu, &b_gpu);

    for i in 0..n {
        let got = gpu_to_ark(&results[i]);
        assert_eq!(got, expected[i], "GPU fp2_mul mismatch at index {i}");
    }
}

#[test]
fn test_fp2_sqr() {
    let mut gpu = MetalGpu::new();
    let mut rng = ark_std::test_rng();
    let n = 1024;

    let a_vals: Vec<ArkFq2> = (0..n).map(|_| ArkFq2::rand(&mut rng)).collect();
    let expected: Vec<ArkFq2> = a_vals.iter().map(|a| *a * *a).collect();

    let a_gpu: Vec<Fp2Limbs> = a_vals.iter().map(ark_to_gpu).collect();
    // b is unused by the sqr kernel but we need to fill the buffer
    let dummy: Vec<Fp2Limbs> = a_gpu.clone();

    let results: Vec<Fp2Limbs> = gpu.run_binary_kernel("fp2_sqr_test", &a_gpu, &dummy);

    for i in 0..n {
        let got = gpu_to_ark(&results[i]);
        assert_eq!(got, expected[i], "GPU fp2_sqr mismatch at index {i}");
    }
}

#[test]
fn test_fp2_add_sub() {
    let mut gpu = MetalGpu::new();
    let mut rng = ark_std::test_rng();
    let n = 512;

    let a_vals: Vec<ArkFq2> = (0..n).map(|_| ArkFq2::rand(&mut rng)).collect();
    let b_vals: Vec<ArkFq2> = (0..n).map(|_| ArkFq2::rand(&mut rng)).collect();

    let a_gpu: Vec<Fp2Limbs> = a_vals.iter().map(ark_to_gpu).collect();
    let b_gpu: Vec<Fp2Limbs> = b_vals.iter().map(ark_to_gpu).collect();

    // Test add
    let add_results: Vec<Fp2Limbs> = gpu.run_binary_kernel("fp2_add_test", &a_gpu, &b_gpu);
    for i in 0..n {
        let expected = a_vals[i] + b_vals[i];
        let got = gpu_to_ark(&add_results[i]);
        assert_eq!(got, expected, "GPU fp2_add mismatch at index {i}");
    }

    // Test sub
    let sub_results: Vec<Fp2Limbs> = gpu.run_binary_kernel("fp2_sub_test", &a_gpu, &b_gpu);
    for i in 0..n {
        let expected = a_vals[i] - b_vals[i];
        let got = gpu_to_ark(&sub_results[i]);
        assert_eq!(got, expected, "GPU fp2_sub mismatch at index {i}");
    }
}

#[test]
fn test_fp2_edge_cases() {
    let mut gpu = MetalGpu::new();

    let zero = ArkFq2::new(ark_bn254::Fq::from(0u64), ark_bn254::Fq::from(0u64));
    let one = ArkFq2::new(ark_bn254::Fq::from(1u64), ark_bn254::Fq::from(0u64));
    let i = ArkFq2::new(ark_bn254::Fq::from(0u64), ark_bn254::Fq::from(1u64));

    let cases: Vec<(ArkFq2, ArkFq2, &str)> = vec![
        (zero, zero, "0 * 0"),
        (one, one, "1 * 1"),
        (i, i, "i * i = -1"),
        (one, i, "1 * i = i"),
    ];

    for (a, b, label) in cases {
        let expected = a * b;
        let result: Vec<Fp2Limbs> =
            gpu.run_binary_kernel("fp2_mul_test", &[ark_to_gpu(&a)], &[ark_to_gpu(&b)]);
        let got = gpu_to_ark(&result[0]);
        assert_eq!(got, expected, "GPU fp2_mul edge case failed: {label}");
    }
}
