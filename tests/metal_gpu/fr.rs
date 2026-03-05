//! Tests for Metal GPU Fr (scalar field) arithmetic against arkworks CPU reference.

use ark_bn254::Fr as ArkFr;
use ark_ff::UniformRand;
use dory_pcs::backends::metal::{gpu::FrLimbs, MetalGpu};

fn ark_fr_to_gpu(f: &ArkFr) -> FrLimbs {
    let limbs64: [u64; 4] = unsafe { std::mem::transmute(*f) };
    let mut limbs = [0u32; 8];
    for (i, &w) in limbs64.iter().enumerate() {
        limbs[2 * i] = w as u32;
        limbs[2 * i + 1] = (w >> 32) as u32;
    }
    FrLimbs { limbs }
}

fn gpu_fr_to_ark(fp: &FrLimbs) -> ArkFr {
    let mut limbs64 = [0u64; 4];
    for i in 0..4 {
        limbs64[i] = fp.limbs[2 * i] as u64 | ((fp.limbs[2 * i + 1] as u64) << 32);
    }
    unsafe { std::mem::transmute::<[u64; 4], ArkFr>(limbs64) }
}

#[test]
fn test_fr_mul() {
    let mut gpu = MetalGpu::new();
    let mut rng = ark_std::test_rng();
    let n = 64;

    let a_ark: Vec<ArkFr> = (0..n).map(|_| ArkFr::rand(&mut rng)).collect();
    let b_ark: Vec<ArkFr> = (0..n).map(|_| ArkFr::rand(&mut rng)).collect();

    let a_gpu: Vec<FrLimbs> = a_ark.iter().map(ark_fr_to_gpu).collect();
    let b_gpu: Vec<FrLimbs> = b_ark.iter().map(ark_fr_to_gpu).collect();

    let results: Vec<FrLimbs> = gpu.run_binary_kernel("fr_mul_test", &a_gpu, &b_gpu);

    for i in 0..n {
        let expected = a_ark[i] * b_ark[i];
        let got = gpu_fr_to_ark(&results[i]);
        assert_eq!(got, expected, "fr_mul mismatch at index {i}");
    }
}

#[test]
fn test_fr_add() {
    let mut gpu = MetalGpu::new();
    let mut rng = ark_std::test_rng();
    let n = 64;

    let a_ark: Vec<ArkFr> = (0..n).map(|_| ArkFr::rand(&mut rng)).collect();
    let b_ark: Vec<ArkFr> = (0..n).map(|_| ArkFr::rand(&mut rng)).collect();

    let a_gpu: Vec<FrLimbs> = a_ark.iter().map(ark_fr_to_gpu).collect();
    let b_gpu: Vec<FrLimbs> = b_ark.iter().map(ark_fr_to_gpu).collect();

    let results: Vec<FrLimbs> = gpu.run_binary_kernel("fr_add_test", &a_gpu, &b_gpu);

    for i in 0..n {
        let expected = a_ark[i] + b_ark[i];
        let got = gpu_fr_to_ark(&results[i]);
        assert_eq!(got, expected, "fr_add mismatch at index {i}");
    }
}

#[test]
fn test_fr_sub() {
    let mut gpu = MetalGpu::new();
    let mut rng = ark_std::test_rng();
    let n = 64;

    let a_ark: Vec<ArkFr> = (0..n).map(|_| ArkFr::rand(&mut rng)).collect();
    let b_ark: Vec<ArkFr> = (0..n).map(|_| ArkFr::rand(&mut rng)).collect();

    let a_gpu: Vec<FrLimbs> = a_ark.iter().map(ark_fr_to_gpu).collect();
    let b_gpu: Vec<FrLimbs> = b_ark.iter().map(ark_fr_to_gpu).collect();

    let results: Vec<FrLimbs> = gpu.run_binary_kernel("fr_sub_test", &a_gpu, &b_gpu);

    for i in 0..n {
        let expected = a_ark[i] - b_ark[i];
        let got = gpu_fr_to_ark(&results[i]);
        assert_eq!(got, expected, "fr_sub mismatch at index {i}");
    }
}
