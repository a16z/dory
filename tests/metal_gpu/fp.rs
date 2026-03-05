//! Tests for Metal GPU Fp arithmetic against arkworks CPU reference.
//!
//! Converts arkworks Fp values (4×64-bit Montgomery limbs) to our 8×32-bit
//! representation, sends them to the GPU, runs the kernel, then compares
//! the GPU result against the arkworks CPU result.

use ark_bn254::Fq as ArkFq;
use ark_ff::UniformRand;
use dory_pcs::backends::metal::{gpu::FpLimbs, MetalGpu};

/// Convert an arkworks Fr (4×64-bit Montgomery limbs, LE) to our 8×32-bit LE representation.
///
/// arkworks stores field elements in Montgomery form as 4×u64 limbs.
/// We split each u64 into two u32s (low, high) to match the GPU layout.
fn ark_to_gpu(f: &ArkFq) -> FpLimbs {
    // arkworks Fp256 stores Montgomery-form limbs as [u64; 4] LE.
    // We transmute to get the raw representation, then split into 8×u32.
    let limbs64: [u64; 4] = unsafe { std::mem::transmute(*f) };

    let mut limbs = [0u32; 8];
    for (i, &w) in limbs64.iter().enumerate() {
        limbs[2 * i] = w as u32;
        limbs[2 * i + 1] = (w >> 32) as u32;
    }
    FpLimbs { limbs }
}

/// Convert our 8×32-bit LE limbs back to an arkworks Fr.
///
/// The GPU returns values in Montgomery form (fully reduced to [0, p)).
/// arkworks `Fr` internally stores Montgomery limbs, so we reconstruct
/// the BigInteger directly and use `from_bigint` — but that expects a
/// *normal* (non-Montgomery) integer.  Instead, we construct the Fr
/// from its raw Montgomery representation.
fn gpu_to_ark(fp: &FpLimbs) -> ArkFq {
    let mut limbs64 = [0u64; 4];
    for i in 0..4 {
        limbs64[i] = fp.limbs[2 * i] as u64 | ((fp.limbs[2 * i + 1] as u64) << 32);
    }
    // SAFETY: the GPU output is a valid Montgomery-form element in [0, p).
    // Fp256 stores its data as MontBackend wrapping a BigInt<4>, and the
    // in-memory layout is just the 4 u64 limbs.
    unsafe { std::mem::transmute::<[u64; 4], ArkFq>(limbs64) }
}

#[test]
fn test_fp_mul_single() {
    let mut gpu = MetalGpu::new();

    let mut rng = ark_std::test_rng();
    let a = ArkFq::rand(&mut rng);
    let b = ArkFq::rand(&mut rng);
    let expected = a * b;

    let a_gpu = ark_to_gpu(&a);
    let b_gpu = ark_to_gpu(&b);

    let result = gpu.run_binary_kernel("fp_mul_test", &[a_gpu], &[b_gpu]);
    let got = gpu_to_ark(&result[0]);

    assert_eq!(got, expected, "GPU fp_mul mismatch");
}

#[test]
fn test_fp_add_single() {
    let mut gpu = MetalGpu::new();

    let mut rng = ark_std::test_rng();
    let a = ArkFq::rand(&mut rng);
    let b = ArkFq::rand(&mut rng);
    let expected = a + b;

    let a_gpu = ark_to_gpu(&a);
    let b_gpu = ark_to_gpu(&b);

    let result = gpu.run_binary_kernel("fp_add_test", &[a_gpu], &[b_gpu]);
    let got = gpu_to_ark(&result[0]);

    assert_eq!(got, expected, "GPU fp_add mismatch");
}

#[test]
fn test_fp_sub_single() {
    let mut gpu = MetalGpu::new();

    let mut rng = ark_std::test_rng();
    let a = ArkFq::rand(&mut rng);
    let b = ArkFq::rand(&mut rng);
    let expected = a - b;

    let a_gpu = ark_to_gpu(&a);
    let b_gpu = ark_to_gpu(&b);

    let result = gpu.run_binary_kernel("fp_sub_test", &[a_gpu], &[b_gpu]);
    let got = gpu_to_ark(&result[0]);

    assert_eq!(got, expected, "GPU fp_sub mismatch");
}

#[test]
fn test_fp_mul_batch() {
    let mut gpu = MetalGpu::new();
    let mut rng = ark_std::test_rng();
    let n = 1024;

    let a_vals: Vec<ArkFq> = (0..n).map(|_| ArkFq::rand(&mut rng)).collect();
    let b_vals: Vec<ArkFq> = (0..n).map(|_| ArkFq::rand(&mut rng)).collect();
    let expected: Vec<ArkFq> = a_vals.iter().zip(&b_vals).map(|(a, b)| *a * *b).collect();

    let a_gpu: Vec<FpLimbs> = a_vals.iter().map(ark_to_gpu).collect();
    let b_gpu: Vec<FpLimbs> = b_vals.iter().map(ark_to_gpu).collect();

    let results = gpu.run_binary_kernel("fp_mul_test", &a_gpu, &b_gpu);

    for i in 0..n {
        let got = gpu_to_ark(&results[i]);
        assert_eq!(got, expected[i], "GPU fp_mul mismatch at index {i}");
    }
}

#[test]
fn test_fp_edge_cases() {
    let mut gpu = MetalGpu::new();

    let zero = ArkFq::from(0u64);
    let one = ArkFq::from(1u64);
    let p_minus_1 = -one;

    let cases: Vec<(ArkFq, ArkFq, &str)> = vec![
        (zero, zero, "0 * 0"),
        (one, one, "1 * 1"),
        (p_minus_1, p_minus_1, "(-1) * (-1)"),
        (p_minus_1, one, "(-1) * 1"),
        (zero, p_minus_1, "0 * (-1)"),
    ];

    for (a, b, label) in cases {
        let expected = a * b;
        let result = gpu.run_binary_kernel("fp_mul_test", &[ark_to_gpu(&a)], &[ark_to_gpu(&b)]);
        let got = gpu_to_ark(&result[0]);
        assert_eq!(got, expected, "GPU fp_mul edge case failed: {label}");
    }
}
