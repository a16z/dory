//! Tests for Metal GPU Fp12 arithmetic against arkworks CPU reference.

use ark_bn254::{Fq as ArkFq, Fq12 as ArkFq12, Fq2 as ArkFq2, Fq6 as ArkFq6};
use ark_ff::UniformRand;
use dory_pcs::backends::metal::gpu::{Fp12Limbs, Fp2Limbs, Fp6Limbs, FpLimbs};
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

fn ark_fq12_to_gpu(f: &ArkFq12) -> Fp12Limbs {
    Fp12Limbs {
        c0: ark_fq6_to_gpu(&f.c0),
        c1: ark_fq6_to_gpu(&f.c1),
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

fn gpu_to_fq12(fp: &Fp12Limbs) -> ArkFq12 {
    ArkFq12::new(gpu_to_fq6(&fp.c0), gpu_to_fq6(&fp.c1))
}

fn zero_fp2() -> Fp2Limbs {
    Fp2Limbs {
        c0: FpLimbs { limbs: [0; 8] },
        c1: FpLimbs { limbs: [0; 8] },
    }
}

fn zero_fp6() -> Fp6Limbs {
    Fp6Limbs {
        c0: zero_fp2(),
        c1: zero_fp2(),
        c2: zero_fp2(),
    }
}

#[test]
fn test_fp12_mul() {
    let mut gpu = MetalGpu::new();
    let mut rng = ark_std::test_rng();
    let n = 256;

    let a_vals: Vec<ArkFq12> = (0..n).map(|_| ArkFq12::rand(&mut rng)).collect();
    let b_vals: Vec<ArkFq12> = (0..n).map(|_| ArkFq12::rand(&mut rng)).collect();
    let expected: Vec<ArkFq12> = a_vals.iter().zip(&b_vals).map(|(a, b)| *a * *b).collect();

    let a_gpu: Vec<Fp12Limbs> = a_vals.iter().map(ark_fq12_to_gpu).collect();
    let b_gpu: Vec<Fp12Limbs> = b_vals.iter().map(ark_fq12_to_gpu).collect();

    let results: Vec<Fp12Limbs> = gpu.run_binary_kernel("fp12_mul_test", &a_gpu, &b_gpu);

    for i in 0..n {
        let got = gpu_to_fq12(&results[i]);
        assert_eq!(got, expected[i], "GPU fp12_mul mismatch at index {i}");
    }
}

#[test]
fn test_fp12_sqr() {
    let mut gpu = MetalGpu::new();
    let mut rng = ark_std::test_rng();
    let n = 256;

    let a_vals: Vec<ArkFq12> = (0..n).map(|_| ArkFq12::rand(&mut rng)).collect();
    let expected: Vec<ArkFq12> = a_vals.iter().map(|a| *a * *a).collect();

    let a_gpu: Vec<Fp12Limbs> = a_vals.iter().map(ark_fq12_to_gpu).collect();
    let dummy: Vec<Fp12Limbs> = a_gpu.clone();

    let results: Vec<Fp12Limbs> = gpu.run_binary_kernel("fp12_sqr_test", &a_gpu, &dummy);

    for i in 0..n {
        let got = gpu_to_fq12(&results[i]);
        assert_eq!(got, expected[i], "GPU fp12_sqr mismatch at index {i}");
    }
}

#[test]
fn test_fp12_mul_by_034() {
    let mut gpu = MetalGpu::new();
    let mut rng = ark_std::test_rng();
    let n = 512;

    let f_vals: Vec<ArkFq12> = (0..n).map(|_| ArkFq12::rand(&mut rng)).collect();
    let c0_vals: Vec<ArkFq2> = (0..n).map(|_| ArkFq2::rand(&mut rng)).collect();
    let c3_vals: Vec<ArkFq2> = (0..n).map(|_| ArkFq2::rand(&mut rng)).collect();
    let c4_vals: Vec<ArkFq2> = (0..n).map(|_| ArkFq2::rand(&mut rng)).collect();

    // Compute expected: f * sparse_element where sparse = (c0,0,0) + (c3,c4,0)·w
    let expected: Vec<ArkFq12> = (0..n)
        .map(|i| {
            let mut f = f_vals[i];
            f.mul_by_034(&c0_vals[i], &c3_vals[i], &c4_vals[i]);
            f
        })
        .collect();

    // GPU: a[i] = f_vals[i], b[i] packs (c0, c3, c4) in c0.c0, c0.c1, c0.c2
    let a_gpu: Vec<Fp12Limbs> = f_vals.iter().map(ark_fq12_to_gpu).collect();
    let b_gpu: Vec<Fp12Limbs> = (0..n)
        .map(|i| Fp12Limbs {
            c0: Fp6Limbs {
                c0: ark_fq2_to_gpu(&c0_vals[i]),
                c1: ark_fq2_to_gpu(&c3_vals[i]),
                c2: ark_fq2_to_gpu(&c4_vals[i]),
            },
            c1: zero_fp6(),
        })
        .collect();

    let results: Vec<Fp12Limbs> = gpu.run_binary_kernel("fp12_mul_by_034_test", &a_gpu, &b_gpu);

    for i in 0..n {
        let got = gpu_to_fq12(&results[i]);
        assert_eq!(
            got, expected[i],
            "GPU fp12_mul_by_034 mismatch at index {i}"
        );
    }
}

#[test]
fn test_fp12_edge_cases() {
    let mut gpu = MetalGpu::new();
    let mut rng = ark_std::test_rng();

    let zero = ArkFq12::from(0u64);
    let one = ArkFq12::from(1u64);
    let rand_a = ArkFq12::rand(&mut rng);

    let cases: Vec<(ArkFq12, ArkFq12, &str)> = vec![
        (zero, zero, "0 * 0"),
        (one, one, "1 * 1"),
        (rand_a, one, "a * 1 = a"),
        (rand_a, zero, "a * 0 = 0"),
    ];

    for (a, b, label) in cases {
        let expected = a * b;
        let result: Vec<Fp12Limbs> = gpu.run_binary_kernel(
            "fp12_mul_test",
            &[ark_fq12_to_gpu(&a)],
            &[ark_fq12_to_gpu(&b)],
        );
        let got = gpu_to_fq12(&result[0]);
        assert_eq!(got, expected, "GPU fp12_mul edge case failed: {label}");
    }
}
