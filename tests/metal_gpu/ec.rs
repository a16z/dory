//! Tests for Metal GPU elliptic curve operations against arkworks CPU reference.
//!
//! G1: affine/Jacobian mixed addition, doubling, negation, full addition.
//! G2: same operations over Fp2.

use ark_bn254::{Fq as ArkFq, Fq2 as ArkFq2, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use dory_pcs::backends::metal::gpu::{
    Fp2Limbs, FpLimbs, G1AffineLimbs, G1JacobianLimbs, G2AffineLimbs, G2JacobianLimbs,
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

fn limbs_to_fq(l: &FpLimbs) -> ArkFq {
    let mut limbs64 = [0u64; 4];
    for i in 0..4 {
        limbs64[i] = l.limbs[2 * i] as u64 | ((l.limbs[2 * i + 1] as u64) << 32);
    }
    unsafe { std::mem::transmute::<[u64; 4], ArkFq>(limbs64) }
}

fn ark_fq2_to_limbs(f: &ArkFq2) -> Fp2Limbs {
    Fp2Limbs {
        c0: ark_fq_to_limbs(&f.c0),
        c1: ark_fq_to_limbs(&f.c1),
    }
}

fn limbs_to_fq2(l: &Fp2Limbs) -> ArkFq2 {
    ArkFq2::new(limbs_to_fq(&l.c0), limbs_to_fq(&l.c1))
}

fn g1_affine_to_gpu(p: &G1Affine) -> G1AffineLimbs {
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

fn gpu_jacobian_to_g1(j: &G1JacobianLimbs) -> G1Projective {
    G1Projective::new(limbs_to_fq(&j.x), limbs_to_fq(&j.y), limbs_to_fq(&j.z))
}

fn g2_affine_to_gpu(p: &G2Affine) -> G2AffineLimbs {
    if p.is_zero() {
        return G2AffineLimbs {
            x: Fp2Limbs {
                c0: FpLimbs { limbs: [0; 8] },
                c1: FpLimbs { limbs: [0; 8] },
            },
            y: Fp2Limbs {
                c0: FpLimbs { limbs: [0; 8] },
                c1: FpLimbs { limbs: [0; 8] },
            },
            is_inf: 1,
        };
    }
    G2AffineLimbs {
        x: ark_fq2_to_limbs(&p.x),
        y: ark_fq2_to_limbs(&p.y),
        is_inf: 0,
    }
}

fn gpu_jacobian_to_g2(j: &G2JacobianLimbs) -> G2Projective {
    G2Projective::new(limbs_to_fq2(&j.x), limbs_to_fq2(&j.y), limbs_to_fq2(&j.z))
}

// ── G1 tests ────────────────────────────────────────────────────────

#[test]
fn test_g1_mixed_add_random() {
    let mut gpu = MetalGpu::new();
    let mut rng = ark_std::test_rng();
    let n = 256;

    let ps: Vec<G1Affine> = (0..n)
        .map(|_| G1Projective::rand(&mut rng).into_affine())
        .collect();
    let qs: Vec<G1Affine> = (0..n)
        .map(|_| G1Projective::rand(&mut rng).into_affine())
        .collect();

    let ps_gpu: Vec<G1AffineLimbs> = ps.iter().map(|p| g1_affine_to_gpu(p)).collect();
    let qs_gpu: Vec<G1AffineLimbs> = qs.iter().map(|q| g1_affine_to_gpu(q)).collect();

    let results: Vec<G1JacobianLimbs> =
        gpu.run_binary_kernel_out("g1_mixed_add_test", &ps_gpu, &qs_gpu);

    for i in 0..n {
        let expected = G1Projective::from(ps[i]) + G1Projective::from(qs[i]);
        let got = gpu_jacobian_to_g1(&results[i]);
        assert_eq!(
            got.into_affine(),
            expected.into_affine(),
            "G1 mixed add mismatch at index {i}"
        );
    }
}

#[test]
fn test_g1_double_random() {
    let mut gpu = MetalGpu::new();
    let mut rng = ark_std::test_rng();
    let n = 256;

    let ps: Vec<G1Affine> = (0..n)
        .map(|_| G1Projective::rand(&mut rng).into_affine())
        .collect();

    let ps_gpu: Vec<G1AffineLimbs> = ps.iter().map(|p| g1_affine_to_gpu(p)).collect();
    let dummy: Vec<G1AffineLimbs> = ps_gpu.clone();

    let results: Vec<G1JacobianLimbs> =
        gpu.run_binary_kernel_out("g1_double_test", &ps_gpu, &dummy);

    for i in 0..n {
        let p = G1Projective::from(ps[i]);
        let expected = p + p;
        let got = gpu_jacobian_to_g1(&results[i]);
        assert_eq!(
            got.into_affine(),
            expected.into_affine(),
            "G1 double mismatch at index {i}"
        );
    }
}

#[test]
fn test_g1_full_add_random() {
    let mut gpu = MetalGpu::new();
    let mut rng = ark_std::test_rng();
    let n = 256;

    let ps: Vec<G1Affine> = (0..n)
        .map(|_| G1Projective::rand(&mut rng).into_affine())
        .collect();
    let qs: Vec<G1Affine> = (0..n)
        .map(|_| G1Projective::rand(&mut rng).into_affine())
        .collect();

    let ps_gpu: Vec<G1AffineLimbs> = ps.iter().map(|p| g1_affine_to_gpu(p)).collect();
    let qs_gpu: Vec<G1AffineLimbs> = qs.iter().map(|q| g1_affine_to_gpu(q)).collect();

    let results: Vec<G1JacobianLimbs> =
        gpu.run_binary_kernel_out("g1_full_add_test", &ps_gpu, &qs_gpu);

    for i in 0..n {
        let expected = G1Projective::from(ps[i]) + G1Projective::from(qs[i]);
        let got = gpu_jacobian_to_g1(&results[i]);
        assert_eq!(
            got.into_affine(),
            expected.into_affine(),
            "G1 full add mismatch at index {i}"
        );
    }
}

#[test]
fn test_g1_negate_random() {
    let mut gpu = MetalGpu::new();
    let mut rng = ark_std::test_rng();
    let n = 256;

    let ps: Vec<G1Affine> = (0..n)
        .map(|_| G1Projective::rand(&mut rng).into_affine())
        .collect();

    let ps_gpu: Vec<G1AffineLimbs> = ps.iter().map(|p| g1_affine_to_gpu(p)).collect();
    let dummy: Vec<G1AffineLimbs> = ps_gpu.clone();

    let results: Vec<G1AffineLimbs> = gpu.run_binary_kernel("g1_negate_test", &ps_gpu, &dummy);

    for i in 0..n {
        let expected = -ps[i];
        let got_x = limbs_to_fq(&results[i].x);
        let got_y = limbs_to_fq(&results[i].y);
        assert_eq!(got_x, expected.x, "G1 negate x mismatch at index {i}");
        assert_eq!(got_y, expected.y, "G1 negate y mismatch at index {i}");
        assert_eq!(results[i].is_inf, 0);
    }
}

#[test]
fn test_g1_full_add_same_point_doubles() {
    let mut gpu = MetalGpu::new();
    let mut rng = ark_std::test_rng();
    let n = 64;

    let ps: Vec<G1Affine> = (0..n)
        .map(|_| G1Projective::rand(&mut rng).into_affine())
        .collect();

    let ps_gpu: Vec<G1AffineLimbs> = ps.iter().map(|p| g1_affine_to_gpu(p)).collect();

    let results: Vec<G1JacobianLimbs> =
        gpu.run_binary_kernel_out("g1_full_add_test", &ps_gpu, &ps_gpu);

    for i in 0..n {
        let p = G1Projective::from(ps[i]);
        let expected = p + p;
        let got = gpu_jacobian_to_g1(&results[i]);
        assert_eq!(
            got.into_affine(),
            expected.into_affine(),
            "G1 full_add(P,P) != 2P at index {i}"
        );
    }
}

#[test]
fn test_g1_add_inverse_gives_identity() {
    let mut gpu = MetalGpu::new();
    let mut rng = ark_std::test_rng();
    let n = 64;

    let ps: Vec<G1Affine> = (0..n)
        .map(|_| G1Projective::rand(&mut rng).into_affine())
        .collect();
    let neg_ps: Vec<G1Affine> = ps.iter().map(|p| (-*p).into()).collect();

    let ps_gpu: Vec<G1AffineLimbs> = ps.iter().map(|p| g1_affine_to_gpu(p)).collect();
    let neg_gpu: Vec<G1AffineLimbs> = neg_ps.iter().map(|p| g1_affine_to_gpu(p)).collect();

    let results: Vec<G1JacobianLimbs> =
        gpu.run_binary_kernel_out("g1_full_add_test", &ps_gpu, &neg_gpu);

    for i in 0..n {
        let got = gpu_jacobian_to_g1(&results[i]);
        assert!(
            got.into_affine().is_zero(),
            "G1 P + (-P) should be identity at index {i}, got {:?}",
            got.into_affine()
        );
    }
}

#[test]
fn test_g1_mixed_add_with_identity() {
    let mut gpu = MetalGpu::new();
    let mut rng = ark_std::test_rng();

    let p = G1Projective::rand(&mut rng).into_affine();
    let inf = G1Affine::zero();

    let p_gpu = g1_affine_to_gpu(&p);
    let inf_gpu = g1_affine_to_gpu(&inf);

    // P + O = P
    let r1: Vec<G1JacobianLimbs> =
        gpu.run_binary_kernel_out("g1_mixed_add_test", &[p_gpu], &[inf_gpu]);
    let got1 = gpu_jacobian_to_g1(&r1[0]);
    assert_eq!(got1.into_affine(), p, "P + O should be P");

    // O + P = P (identity Jacobian accumulator, P affine addend)
    let r2: Vec<G1JacobianLimbs> =
        gpu.run_binary_kernel_out("g1_mixed_add_test", &[inf_gpu], &[p_gpu]);
    let got2 = gpu_jacobian_to_g1(&r2[0]);
    assert_eq!(got2.into_affine(), p, "O + P should be P");
}

// ── G2 tests ────────────────────────────────────────────────────────

#[test]
fn test_g2_mixed_add_random() {
    let mut gpu = MetalGpu::new();
    let mut rng = ark_std::test_rng();
    let n = 64;

    let ps: Vec<G2Affine> = (0..n)
        .map(|_| G2Projective::rand(&mut rng).into_affine())
        .collect();
    let qs: Vec<G2Affine> = (0..n)
        .map(|_| G2Projective::rand(&mut rng).into_affine())
        .collect();

    let ps_gpu: Vec<G2AffineLimbs> = ps.iter().map(|p| g2_affine_to_gpu(p)).collect();
    let qs_gpu: Vec<G2AffineLimbs> = qs.iter().map(|q| g2_affine_to_gpu(q)).collect();

    let results: Vec<G2JacobianLimbs> =
        gpu.run_binary_kernel_out("g2_mixed_add_test", &ps_gpu, &qs_gpu);

    for i in 0..n {
        let expected = G2Projective::from(ps[i]) + G2Projective::from(qs[i]);
        let got = gpu_jacobian_to_g2(&results[i]);
        assert_eq!(
            got.into_affine(),
            expected.into_affine(),
            "G2 mixed add mismatch at index {i}"
        );
    }
}

#[test]
fn test_g2_double_random() {
    let mut gpu = MetalGpu::new();
    let mut rng = ark_std::test_rng();
    let n = 64;

    let ps: Vec<G2Affine> = (0..n)
        .map(|_| G2Projective::rand(&mut rng).into_affine())
        .collect();

    let ps_gpu: Vec<G2AffineLimbs> = ps.iter().map(|p| g2_affine_to_gpu(p)).collect();
    let dummy: Vec<G2AffineLimbs> = ps_gpu.clone();

    let results: Vec<G2JacobianLimbs> =
        gpu.run_binary_kernel_out("g2_double_test", &ps_gpu, &dummy);

    for i in 0..n {
        let p = G2Projective::from(ps[i]);
        let expected = p + p;
        let got = gpu_jacobian_to_g2(&results[i]);
        assert_eq!(
            got.into_affine(),
            expected.into_affine(),
            "G2 double mismatch at index {i}"
        );
    }
}

#[test]
fn test_g2_full_add_random() {
    let mut gpu = MetalGpu::new();
    let mut rng = ark_std::test_rng();
    let n = 64;

    let ps: Vec<G2Affine> = (0..n)
        .map(|_| G2Projective::rand(&mut rng).into_affine())
        .collect();
    let qs: Vec<G2Affine> = (0..n)
        .map(|_| G2Projective::rand(&mut rng).into_affine())
        .collect();

    let ps_gpu: Vec<G2AffineLimbs> = ps.iter().map(|p| g2_affine_to_gpu(p)).collect();
    let qs_gpu: Vec<G2AffineLimbs> = qs.iter().map(|q| g2_affine_to_gpu(q)).collect();

    let results: Vec<G2JacobianLimbs> =
        gpu.run_binary_kernel_out("g2_full_add_test", &ps_gpu, &qs_gpu);

    for i in 0..n {
        let expected = G2Projective::from(ps[i]) + G2Projective::from(qs[i]);
        let got = gpu_jacobian_to_g2(&results[i]);
        assert_eq!(
            got.into_affine(),
            expected.into_affine(),
            "G2 full add mismatch at index {i}"
        );
    }
}

#[test]
fn test_g2_full_add_same_point_doubles() {
    let mut gpu = MetalGpu::new();
    let mut rng = ark_std::test_rng();
    let n = 64;

    let ps: Vec<G2Affine> = (0..n)
        .map(|_| G2Projective::rand(&mut rng).into_affine())
        .collect();

    let ps_gpu: Vec<G2AffineLimbs> = ps.iter().map(|p| g2_affine_to_gpu(p)).collect();

    let results: Vec<G2JacobianLimbs> =
        gpu.run_binary_kernel_out("g2_full_add_test", &ps_gpu, &ps_gpu);

    for i in 0..n {
        let p = G2Projective::from(ps[i]);
        let expected = p + p;
        let got = gpu_jacobian_to_g2(&results[i]);
        assert_eq!(
            got.into_affine(),
            expected.into_affine(),
            "G2 full_add(P,P) != 2P at index {i}"
        );
    }
}
