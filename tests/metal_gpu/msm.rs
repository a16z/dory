//! Tests for GPU G1 MSM against arkworks CPU reference.

use ark_bn254::{Fr as ArkFr, G1Affine, G1Projective};
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::{PrimeField, UniformRand};
use dory_pcs::backends::metal::gpu::{FpLimbs, G1AffineLimbs, G1JacobianLimbs};
use dory_pcs::backends::metal::MetalGpu;

// ── Conversion helpers ──────────────────────────────────────────────

fn ark_fq_to_limbs(f: &ark_bn254::Fq) -> FpLimbs {
    let limbs64: [u64; 4] = unsafe { std::mem::transmute(*f) };
    let mut limbs = [0u32; 8];
    for (i, &w) in limbs64.iter().enumerate() {
        limbs[2 * i] = w as u32;
        limbs[2 * i + 1] = (w >> 32) as u32;
    }
    FpLimbs { limbs }
}

fn limbs_to_fq(l: &FpLimbs) -> ark_bn254::Fq {
    let mut limbs64 = [0u64; 4];
    for i in 0..4 {
        limbs64[i] = l.limbs[2 * i] as u64 | ((l.limbs[2 * i + 1] as u64) << 32);
    }
    unsafe { std::mem::transmute::<[u64; 4], ark_bn254::Fq>(limbs64) }
}

fn g1_affine_to_gpu(p: &G1Affine) -> G1AffineLimbs {
    use ark_ec::AffineRepr;
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

/// Convert an arkworks Fr scalar to raw (non-Montgomery) 8×u32 LE limbs.
fn fr_to_raw_limbs(s: &ArkFr) -> [u32; 8] {
    let bigint = s.into_bigint();
    let mut limbs = [0u32; 8];
    for (i, &w) in bigint.0.iter().enumerate() {
        limbs[2 * i] = w as u32;
        limbs[2 * i + 1] = (w >> 32) as u32;
    }
    limbs
}

// ── Tests ────────────────────────────────────────────────────────────

#[test]
fn test_g1_msm_tiny() {
    let mut gpu = MetalGpu::new();
    let mut rng = ark_std::test_rng();
    let n = 4;

    let points: Vec<G1Affine> = (0..n)
        .map(|_| G1Projective::rand(&mut rng).into_affine())
        .collect();
    let scalars: Vec<ArkFr> = (0..n).map(|_| ArkFr::rand(&mut rng)).collect();

    let expected = G1Projective::msm(&points, &scalars).unwrap();

    let points_gpu: Vec<G1AffineLimbs> = points.iter().map(|p| g1_affine_to_gpu(p)).collect();
    let scalars_gpu: Vec<[u32; 8]> = scalars.iter().map(|s| fr_to_raw_limbs(s)).collect();

    let result = gpu.run_g1_msm(&points_gpu, &scalars_gpu);
    let got = gpu_jacobian_to_g1(&result);

    assert_eq!(
        got.into_affine(),
        expected.into_affine(),
        "MSM mismatch for n={n}"
    );
}

#[test]
fn test_g1_msm_single() {
    let mut gpu = MetalGpu::new();
    let mut rng = ark_std::test_rng();

    let p = G1Projective::rand(&mut rng).into_affine();
    let s = ArkFr::rand(&mut rng);

    let expected = G1Projective::msm(&[p], &[s]).unwrap();

    let result = gpu.run_g1_msm(&[g1_affine_to_gpu(&p)], &[fr_to_raw_limbs(&s)]);
    let got = gpu_jacobian_to_g1(&result);

    assert_eq!(
        got.into_affine(),
        expected.into_affine(),
        "MSM mismatch for n=1"
    );
}

#[test]
fn test_g1_msm_small() {
    let mut gpu = MetalGpu::new();
    let mut rng = ark_std::test_rng();
    let n = 64;

    let points: Vec<G1Affine> = (0..n)
        .map(|_| G1Projective::rand(&mut rng).into_affine())
        .collect();
    let scalars: Vec<ArkFr> = (0..n).map(|_| ArkFr::rand(&mut rng)).collect();

    let expected = G1Projective::msm(&points, &scalars).unwrap();

    let points_gpu: Vec<G1AffineLimbs> = points.iter().map(|p| g1_affine_to_gpu(p)).collect();
    let scalars_gpu: Vec<[u32; 8]> = scalars.iter().map(|s| fr_to_raw_limbs(s)).collect();

    let result = gpu.run_g1_msm(&points_gpu, &scalars_gpu);
    let got = gpu_jacobian_to_g1(&result);

    assert_eq!(
        got.into_affine(),
        expected.into_affine(),
        "MSM mismatch for n={n}"
    );
}

#[test]
fn test_g1_msm_medium() {
    let mut gpu = MetalGpu::new();
    let mut rng = ark_std::test_rng();
    let n = 1024;

    let points: Vec<G1Affine> = (0..n)
        .map(|_| G1Projective::rand(&mut rng).into_affine())
        .collect();
    let scalars: Vec<ArkFr> = (0..n).map(|_| ArkFr::rand(&mut rng)).collect();

    let expected = G1Projective::msm(&points, &scalars).unwrap();

    let points_gpu: Vec<G1AffineLimbs> = points.iter().map(|p| g1_affine_to_gpu(p)).collect();
    let scalars_gpu: Vec<[u32; 8]> = scalars.iter().map(|s| fr_to_raw_limbs(s)).collect();

    let result = gpu.run_g1_msm(&points_gpu, &scalars_gpu);
    let got = gpu_jacobian_to_g1(&result);

    assert_eq!(
        got.into_affine(),
        expected.into_affine(),
        "MSM mismatch for n={n}"
    );
}

#[test]
fn test_g1_msm_all_ones() {
    let mut gpu = MetalGpu::new();
    let mut rng = ark_std::test_rng();
    let n = 128;

    let points: Vec<G1Affine> = (0..n)
        .map(|_| G1Projective::rand(&mut rng).into_affine())
        .collect();
    let one = ArkFr::from(1u64);
    let scalars: Vec<ArkFr> = vec![one; n];

    let expected = G1Projective::msm(&points, &scalars).unwrap();

    let points_gpu: Vec<G1AffineLimbs> = points.iter().map(|p| g1_affine_to_gpu(p)).collect();
    let scalars_gpu: Vec<[u32; 8]> = scalars.iter().map(|s| fr_to_raw_limbs(s)).collect();

    let result = gpu.run_g1_msm(&points_gpu, &scalars_gpu);
    let got = gpu_jacobian_to_g1(&result);

    assert_eq!(
        got.into_affine(),
        expected.into_affine(),
        "MSM all-ones mismatch"
    );
}

#[test]
fn test_g1_msm_zero_scalars() {
    let mut gpu = MetalGpu::new();
    let mut rng = ark_std::test_rng();
    let n = 32;

    let points: Vec<G1Affine> = (0..n)
        .map(|_| G1Projective::rand(&mut rng).into_affine())
        .collect();
    let scalars: Vec<ArkFr> = vec![ArkFr::from(0u64); n];

    let expected = G1Projective::msm(&points, &scalars).unwrap();

    let points_gpu: Vec<G1AffineLimbs> = points.iter().map(|p| g1_affine_to_gpu(p)).collect();
    let scalars_gpu: Vec<[u32; 8]> = scalars.iter().map(|s| fr_to_raw_limbs(s)).collect();

    let result = gpu.run_g1_msm(&points_gpu, &scalars_gpu);
    let got = gpu_jacobian_to_g1(&result);

    assert_eq!(
        got.into_affine(),
        expected.into_affine(),
        "MSM zero-scalars should give identity"
    );
}

#[test]
fn test_g1_msm_mixed_zero_nonzero() {
    let mut gpu = MetalGpu::new();
    let mut rng = ark_std::test_rng();
    let n = 64;

    let points: Vec<G1Affine> = (0..n)
        .map(|_| G1Projective::rand(&mut rng).into_affine())
        .collect();
    let scalars: Vec<ArkFr> = (0..n)
        .map(|i| {
            if i % 3 == 0 {
                ArkFr::from(0u64)
            } else {
                ArkFr::rand(&mut rng)
            }
        })
        .collect();

    let expected = G1Projective::msm(&points, &scalars).unwrap();

    let points_gpu: Vec<G1AffineLimbs> = points.iter().map(|p| g1_affine_to_gpu(p)).collect();
    let scalars_gpu: Vec<[u32; 8]> = scalars.iter().map(|s| fr_to_raw_limbs(s)).collect();

    let result = gpu.run_g1_msm(&points_gpu, &scalars_gpu);
    let got = gpu_jacobian_to_g1(&result);

    assert_eq!(
        got.into_affine(),
        expected.into_affine(),
        "MSM mixed zero/nonzero mismatch"
    );
}

#[test]
fn test_g1_msm_scale() {
    let mut gpu = MetalGpu::new();
    let mut rng = ark_std::test_rng();

    for log_n in [8, 10, 12, 14] {
        let n = 1usize << log_n;
        let points: Vec<G1Affine> = (0..n)
            .map(|_| G1Projective::rand(&mut rng).into_affine())
            .collect();
        let scalars: Vec<ArkFr> = (0..n).map(|_| ArkFr::rand(&mut rng)).collect();

        let expected = G1Projective::msm(&points, &scalars).unwrap();

        let points_gpu: Vec<G1AffineLimbs> = points.iter().map(|p| g1_affine_to_gpu(p)).collect();
        let scalars_gpu: Vec<[u32; 8]> = scalars.iter().map(|s| fr_to_raw_limbs(s)).collect();

        let result = gpu.run_g1_msm(&points_gpu, &scalars_gpu);
        let got = gpu_jacobian_to_g1(&result);

        assert_eq!(
            got.into_affine(),
            expected.into_affine(),
            "MSM mismatch at n=2^{log_n} ({n} points)"
        );
    }
}
