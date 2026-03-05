//! Tests for Metal GPU vector operations (AXPY kernels)
//! used in Dory reduce-and-fold, against arkworks CPU reference.

use ark_bn254::{Fq as ArkFq, Fq2 as ArkFq2, Fr as ArkFr, G1Projective, G2Projective};
use ark_ff::{PrimeField, UniformRand};
use dory_pcs::backends::metal::gpu::{
    Fp2Limbs, FpLimbs, FrLimbs, G1JacobianLimbs, G2JacobianLimbs,
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

/// Convert Fr to raw (non-Montgomery) limbs for EC scalar mul kernels.
fn ark_fr_to_raw_limbs(f: &ArkFr) -> FrLimbs {
    let bigint = f.into_bigint();
    let mut limbs = [0u32; 8];
    for (i, &w) in bigint.0.iter().enumerate() {
        limbs[2 * i] = w as u32;
        limbs[2 * i + 1] = (w >> 32) as u32;
    }
    FrLimbs { limbs }
}

fn g1_proj_to_jacobian(p: &G1Projective) -> G1JacobianLimbs {
    G1JacobianLimbs {
        x: ark_fq_to_limbs(&p.x),
        y: ark_fq_to_limbs(&p.y),
        z: ark_fq_to_limbs(&p.z),
    }
}

fn jacobian_to_g1_proj(j: &G1JacobianLimbs) -> G1Projective {
    G1Projective::new(limbs_to_fq(&j.x), limbs_to_fq(&j.y), limbs_to_fq(&j.z))
}

fn g2_proj_to_jacobian(p: &G2Projective) -> G2JacobianLimbs {
    G2JacobianLimbs {
        x: ark_fq2_to_limbs(&p.x),
        y: ark_fq2_to_limbs(&p.y),
        z: ark_fq2_to_limbs(&p.z),
    }
}

fn jacobian_to_g2_proj(j: &G2JacobianLimbs) -> G2Projective {
    G2Projective::new(limbs_to_fq2(&j.x), limbs_to_fq2(&j.y), limbs_to_fq2(&j.z))
}

// ── G1 scale_bases_add: out[i] = vs[i] + scalar * bases[i] ─────────

#[test]
fn test_g1_scale_bases_add() {
    let mut gpu = MetalGpu::new();
    let mut rng = ark_std::test_rng();
    let n = 16;

    let scalar = ArkFr::rand(&mut rng);
    let scalar_raw = ark_fr_to_raw_limbs(&scalar);

    let bases: Vec<G1Projective> = (0..n).map(|_| G1Projective::rand(&mut rng)).collect();
    let vs: Vec<G1Projective> = (0..n).map(|_| G1Projective::rand(&mut rng)).collect();

    let bases_gpu: Vec<G1JacobianLimbs> = bases.iter().map(g1_proj_to_jacobian).collect();
    let vs_gpu: Vec<G1JacobianLimbs> = vs.iter().map(g1_proj_to_jacobian).collect();

    let results = gpu.run_g1_scale_bases_add(&bases_gpu, &vs_gpu, &scalar_raw);

    for i in 0..n {
        let expected = vs[i] + bases[i] * scalar;
        let got = jacobian_to_g1_proj(&results[i]);
        assert_eq!(got, expected, "g1_scale_bases_add mismatch at index {i}");
    }
}

// ── G1 scale_vs_add: out[i] = scalar * vs[i] + addends[i] ──────────

#[test]
fn test_g1_scale_vs_add() {
    let mut gpu = MetalGpu::new();
    let mut rng = ark_std::test_rng();
    let n = 16;

    let scalar = ArkFr::rand(&mut rng);
    let scalar_raw = ark_fr_to_raw_limbs(&scalar);

    let vs: Vec<G1Projective> = (0..n).map(|_| G1Projective::rand(&mut rng)).collect();
    let addends: Vec<G1Projective> = (0..n).map(|_| G1Projective::rand(&mut rng)).collect();

    let vs_gpu: Vec<G1JacobianLimbs> = vs.iter().map(g1_proj_to_jacobian).collect();
    let addends_gpu: Vec<G1JacobianLimbs> = addends.iter().map(g1_proj_to_jacobian).collect();

    let results = gpu.run_g1_scale_vs_add(&vs_gpu, &addends_gpu, &scalar_raw);

    for i in 0..n {
        let expected = vs[i] * scalar + addends[i];
        let got = jacobian_to_g1_proj(&results[i]);
        assert_eq!(got, expected, "g1_scale_vs_add mismatch at index {i}");
    }
}

// ── G2 scale_bases_add ──────────────────────────────────────────────

#[test]
fn test_g2_scale_bases_add() {
    let mut gpu = MetalGpu::new();
    let mut rng = ark_std::test_rng();
    let n = 4;

    let scalar = ArkFr::rand(&mut rng);
    let scalar_raw = ark_fr_to_raw_limbs(&scalar);

    let bases: Vec<G2Projective> = (0..n).map(|_| G2Projective::rand(&mut rng)).collect();
    let vs: Vec<G2Projective> = (0..n).map(|_| G2Projective::rand(&mut rng)).collect();

    let bases_gpu: Vec<G2JacobianLimbs> = bases.iter().map(g2_proj_to_jacobian).collect();
    let vs_gpu: Vec<G2JacobianLimbs> = vs.iter().map(g2_proj_to_jacobian).collect();

    let results = gpu.run_g2_scale_bases_add(&bases_gpu, &vs_gpu, &scalar_raw);

    for i in 0..n {
        let expected = vs[i] + bases[i] * scalar;
        let got = jacobian_to_g2_proj(&results[i]);
        assert_eq!(got, expected, "g2_scale_bases_add mismatch at index {i}");
    }
}

// ── G2 scale_vs_add ─────────────────────────────────────────────────

#[test]
fn test_g2_scale_vs_add() {
    let mut gpu = MetalGpu::new();
    let mut rng = ark_std::test_rng();
    let n = 4;

    let scalar = ArkFr::rand(&mut rng);
    let scalar_raw = ark_fr_to_raw_limbs(&scalar);

    let vs: Vec<G2Projective> = (0..n).map(|_| G2Projective::rand(&mut rng)).collect();
    let addends: Vec<G2Projective> = (0..n).map(|_| G2Projective::rand(&mut rng)).collect();

    let vs_gpu: Vec<G2JacobianLimbs> = vs.iter().map(g2_proj_to_jacobian).collect();
    let addends_gpu: Vec<G2JacobianLimbs> = addends.iter().map(g2_proj_to_jacobian).collect();

    let results = gpu.run_g2_scale_vs_add(&vs_gpu, &addends_gpu, &scalar_raw);

    for i in 0..n {
        let expected = vs[i] * scalar + addends[i];
        let got = jacobian_to_g2_proj(&results[i]);
        assert_eq!(got, expected, "g2_scale_vs_add mismatch at index {i}");
    }
}

// ── Fr AXPY: out[i] = scalar * left[i] + right[i] ──────────────────

#[test]
fn test_fr_axpy() {
    let mut gpu = MetalGpu::new();
    let mut rng = ark_std::test_rng();
    let n = 256;

    let scalar = ArkFr::rand(&mut rng);
    let scalar_gpu = ark_fr_to_gpu(&scalar);

    let left: Vec<ArkFr> = (0..n).map(|_| ArkFr::rand(&mut rng)).collect();
    let right: Vec<ArkFr> = (0..n).map(|_| ArkFr::rand(&mut rng)).collect();

    let left_gpu: Vec<FrLimbs> = left.iter().map(ark_fr_to_gpu).collect();
    let right_gpu: Vec<FrLimbs> = right.iter().map(ark_fr_to_gpu).collect();

    let results = gpu.run_fr_axpy(&left_gpu, &right_gpu, &scalar_gpu);

    for i in 0..n {
        let expected = scalar * left[i] + right[i];
        let got = gpu_fr_to_ark(&results[i]);
        assert_eq!(got, expected, "fr_axpy mismatch at index {i}");
    }
}
