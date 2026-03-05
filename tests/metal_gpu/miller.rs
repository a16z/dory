//! Tests for Metal GPU Miller loop against arkworks CPU reference.

use ark_bn254::{
    Bn254, Fq as ArkFq, Fq2 as ArkFq2, G1Affine, G1Projective, G2Affine, G2Projective,
};
use ark_ec::{pairing::Pairing, CurveGroup};
use ark_ff::UniformRand;
use dory_pcs::backends::metal::gpu::{
    EllCoeffLimbs, Fp12Limbs, Fp2Limbs, Fp6Limbs, FpLimbs, NUM_ELL_COEFFS,
};
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

fn gpu_to_fq6(fp: &Fp6Limbs) -> ark_bn254::Fq6 {
    ark_bn254::Fq6::new(gpu_to_fq2(&fp.c0), gpu_to_fq2(&fp.c1), gpu_to_fq2(&fp.c2))
}

fn gpu_to_fq12(fp: &Fp12Limbs) -> ark_bn254::Fq12 {
    ark_bn254::Fq12::new(gpu_to_fq6(&fp.c0), gpu_to_fq6(&fp.c1))
}

/// Convert arkworks G2Prepared ell_coeffs to GPU format.
fn prepared_to_gpu(g2_prep: &<Bn254 as Pairing>::G2Prepared) -> Vec<EllCoeffLimbs> {
    // Access the ell_coeffs field directly
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

#[test]
fn test_miller_loop_single() {
    let mut gpu = MetalGpu::new();
    let mut rng = ark_std::test_rng();

    let g1: G1Affine = G1Projective::rand(&mut rng).into_affine();
    let g2: G2Affine = G2Projective::rand(&mut rng).into_affine();

    // Arkworks reference: single Miller loop
    let expected = Bn254::miller_loop(g1, g2);

    // Prepare GPU inputs
    let g2_prep = <Bn254 as Pairing>::G2Prepared::from(g2);
    let coeffs = prepared_to_gpu(&g2_prep);
    assert_eq!(
        coeffs.len(),
        NUM_ELL_COEFFS,
        "unexpected number of ell_coeffs: {}",
        coeffs.len()
    );

    let g1_xy = vec![ark_fq_to_limbs(&g1.x), ark_fq_to_limbs(&g1.y)];

    let results = gpu.run_miller_loop(&g1_xy, &coeffs);
    assert_eq!(results.len(), 1);

    let got = gpu_to_fq12(&results[0]);
    assert_eq!(got, expected.0, "GPU Miller loop mismatch");
}

#[test]
fn test_miller_loop_batch() {
    let mut gpu = MetalGpu::new();
    let mut rng = ark_std::test_rng();
    let n = 64;

    let g1s: Vec<G1Affine> = (0..n)
        .map(|_| G1Projective::rand(&mut rng).into_affine())
        .collect();
    let g2s: Vec<G2Affine> = (0..n)
        .map(|_| G2Projective::rand(&mut rng).into_affine())
        .collect();

    // Build GPU inputs
    let mut g1_xy = Vec::with_capacity(2 * n);
    let mut all_coeffs = Vec::with_capacity(n * NUM_ELL_COEFFS);

    let g2_preps: Vec<_> = g2s
        .iter()
        .map(|q| <Bn254 as Pairing>::G2Prepared::from(*q))
        .collect();

    for i in 0..n {
        g1_xy.push(ark_fq_to_limbs(&g1s[i].x));
        g1_xy.push(ark_fq_to_limbs(&g1s[i].y));
        all_coeffs.extend_from_slice(&prepared_to_gpu(&g2_preps[i]));
    }

    let results = gpu.run_miller_loop(&g1_xy, &all_coeffs);
    assert_eq!(results.len(), n);

    // Also run each pair individually to isolate batch vs single-pair bugs
    for i in 0..n {
        let expected = Bn254::miller_loop(g1s[i], g2s[i]);

        // Run this single pair through the GPU
        let single_g1_xy = vec![ark_fq_to_limbs(&g1s[i].x), ark_fq_to_limbs(&g1s[i].y)];
        let single_coeffs = prepared_to_gpu(&g2_preps[i]);
        let single_result = gpu.run_miller_loop(&single_g1_xy, &single_coeffs);
        let got_single = gpu_to_fq12(&single_result[0]);

        let got_batch = gpu_to_fq12(&results[i]);

        if got_single != expected.0 {
            panic!("GPU Miller loop SINGLE mismatch at index {i}");
        }
        if got_batch != expected.0 {
            panic!("GPU Miller loop BATCH mismatch at index {i} (single was correct)");
        }
    }
}
