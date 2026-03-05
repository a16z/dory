//! Tests for the high-level `multi_miller_loop` and `multi_pair` API
//! against the arkworks CPU reference implementation.

use ark_bn254::{Bn254, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_ff::UniformRand;
use dory_pcs::backends::metal::MetalGpu;

#[test]
fn test_multi_miller_loop_matches_arkworks() {
    let mut gpu = MetalGpu::new();
    let mut rng = ark_std::test_rng();
    let n = 32;

    let g1s: Vec<G1Affine> = (0..n)
        .map(|_| G1Projective::rand(&mut rng).into_affine())
        .collect();
    let g2s: Vec<G2Affine> = (0..n)
        .map(|_| G2Projective::rand(&mut rng).into_affine())
        .collect();

    // Arkworks reference
    let ps_prep: Vec<<Bn254 as Pairing>::G1Prepared> =
        g1s.iter().copied().map(Into::into).collect();
    let qs_prep: Vec<<Bn254 as Pairing>::G2Prepared> =
        g2s.iter().copied().map(Into::into).collect();
    let expected = Bn254::multi_miller_loop(ps_prep, qs_prep);

    // GPU
    let got = gpu.multi_miller_loop(&g1s, &g2s);

    assert_eq!(got.0, expected.0, "multi_miller_loop mismatch");
}

#[test]
fn test_multi_pair_matches_arkworks() {
    let mut gpu = MetalGpu::new();
    let mut rng = ark_std::test_rng();
    let n = 16;

    let g1s: Vec<G1Affine> = (0..n)
        .map(|_| G1Projective::rand(&mut rng).into_affine())
        .collect();
    let g2s: Vec<G2Affine> = (0..n)
        .map(|_| G2Projective::rand(&mut rng).into_affine())
        .collect();

    // Arkworks reference
    let ps_prep: Vec<<Bn254 as Pairing>::G1Prepared> =
        g1s.iter().copied().map(Into::into).collect();
    let qs_prep: Vec<<Bn254 as Pairing>::G2Prepared> =
        g2s.iter().copied().map(Into::into).collect();
    let expected = Bn254::final_exponentiation(Bn254::multi_miller_loop(ps_prep, qs_prep))
        .expect("final exp should not fail");

    // GPU
    let got = gpu.multi_pair(&g1s, &g2s);

    assert_eq!(got, expected, "multi_pair mismatch");
}

#[test]
fn test_multi_miller_loop_prepared_matches() {
    let mut gpu = MetalGpu::new();
    let mut rng = ark_std::test_rng();
    let n = 8;

    let g1s: Vec<G1Affine> = (0..n)
        .map(|_| G1Projective::rand(&mut rng).into_affine())
        .collect();
    let g2s: Vec<G2Affine> = (0..n)
        .map(|_| G2Projective::rand(&mut rng).into_affine())
        .collect();

    let g2_preps: Vec<<Bn254 as Pairing>::G2Prepared> =
        g2s.iter().copied().map(Into::into).collect();

    // Compare prepared vs unprepared GPU paths
    let from_unprepared = gpu.multi_miller_loop(&g1s, &g2s);
    let from_prepared = gpu.multi_miller_loop_prepared(&g1s, &g2_preps);

    assert_eq!(
        from_unprepared.0, from_prepared.0,
        "prepared vs unprepared mismatch"
    );
}

#[test]
fn test_multi_miller_loop_single_pair() {
    let mut gpu = MetalGpu::new();
    let mut rng = ark_std::test_rng();

    let g1: G1Affine = G1Projective::rand(&mut rng).into_affine();
    let g2: G2Affine = G2Projective::rand(&mut rng).into_affine();

    let expected = Bn254::miller_loop(g1, g2);
    let got = gpu.multi_miller_loop(&[g1], &[g2]);

    assert_eq!(got.0, expected.0, "single-pair multi_miller_loop mismatch");
}
