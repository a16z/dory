//! Equivalence tests for the optimized `DoryRoutines` implementations.
//!
//! The optimized routines (batch-normalized MSM, `parallel`-gated vector ops)
//! must return exactly the results of the naive per-element reference,
//! including the edge cases the optimizations could plausibly mishandle:
//! identity points (batch normalization skips their zero z-coordinates),
//! zero scalars, and empty inputs.

use dory_pcs::backends::arkworks::{ArkFr, ArkG1, ArkG2, G1Routines, G2Routines};
use dory_pcs::primitives::arithmetic::{DoryRoutines, Field, Group};

fn naive_msm<G: Group>(bases: &[G], scalars: &[G::Scalar]) -> G {
    bases
        .iter()
        .zip(scalars.iter())
        .fold(G::identity(), |acc, (base, scalar)| {
            acc.add(&base.scale(scalar))
        })
}

fn random_g1_fixture(len: usize) -> (Vec<ArkG1>, Vec<ArkFr>) {
    // Odd indices are scalar-mul outputs (z ≠ 1, the reduce-fold shape). On
    // G1 the even `random()` points come out normalized (z = 1, cofactor 1),
    // so the fixture mixes both coordinate shapes; on G2 `random()` is
    // already z ≠ 1 and the identity injected below covers z = 0 either way.
    let mut bases: Vec<ArkG1> = (0..len)
        .map(|i| {
            let p = ArkG1::random();
            if i % 2 == 1 {
                p.scale(&ArkFr::random())
            } else {
                p
            }
        })
        .collect();
    let mut scalars: Vec<ArkFr> = (0..len).map(|_| ArkFr::random()).collect();
    // Identity points and zero scalars exercise the batch-normalization and
    // parallel-iteration edge cases the random fixtures miss.
    bases[len / 2] = ArkG1::identity();
    scalars[len / 3] = ArkFr::zero();
    (bases, scalars)
}

fn random_g2_fixture(len: usize) -> (Vec<ArkG2>, Vec<ArkFr>) {
    let mut bases: Vec<ArkG2> = (0..len)
        .map(|i| {
            let p = ArkG2::random();
            if i % 2 == 1 {
                p.scale(&ArkFr::random())
            } else {
                p
            }
        })
        .collect();
    let mut scalars: Vec<ArkFr> = (0..len).map(|_| ArkFr::random()).collect();
    bases[len / 2] = ArkG2::identity();
    scalars[len / 3] = ArkFr::zero();
    (bases, scalars)
}

#[test]
fn g1_msm_matches_naive() {
    let (bases, scalars) = random_g1_fixture(33);
    assert_eq!(
        G1Routines::msm(&bases, &scalars),
        naive_msm(&bases, &scalars)
    );
}

#[test]
fn g2_msm_matches_naive() {
    let (bases, scalars) = random_g2_fixture(17);
    assert_eq!(
        G2Routines::msm(&bases, &scalars),
        naive_msm(&bases, &scalars)
    );
}

#[test]
fn msm_empty_is_identity() {
    assert_eq!(G1Routines::msm(&[], &[]), ArkG1::identity());
    assert_eq!(G2Routines::msm(&[], &[]), ArkG2::identity());
}

#[test]
fn msm_all_identity_bases() {
    let bases = vec![ArkG1::identity(); 7];
    let scalars: Vec<ArkFr> = (0..7).map(|_| ArkFr::random()).collect();
    assert_eq!(G1Routines::msm(&bases, &scalars), ArkG1::identity());
}

#[test]
fn msm_normalized_bases_fast_path() {
    // All bases with z = 1 (the setup-generator shape) take the free
    // `into_affine` conversion instead of batch normalization; the result
    // must be identical either way. Non-identity points only — an identity
    // (z = 0) would deliberately route to the batch branch.
    use ark_ec::CurveGroup;
    use ark_ff::One;
    let bases: Vec<ArkG1> = (0..9)
        .map(|_| ArkG1::random().scale(&ArkFr::random()))
        .collect();
    let normalized: Vec<ArkG1> = bases
        .iter()
        .map(|b| ArkG1(b.0.into_affine().into()))
        .collect();
    assert!(
        normalized.iter().all(|b| b.0.z.is_one()),
        "fixture must be normalized"
    );
    let scalars: Vec<ArkFr> = (0..9).map(|_| ArkFr::random()).collect();
    assert_eq!(
        G1Routines::msm(&normalized, &scalars),
        naive_msm(&normalized, &scalars)
    );
    assert_eq!(
        G1Routines::msm(&normalized, &scalars),
        G1Routines::msm(&bases, &scalars)
    );

    let bases_g2: Vec<ArkG2> = (0..9)
        .map(|_| ArkG2::random().scale(&ArkFr::random()))
        .collect();
    let normalized_g2: Vec<ArkG2> = bases_g2
        .iter()
        .map(|b| ArkG2(b.0.into_affine().into()))
        .collect();
    assert!(
        normalized_g2.iter().all(|b| b.0.z.is_one()),
        "fixture must be normalized"
    );
    assert_eq!(
        G2Routines::msm(&normalized_g2, &scalars),
        naive_msm(&normalized_g2, &scalars)
    );
    assert_eq!(
        G2Routines::msm(&normalized_g2, &scalars),
        G2Routines::msm(&bases_g2, &scalars)
    );
}

#[test]
fn g1_fixed_base_vector_scalar_mul_matches_naive() {
    let (bases, scalars) = random_g1_fixture(33);
    let expected: Vec<ArkG1> = scalars.iter().map(|s| bases[0].scale(s)).collect();
    assert_eq!(
        G1Routines::fixed_base_vector_scalar_mul(&bases[0], &scalars),
        expected
    );
    // Identity base: every product is the identity.
    assert_eq!(
        G1Routines::fixed_base_vector_scalar_mul(&ArkG1::identity(), &scalars),
        vec![ArkG1::identity(); scalars.len()]
    );
}

#[test]
fn g2_fixed_base_vector_scalar_mul_matches_naive() {
    let (bases, scalars) = random_g2_fixture(17);
    let expected: Vec<ArkG2> = scalars.iter().map(|s| bases[0].scale(s)).collect();
    assert_eq!(
        G2Routines::fixed_base_vector_scalar_mul(&bases[0], &scalars),
        expected
    );
    assert_eq!(
        G2Routines::fixed_base_vector_scalar_mul(&ArkG2::identity(), &scalars),
        vec![ArkG2::identity(); scalars.len()]
    );
}

#[test]
fn g1_fixed_scalar_mul_bases_then_add_matches_naive() {
    let (bases, _) = random_g1_fixture(33);
    let scalar = ArkFr::random();
    let (mut vs, _) = random_g1_fixture(33);
    let expected: Vec<ArkG1> = vs
        .iter()
        .zip(bases.iter())
        .map(|(v, base)| v.add(&base.scale(&scalar)))
        .collect();
    G1Routines::fixed_scalar_mul_bases_then_add(&bases, &mut vs, &scalar);
    assert_eq!(vs, expected);
}

#[test]
fn g2_fixed_scalar_mul_bases_then_add_matches_naive() {
    let (bases, _) = random_g2_fixture(17);
    let scalar = ArkFr::random();
    let (mut vs, _) = random_g2_fixture(17);
    let expected: Vec<ArkG2> = vs
        .iter()
        .zip(bases.iter())
        .map(|(v, base)| v.add(&base.scale(&scalar)))
        .collect();
    G2Routines::fixed_scalar_mul_bases_then_add(&bases, &mut vs, &scalar);
    assert_eq!(vs, expected);
}

#[test]
fn g1_fixed_scalar_mul_vs_then_add_matches_naive() {
    let (addends, _) = random_g1_fixture(33);
    let scalar = ArkFr::random();
    let (mut vs, _) = random_g1_fixture(33);
    let expected: Vec<ArkG1> = vs
        .iter()
        .zip(addends.iter())
        .map(|(v, addend)| v.scale(&scalar).add(addend))
        .collect();
    G1Routines::fixed_scalar_mul_vs_then_add(&mut vs, &addends, &scalar);
    assert_eq!(vs, expected);
}

#[test]
fn g2_fixed_scalar_mul_vs_then_add_matches_naive() {
    let (addends, _) = random_g2_fixture(17);
    let scalar = ArkFr::random();
    let (mut vs, _) = random_g2_fixture(17);
    let expected: Vec<ArkG2> = vs
        .iter()
        .zip(addends.iter())
        .map(|(v, addend)| v.scale(&scalar).add(addend))
        .collect();
    G2Routines::fixed_scalar_mul_vs_then_add(&mut vs, &addends, &scalar);
    assert_eq!(vs, expected);
}

#[test]
fn fold_field_vectors_matches_naive() {
    let scalar = ArkFr::random();
    let right: Vec<ArkFr> = (0..33).map(|_| ArkFr::random()).collect();
    let mut left: Vec<ArkFr> = (0..33).map(|_| ArkFr::random()).collect();
    left[4] = ArkFr::zero();
    let expected: Vec<ArkFr> = left
        .iter()
        .zip(right.iter())
        .map(|(l, r)| *l * scalar + *r)
        .collect();
    <G1Routines as DoryRoutines<ArkG1>>::fold_field_vectors(&mut left, &right, &scalar);
    assert_eq!(left, expected);

    let mut left_g2: Vec<ArkFr> = expected.clone();
    let expected_g2: Vec<ArkFr> = left_g2
        .iter()
        .zip(right.iter())
        .map(|(l, r)| *l * scalar + *r)
        .collect();
    <G2Routines as DoryRoutines<ArkG2>>::fold_field_vectors(&mut left_g2, &right, &scalar);
    assert_eq!(left_g2, expected_g2);
}
