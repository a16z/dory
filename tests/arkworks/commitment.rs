//! Polynomial commitment tests

use super::*;
use dory_pcs::primitives::poly::Polynomial;
use dory_pcs::Transparent;

#[test]
fn test_commit_small_polynomial() {
    let mut rng = rand::thread_rng();
    let setup = test_setup(4);
    let poly = random_polynomial(16);

    let nu = 2;
    let sigma = 2;

    let result = poly.commit::<BN254, Transparent, TestG1Routines, _>(nu, sigma, &setup, &mut rng);
    assert!(result.is_ok());

    let (_commitment, row_commitments, _) = result.unwrap();
    assert_eq!(row_commitments.len(), 1 << nu);
}

#[test]
fn test_commit_constant_polynomial() {
    let mut rng = rand::thread_rng();
    let setup = test_setup(4);
    let poly = constant_polynomial(42, 4);

    let nu = 2;
    let sigma = 2;

    let result = poly.commit::<BN254, Transparent, TestG1Routines, _>(nu, sigma, &setup, &mut rng);
    assert!(result.is_ok());

    let (_commitment, row_commitments, _) = result.unwrap();
    assert_eq!(row_commitments.len(), 1 << nu);
}

#[test]
fn test_commit_different_sizes() {
    let mut rng = rand::thread_rng();
    let setup = test_setup(8);

    let poly_4 = random_polynomial(4);
    let result = poly_4.commit::<BN254, Transparent, TestG1Routines, _>(1, 1, &setup, &mut rng);
    assert!(result.is_ok());

    let poly_16 = random_polynomial(16);
    let result = poly_16.commit::<BN254, Transparent, TestG1Routines, _>(2, 2, &setup, &mut rng);
    assert!(result.is_ok());

    let poly_64 = random_polynomial(64);
    let result = poly_64.commit::<BN254, Transparent, TestG1Routines, _>(3, 3, &setup, &mut rng);
    assert!(result.is_ok());
}

#[test]
fn test_commit_invalid_size() {
    let mut rng = rand::thread_rng();
    let setup = test_setup(4);
    let poly = random_polynomial(16);

    let nu = 3;
    let sigma = 2;

    let result = poly.commit::<BN254, Transparent, TestG1Routines, _>(nu, sigma, &setup, &mut rng);
    assert!(result.is_err());
}

#[test]
fn test_commit_deterministic() {
    let mut rng = rand::thread_rng();
    let setup = test_setup(6);

    let coefficients: Vec<ArkFr> = (0..16).map(|i| ArkFr::from_u64(i as u64)).collect();
    let poly1 = ArkworksPolynomial::new(coefficients.clone());
    let poly2 = ArkworksPolynomial::new(coefficients);

    let (comm1, _, _) = poly1
        .commit::<BN254, Transparent, TestG1Routines, _>(2, 2, &setup, &mut rng)
        .unwrap();
    let (comm2, _, _) = poly2
        .commit::<BN254, Transparent, TestG1Routines, _>(2, 2, &setup, &mut rng)
        .unwrap();

    assert_eq!(comm1, comm2);
}

#[test]
fn test_commit_different_polynomials() {
    let mut rng = rand::thread_rng();
    let setup = test_setup(6);

    let poly1 = random_polynomial(16);
    let poly2 = random_polynomial(16);

    let (comm1, _, _) = poly1
        .commit::<BN254, Transparent, TestG1Routines, _>(2, 2, &setup, &mut rng)
        .unwrap();
    let (comm2, _, _) = poly2
        .commit::<BN254, Transparent, TestG1Routines, _>(2, 2, &setup, &mut rng)
        .unwrap();

    assert_ne!(comm1, comm2);
}
