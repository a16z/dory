//! Polynomial commitment tests

use super::*;
use dory_pcs::primitives::poly::Polynomial;

#[test]
fn test_commit_small_polynomial() {
    let setup = test_setup(4);
    let poly = random_polynomial(16);

    let nu = 2;
    let sigma = 2;

    let result = poly.commit::<BN254, TestG1Routines>(nu, sigma, &setup);
    assert!(result.is_ok());

    let (_commitment, row_commitments) = result.unwrap();
    assert_eq!(row_commitments.len(), 1 << nu);
}

#[test]
fn test_commit_constant_polynomial() {
    let setup = test_setup(4);
    let poly = constant_polynomial(42, 4);

    let nu = 2;
    let sigma = 2;

    let result = poly.commit::<BN254, TestG1Routines>(nu, sigma, &setup);
    assert!(result.is_ok());

    let (_commitment, row_commitments) = result.unwrap();
    assert_eq!(row_commitments.len(), 1 << nu);
}

#[test]
fn test_commit_different_sizes() {
    let setup = test_setup(8);

    let poly_4 = random_polynomial(4);
    let result = poly_4.commit::<BN254, TestG1Routines>(1, 1, &setup);
    assert!(result.is_ok());

    let poly_16 = random_polynomial(16);
    let result = poly_16.commit::<BN254, TestG1Routines>(2, 2, &setup);
    assert!(result.is_ok());

    let poly_64 = random_polynomial(64);
    let result = poly_64.commit::<BN254, TestG1Routines>(3, 3, &setup);
    assert!(result.is_ok());
}

#[test]
fn test_commit_invalid_size() {
    let setup = test_setup(4);
    let poly = random_polynomial(16);

    let nu = 3;
    let sigma = 2;

    let result = poly.commit::<BN254, TestG1Routines>(nu, sigma, &setup);
    assert!(result.is_err());
}

#[test]
fn test_commit_deterministic() {
    let setup = test_setup(6);

    let coefficients: Vec<ArkFr> = (0..16).map(|i| ArkFr::from_u64(i as u64)).collect();
    let poly1 = ArkworksPolynomial::new(coefficients.clone());
    let poly2 = ArkworksPolynomial::new(coefficients);

    let (comm1, _) = poly1.commit::<BN254, TestG1Routines>(2, 2, &setup).unwrap();
    let (comm2, _) = poly2.commit::<BN254, TestG1Routines>(2, 2, &setup).unwrap();

    assert_eq!(comm1, comm2);
}

#[test]
fn test_commit_different_polynomials() {
    let setup = test_setup(6);

    let poly1 = random_polynomial(16);
    let poly2 = random_polynomial(16);

    let (comm1, _) = poly1.commit::<BN254, TestG1Routines>(2, 2, &setup).unwrap();
    let (comm2, _) = poly2.commit::<BN254, TestG1Routines>(2, 2, &setup).unwrap();

    assert_ne!(comm1, comm2);
}
