//! Tests for Arkworks witness generation

use dory_pcs::backends::arkworks::{ArkFr, ArkG1, ArkG2, ArkGT, SimpleWitnessGenerator, BN254};
use dory_pcs::primitives::arithmetic::{Field, Group, PairingCurve};
use dory_pcs::recursion::WitnessGenerator;
use rand::thread_rng;

#[test]
fn test_gt_exp_witness_generation() {
    let mut rng = thread_rng();
    let base = ArkGT::random(&mut rng);
    let scalar = ArkFr::random(&mut rng);
    let result = base.scale(&scalar);

    let witness = SimpleWitnessGenerator::generate_gt_exp(&base, &scalar, &result);

    assert_eq!(witness.base, base);
    assert_eq!(witness.result, result);
    assert_eq!(witness.scalar_bits.len(), 254);
}

#[test]
fn test_g1_scalar_mul_witness_generation() {
    let mut rng = thread_rng();
    let point = ArkG1::random(&mut rng);
    let scalar = ArkFr::random(&mut rng);
    let result = point.scale(&scalar);

    let witness = SimpleWitnessGenerator::generate_g1_scalar_mul(&point, &scalar, &result);

    assert_eq!(witness.point, point);
    assert_eq!(witness.result, result);
}

#[test]
fn test_pairing_witness_generation() {
    let mut rng = thread_rng();
    let g1 = ArkG1::random(&mut rng);
    let g2 = ArkG2::random(&mut rng);
    let result = BN254::pair(&g1, &g2);

    let witness = SimpleWitnessGenerator::generate_pairing(&g1, &g2, &result);

    assert_eq!(witness.g1, g1);
    assert_eq!(witness.g2, g2);
    assert_eq!(witness.result, result);
}
