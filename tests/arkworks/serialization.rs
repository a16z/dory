//! Proof serialization round-trip tests

use super::*;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use dory_pcs::backends::arkworks::ArkDoryProof;
use dory_pcs::primitives::poly::Polynomial;
use dory_pcs::{prove, verify, Transparent};

fn make_transparent_proof() -> (
    ArkDoryProof,
    dory_pcs::backends::arkworks::ArkGT,
    Vec<ArkFr>,
) {
    let mut rng = rand::thread_rng();
    let (setup, verifier_setup) = test_setup_pair(4);

    let poly = random_polynomial(16);
    let point = random_point(4);
    let (tier_2, tier_1) = poly.commit::<BN254, TestG1Routines>(2, 2, &setup).unwrap();
    let mut transcript = fresh_transcript();
    let (proof, _) = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, Transparent, _>(
        &poly,
        &point,
        tier_1,
        2,
        2,
        &setup,
        &mut transcript,
        &mut rng,
    )
    .unwrap();

    // Sanity: verify before serialization
    let eval = poly.evaluate(&point);
    let mut vt = fresh_transcript();
    verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        tier_2,
        eval,
        &point,
        &proof,
        verifier_setup,
        &mut vt,
    )
    .unwrap();

    (proof, tier_2, point)
}

#[test]
fn test_transparent_proof_roundtrip_compressed() {
    let (proof, _, _) = make_transparent_proof();

    let mut buf = Vec::new();
    proof.serialize_compressed(&mut buf).unwrap();
    assert_eq!(buf.len(), proof.compressed_size());

    let decoded = ArkDoryProof::deserialize_compressed(&buf[..]).unwrap();

    assert_eq!(proof.nu, decoded.nu);
    assert_eq!(proof.sigma, decoded.sigma);
    assert_eq!(proof.first_messages.len(), decoded.first_messages.len());
    assert_eq!(proof.second_messages.len(), decoded.second_messages.len());
}

#[test]
fn test_transparent_proof_roundtrip_uncompressed() {
    let (proof, _, _) = make_transparent_proof();

    let mut buf = Vec::new();
    proof.serialize_uncompressed(&mut buf).unwrap();
    assert_eq!(buf.len(), proof.uncompressed_size());

    let decoded = ArkDoryProof::deserialize_uncompressed(&buf[..]).unwrap();
    assert_eq!(proof.nu, decoded.nu);
    assert_eq!(proof.sigma, decoded.sigma);
}

#[test]
fn test_transparent_proof_roundtrip_verifies() {
    let mut rng = rand::thread_rng();
    let (setup, verifier_setup) = test_setup_pair(4);

    let poly = random_polynomial(16);
    let point = random_point(4);
    let (tier_2, tier_1) = poly.commit::<BN254, TestG1Routines>(2, 2, &setup).unwrap();

    let mut transcript = fresh_transcript();
    let (proof, _) = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, Transparent, _>(
        &poly,
        &point,
        tier_1,
        2,
        2,
        &setup,
        &mut transcript,
        &mut rng,
    )
    .unwrap();

    // Round-trip through serialization
    let mut buf = Vec::new();
    proof.serialize_compressed(&mut buf).unwrap();
    let decoded = ArkDoryProof::deserialize_compressed(&buf[..]).unwrap();

    // Verify the deserialized proof
    let eval = poly.evaluate(&point);
    let mut vt = fresh_transcript();
    verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        tier_2,
        eval,
        &point,
        &decoded,
        verifier_setup,
        &mut vt,
    )
    .unwrap();
}

#[cfg(feature = "zk")]
mod zk_roundtrip {
    use super::*;
    use dory_pcs::{prove, verify, ZK};

    fn make_zk_proof() -> (
        ArkDoryProof,
        dory_pcs::backends::arkworks::ArkGT,
        Vec<ArkFr>,
    ) {
        let mut rng = rand::thread_rng();
        let (setup, verifier_setup) = test_setup_pair(4);

        let poly = random_polynomial(16);
        let point = random_point(4);
        let (tier_2, tier_1) = poly.commit::<BN254, TestG1Routines>(2, 2, &setup).unwrap();

        let mut transcript = fresh_transcript();
        let (proof, _) = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, ZK, _>(
            &poly,
            &point,
            tier_1,
            2,
            2,
            &setup,
            &mut transcript,
            &mut rng,
        )
        .unwrap();

        // Sanity: ZK fields must be populated
        assert!(proof.e2.is_some());
        assert!(proof.y_com.is_some());
        assert!(proof.sigma1_proof.is_some());
        assert!(proof.sigma2_proof.is_some());
        assert!(proof.scalar_product_proof.is_some());

        let eval = poly.evaluate(&point);
        let mut vt = fresh_transcript();
        verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
            tier_2,
            eval,
            &point,
            &proof,
            verifier_setup,
            &mut vt,
        )
        .unwrap();

        (proof, tier_2, point)
    }

    #[test]
    fn test_zk_proof_roundtrip_compressed() {
        let (proof, _, _) = make_zk_proof();

        let mut buf = Vec::new();
        proof.serialize_compressed(&mut buf).unwrap();
        assert_eq!(buf.len(), proof.compressed_size());

        let decoded = ArkDoryProof::deserialize_compressed(&buf[..]).unwrap();
        assert_eq!(proof.nu, decoded.nu);
        assert_eq!(proof.sigma, decoded.sigma);
        assert!(decoded.e2.is_some());
        assert!(decoded.y_com.is_some());
        assert!(decoded.sigma1_proof.is_some());
        assert!(decoded.sigma2_proof.is_some());
        assert!(decoded.scalar_product_proof.is_some());
    }

    #[test]
    fn test_zk_proof_roundtrip_verifies() {
        let mut rng = rand::thread_rng();
        let (setup, verifier_setup) = test_setup_pair(4);

        let poly = random_polynomial(16);
        let point = random_point(4);
        let (tier_2, tier_1) = poly.commit::<BN254, TestG1Routines>(2, 2, &setup).unwrap();

        let mut transcript = fresh_transcript();
        let (proof, _) = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, ZK, _>(
            &poly,
            &point,
            tier_1,
            2,
            2,
            &setup,
            &mut transcript,
            &mut rng,
        )
        .unwrap();

        let mut buf = Vec::new();
        proof.serialize_compressed(&mut buf).unwrap();
        let decoded = ArkDoryProof::deserialize_compressed(&buf[..]).unwrap();

        let eval = poly.evaluate(&point);
        let mut vt = fresh_transcript();
        verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
            tier_2,
            eval,
            &point,
            &decoded,
            verifier_setup,
            &mut vt,
        )
        .unwrap();
    }

    #[test]
    fn test_zk_proof_larger_size_than_transparent() {
        let (zk_proof, _, _) = make_zk_proof();
        let (transparent_proof, _, _) = super::make_transparent_proof();

        let zk_size = zk_proof.compressed_size();
        let transparent_size = transparent_proof.compressed_size();

        assert!(
            zk_size > transparent_size,
            "ZK proof ({zk_size}) should be larger than transparent ({transparent_size})"
        );
    }
}
