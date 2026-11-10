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
    let mut prover_rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(42);
    let (setup, verifier_setup) = test_setup_pair(4);

    let poly = random_polynomial(16);
    let point = random_point(4);
    let (tier_2, tier_1, commit_blind) = poly
        .commit::<BN254, Transparent, TestG1Routines>(2, 2, &setup, &mut prover_rng)
        .unwrap();
    let mut transcript = fresh_transcript();
    let (proof, _) = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, Transparent>(
        &poly,
        &point,
        tier_1,
        commit_blind,
        2,
        2,
        &setup,
        &mut transcript,
        &mut prover_rng,
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
    assert_eq!(proof, decoded);
}

#[test]
fn test_transparent_proof_roundtrip_uncompressed() {
    let (proof, _, _) = make_transparent_proof();

    let mut buf = Vec::new();
    proof.serialize_uncompressed(&mut buf).unwrap();
    assert_eq!(buf.len(), proof.uncompressed_size());

    let decoded = ArkDoryProof::deserialize_uncompressed(&buf[..]).unwrap();
    assert_eq!(proof, decoded);
}

#[test]
fn test_transparent_proof_roundtrip_verifies() {
    let mut prover_rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(42);
    let (setup, verifier_setup) = test_setup_pair(4);

    let poly = random_polynomial(16);
    let point = random_point(4);
    let (tier_2, tier_1, commit_blind) = poly
        .commit::<BN254, Transparent, TestG1Routines>(2, 2, &setup, &mut prover_rng)
        .unwrap();

    let mut transcript = fresh_transcript();
    let (proof, _) = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, Transparent>(
        &poly,
        &point,
        tier_1,
        commit_blind,
        2,
        2,
        &setup,
        &mut transcript,
        &mut prover_rng,
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
        let mut prover_rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(42);
        let (setup, verifier_setup) = test_setup_pair(4);

        let poly = random_polynomial(16);
        let point = random_point(4);
        let (tier_2, tier_1, commit_blind) = poly
            .commit::<BN254, Transparent, TestG1Routines>(2, 2, &setup, &mut prover_rng)
            .unwrap();

        let mut transcript = fresh_transcript();
        let (proof, _) = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, ZK>(
            &poly,
            &point,
            tier_1,
            commit_blind,
            2,
            2,
            &setup,
            &mut transcript,
            &mut prover_rng,
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
        assert_eq!(proof, decoded);
    }

    #[test]
    fn test_zk_proof_roundtrip_verifies() {
        let mut prover_rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(42);
        let (setup, verifier_setup) = test_setup_pair(4);

        let poly = random_polynomial(16);
        let point = random_point(4);
        let (tier_2, tier_1, commit_blind) = poly
            .commit::<BN254, Transparent, TestG1Routines>(2, 2, &setup, &mut prover_rng)
            .unwrap();

        let mut transcript = fresh_transcript();
        let (proof, _) = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, ZK>(
            &poly,
            &point,
            tier_1,
            commit_blind,
            2,
            2,
            &setup,
            &mut transcript,
            &mut prover_rng,
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
