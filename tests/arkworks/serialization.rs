//! Proof serialization round-trip tests

use super::*;
use ark_bn254::{Fq12, Fr};
use ark_ff::{Field as ArkField, PrimeField, Zero};
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress as ArkCompress, Validate as ArkValidate,
};
use dory_pcs::backends::arkworks::{ArkDoryProof, ArkGT, MAX_SERIALIZED_PROOF_ROUNDS};
use dory_pcs::primitives::poly::Polynomial;
use dory_pcs::primitives::serialization::{
    Compress as DoryCompress, DoryDeserialize, Validate as DoryValidate,
};
use dory_pcs::{prove, verify, Transparent};

fn make_transparent_proof() -> (
    ArkDoryProof,
    dory_pcs::backends::arkworks::ArkGT,
    Vec<ArkFr>,
) {
    let (setup, verifier_setup) = test_setup_pair(4);

    let poly = random_polynomial(16);
    let point = random_point(4);
    let (tier_2, tier_1, commit_blind) = poly
        .commit::<BN254, Transparent, TestG1Routines>(2, 2, &setup)
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

fn serialized_rounds_offset(proof: &ArkDoryProof, compress: ArkCompress) -> usize {
    CanonicalSerialize::serialized_size(&proof.vmv_message.c, compress)
        + CanonicalSerialize::serialized_size(&proof.vmv_message.d2, compress)
        + CanonicalSerialize::serialized_size(&proof.vmv_message.e1, compress)
}

fn serialized_sigma_offset(proof: &ArkDoryProof, compress: ArkCompress) -> usize {
    let u32_size = CanonicalSerialize::serialized_size(&0u32, compress);
    let mut offset = serialized_rounds_offset(proof, compress) + u32_size;

    for msg in &proof.first_messages {
        offset += CanonicalSerialize::serialized_size(&msg.d1_left, compress);
        offset += CanonicalSerialize::serialized_size(&msg.d1_right, compress);
        offset += CanonicalSerialize::serialized_size(&msg.d2_left, compress);
        offset += CanonicalSerialize::serialized_size(&msg.d2_right, compress);
        offset += CanonicalSerialize::serialized_size(&msg.e1_beta, compress);
        offset += CanonicalSerialize::serialized_size(&msg.e2_beta, compress);
    }

    for msg in &proof.second_messages {
        offset += CanonicalSerialize::serialized_size(&msg.c_plus, compress);
        offset += CanonicalSerialize::serialized_size(&msg.c_minus, compress);
        offset += CanonicalSerialize::serialized_size(&msg.e1_plus, compress);
        offset += CanonicalSerialize::serialized_size(&msg.e1_minus, compress);
        offset += CanonicalSerialize::serialized_size(&msg.e2_plus, compress);
        offset += CanonicalSerialize::serialized_size(&msg.e2_minus, compress);
    }

    offset += CanonicalSerialize::serialized_size(&proof.final_message.e1, compress);
    offset += CanonicalSerialize::serialized_size(&proof.final_message.e2, compress);
    offset + u32_size
}

fn overwrite_serialized_u32(bytes: &mut [u8], offset: usize, value: u32, compress: ArkCompress) {
    let mut encoded = Vec::new();
    CanonicalSerialize::serialize_with_mode(&value, &mut encoded, compress).unwrap();
    bytes[offset..offset + encoded.len()].copy_from_slice(&encoded);
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
    let (setup, verifier_setup) = test_setup_pair(4);

    let poly = random_polynomial(16);
    let point = random_point(4);
    let (tier_2, tier_1, commit_blind) = poly
        .commit::<BN254, Transparent, TestG1Routines>(2, 2, &setup)
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

#[test]
fn test_arkgt_deserialization_rejects_zero() {
    let mut bytes = Vec::new();
    let zero = Fq12::zero();
    zero.serialize_compressed(&mut bytes).unwrap();

    let dory_result = <ArkGT as DoryDeserialize>::deserialize_with_mode(
        &bytes[..],
        DoryCompress::Yes,
        DoryValidate::Yes,
    );
    assert!(
        dory_result.is_err(),
        "Dory ArkGT validation must reject zero"
    );

    let ark_result = <ArkGT as CanonicalDeserialize>::deserialize_with_mode(
        &bytes[..],
        ArkCompress::Yes,
        ArkValidate::Yes,
    );
    assert!(
        ark_result.is_err(),
        "arkworks ArkGT validation must reject zero"
    );

    let unchecked = <ArkGT as DoryDeserialize>::deserialize_with_mode(
        &bytes[..],
        DoryCompress::Yes,
        DoryValidate::No,
    )
    .unwrap();
    assert_eq!(unchecked.0, zero);
}

#[test]
fn test_arkgt_deserialization_rejects_non_r_torsion() {
    let non_torsion = Fq12::ONE + Fq12::ONE;
    assert_ne!(non_torsion.pow(Fr::MODULUS), Fq12::ONE);

    let mut bytes = Vec::new();
    non_torsion.serialize_compressed(&mut bytes).unwrap();

    let dory_result = <ArkGT as DoryDeserialize>::deserialize_with_mode(
        &bytes[..],
        DoryCompress::Yes,
        DoryValidate::Yes,
    );
    assert!(
        dory_result.is_err(),
        "Dory ArkGT validation must reject non-r-torsion elements"
    );

    let ark_result = <ArkGT as CanonicalDeserialize>::deserialize_with_mode(
        &bytes[..],
        ArkCompress::Yes,
        ArkValidate::Yes,
    );
    assert!(
        ark_result.is_err(),
        "arkworks ArkGT validation must reject non-r-torsion elements"
    );
}

#[test]
fn test_proof_deserialization_rejects_u32_max_rounds() {
    let (proof, _, _) = make_transparent_proof();
    let compress = ArkCompress::Yes;
    let mut bytes = Vec::new();
    proof.serialize_with_mode(&mut bytes, compress).unwrap();

    let offset = serialized_rounds_offset(&proof, compress);
    overwrite_serialized_u32(&mut bytes, offset, u32::MAX, compress);

    let result = ArkDoryProof::deserialize_with_mode(&bytes[..], compress, ArkValidate::Yes);
    assert!(result.is_err());
}

#[test]
fn test_proof_deserialization_rejects_rounds_over_bound() {
    let (proof, _, _) = make_transparent_proof();
    let compress = ArkCompress::Yes;
    let mut bytes = Vec::new();
    proof.serialize_with_mode(&mut bytes, compress).unwrap();

    let offset = serialized_rounds_offset(&proof, compress);
    overwrite_serialized_u32(
        &mut bytes,
        offset,
        (MAX_SERIALIZED_PROOF_ROUNDS as u32) + 1,
        compress,
    );

    let result = ArkDoryProof::deserialize_with_mode(&bytes[..], compress, ArkValidate::Yes);
    assert!(result.is_err());
}

#[test]
fn test_proof_deserialization_rejects_sigma_round_mismatch() {
    let (proof, _, _) = make_transparent_proof();
    let compress = ArkCompress::Yes;
    let mut bytes = Vec::new();
    proof.serialize_with_mode(&mut bytes, compress).unwrap();

    let offset = serialized_sigma_offset(&proof, compress);
    overwrite_serialized_u32(&mut bytes, offset, (proof.sigma as u32) + 1, compress);

    let result = ArkDoryProof::deserialize_with_mode(&bytes[..], compress, ArkValidate::Yes);
    assert!(result.is_err());
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
        let (setup, verifier_setup) = test_setup_pair(4);

        let poly = random_polynomial(16);
        let point = random_point(4);
        let (tier_2, tier_1, commit_blind) = poly
            .commit::<BN254, Transparent, TestG1Routines>(2, 2, &setup)
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
        let (setup, verifier_setup) = test_setup_pair(4);

        let poly = random_polynomial(16);
        let point = random_point(4);
        let (tier_2, tier_1, commit_blind) = poly
            .commit::<BN254, Transparent, TestG1Routines>(2, 2, &setup)
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
