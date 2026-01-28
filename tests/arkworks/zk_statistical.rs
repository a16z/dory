//! Statistical tests for zero-knowledge property of Dory PCS
//!
//! Verifies that proof elements are statistically indistinguishable from uniform
//! random regardless of the witness (polynomial) distribution.

use super::*;
use ark_serialize::CanonicalSerialize;
use dory_pcs::primitives::arithmetic::Field;
use dory_pcs::primitives::poly::Polynomial;
use dory_pcs::{create_evaluation_proof, setup, verify, DoryProof, ZK};
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::collections::HashMap;

const NUM_BUCKETS: usize = 16;

/// Bucket distribution tracker for statistical analysis
struct BucketTracker {
    buckets: HashMap<String, Vec<usize>>,
}

impl BucketTracker {
    fn new() -> Self {
        Self {
            buckets: HashMap::new(),
        }
    }

    fn record(&mut self, name: &str, bucket: usize) {
        self.buckets
            .entry(name.to_string())
            .or_insert_with(|| vec![0; NUM_BUCKETS])[bucket] += 1;
    }

    fn chi_squared(&self, name: &str, expected: f64) -> Option<f64> {
        self.buckets.get(name).map(|buckets| {
            buckets
                .iter()
                .map(|&observed| {
                    let diff = observed as f64 - expected;
                    diff * diff / expected
                })
                .sum()
        })
    }

    fn all_names(&self) -> Vec<String> {
        let mut names: Vec<_> = self.buckets.keys().cloned().collect();
        names.sort();
        names
    }
}

/// Extract low bytes from serializable element for bucketing
fn bucket_from_serializable<T: CanonicalSerialize>(elem: &T) -> usize {
    let mut bytes = Vec::new();
    elem.serialize_compressed(&mut bytes).unwrap();
    // Use first byte for primary bucket
    (bytes[0] as usize) % NUM_BUCKETS
}

type ArkDoryProof = DoryProof<
    dory_pcs::backends::arkworks::ArkG1,
    dory_pcs::backends::arkworks::ArkG2,
    dory_pcs::backends::arkworks::ArkGT,
>;

/// Collect bucket statistics from a full ZK proof (with hidden y)
fn collect_full_zk_proof_stats(proof: &ArkDoryProof, tracker: &mut BucketTracker) {
    // VMV message elements
    tracker.record("zk_vmv_c", bucket_from_serializable(&proof.vmv_message.c));
    tracker.record("zk_vmv_d2", bucket_from_serializable(&proof.vmv_message.d2));
    tracker.record("zk_vmv_e1", bucket_from_serializable(&proof.vmv_message.e1));

    // ZK-specific fields from proof
    if let Some(ref e2) = proof.e2 {
        tracker.record("zk_vmv_e2", bucket_from_serializable(e2));
    }
    if let Some(ref y_com) = proof.y_com {
        tracker.record("zk_vmv_y_com", bucket_from_serializable(y_com));
    }

    // First reduce messages (D values only - e1_beta/e2_beta are public)
    for (i, msg) in proof.first_messages.iter().enumerate() {
        let prefix = format!("zk_first_{}", i);
        tracker.record(
            &format!("{}_d1_left", prefix),
            bucket_from_serializable(&msg.d1_left),
        );
        tracker.record(
            &format!("{}_d1_right", prefix),
            bucket_from_serializable(&msg.d1_right),
        );
        tracker.record(
            &format!("{}_d2_left", prefix),
            bucket_from_serializable(&msg.d2_left),
        );
        tracker.record(
            &format!("{}_d2_right", prefix),
            bucket_from_serializable(&msg.d2_right),
        );
    }

    // Second reduce messages
    for (i, msg) in proof.second_messages.iter().enumerate() {
        let prefix = format!("zk_second_{}", i);
        tracker.record(
            &format!("{}_c_plus", prefix),
            bucket_from_serializable(&msg.c_plus),
        );
        tracker.record(
            &format!("{}_c_minus", prefix),
            bucket_from_serializable(&msg.c_minus),
        );
        tracker.record(
            &format!("{}_e1_plus", prefix),
            bucket_from_serializable(&msg.e1_plus),
        );
        tracker.record(
            &format!("{}_e1_minus", prefix),
            bucket_from_serializable(&msg.e1_minus),
        );
        tracker.record(
            &format!("{}_e2_plus", prefix),
            bucket_from_serializable(&msg.e2_plus),
        );
        tracker.record(
            &format!("{}_e2_minus", prefix),
            bucket_from_serializable(&msg.e2_minus),
        );
    }

    // Final message
    tracker.record(
        "zk_final_e1",
        bucket_from_serializable(&proof.final_message.e1),
    );
    tracker.record(
        "zk_final_e2",
        bucket_from_serializable(&proof.final_message.e2),
    );

    // Sigma1 proof (proves y_com and E2 commit to same y)
    if let Some(ref sigma1) = proof.sigma1_proof {
        tracker.record("sigma1_a1", bucket_from_serializable(&sigma1.a1));
        tracker.record("sigma1_a2", bucket_from_serializable(&sigma1.a2));
        tracker.record("sigma1_z1", bucket_from_serializable(&sigma1.z1));
        tracker.record("sigma1_z2", bucket_from_serializable(&sigma1.z2));
        tracker.record("sigma1_z3", bucket_from_serializable(&sigma1.z3));
    }

    // Sigma2 proof (proves VMV relation)
    if let Some(ref sigma2) = proof.sigma2_proof {
        tracker.record("sigma2_a", bucket_from_serializable(&sigma2.a));
        tracker.record("sigma2_z1", bucket_from_serializable(&sigma2.z1));
        tracker.record("sigma2_z2", bucket_from_serializable(&sigma2.z2));
    }

    // Scalar product proof
    if let Some(ref sp) = proof.scalar_product_proof {
        tracker.record("zk_sp_p1", bucket_from_serializable(&sp.p1));
        tracker.record("zk_sp_p2", bucket_from_serializable(&sp.p2));
        tracker.record("zk_sp_q", bucket_from_serializable(&sp.q));
        tracker.record("zk_sp_r", bucket_from_serializable(&sp.r));
        tracker.record("zk_sp_e1", bucket_from_serializable(&sp.e1));
        tracker.record("zk_sp_e2", bucket_from_serializable(&sp.e2));
        tracker.record("zk_sp_r1", bucket_from_serializable(&sp.r1));
        tracker.record("zk_sp_r2", bucket_from_serializable(&sp.r2));
        tracker.record("zk_sp_r3", bucket_from_serializable(&sp.r3));
    }
}

/// Statistical test for zero-knowledge property (full ZK with hidden y).
///
/// Creates polynomials with different coefficient distributions and verifies
/// that all resulting proof elements (including y_com, Sigma1, Sigma2) are
/// statistically indistinguishable from uniform random.
#[test]
#[ignore] // Long-running statistical test
fn test_zk_statistical_indistinguishability() {
    const NUM_TRIALS: usize = 100;

    let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
    let (prover_setup, verifier_setup) = setup::<BN254, _>(&mut rng, 6);

    let nu = 2;
    let sigma = 2;
    let poly_size = 16;
    let point = random_point(nu + sigma);

    // Track distributions for three witness types
    let mut tracker_zeros = BucketTracker::new();
    let mut tracker_ones = BucketTracker::new();
    let mut tracker_random = BucketTracker::new();

    for trial in 0..NUM_TRIALS {
        // Reseed RNG for reproducibility within each trial type
        let mut trial_rng = StdRng::seed_from_u64(0xCAFEBABE + trial as u64);

        // Distribution A: All-zeros polynomial (y=0 for all points)
        {
            let coeffs = vec![ArkFr::zero(); poly_size];
            let poly = ArkworksPolynomial::new(coeffs);

            let (tier_2, tier_1) = poly
                .commit::<BN254, TestG1Routines>(nu, sigma, &prover_setup)
                .unwrap();

            let evaluation = poly.evaluate(&point);
            let mut transcript = fresh_transcript();
            let (proof, _) =
                create_evaluation_proof::<_, BN254, TestG1Routines, TestG2Routines, _, _, ZK, _>(
                    &poly,
                    &point,
                    Some(tier_1),
                    nu,
                    sigma,
                    &prover_setup,
                    &mut transcript,
                    &mut trial_rng,
                )
                .unwrap();

            // Verify proof is valid
            let mut verifier_transcript = fresh_transcript();
            assert!(verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
                tier_2,
                evaluation,
                &point,
                &proof,
                verifier_setup.clone(),
                &mut verifier_transcript,
            )
            .is_ok());

            collect_full_zk_proof_stats(&proof, &mut tracker_zeros);
        }

        // Distribution B: All-ones polynomial (y=2^n for point=(0,0,...))
        {
            let coeffs = vec![ArkFr::one(); poly_size];
            let poly = ArkworksPolynomial::new(coeffs);

            let (tier_2, tier_1) = poly
                .commit::<BN254, TestG1Routines>(nu, sigma, &prover_setup)
                .unwrap();

            let evaluation = poly.evaluate(&point);
            let mut transcript = fresh_transcript();
            let (proof, _) =
                create_evaluation_proof::<_, BN254, TestG1Routines, TestG2Routines, _, _, ZK, _>(
                    &poly,
                    &point,
                    Some(tier_1),
                    nu,
                    sigma,
                    &prover_setup,
                    &mut transcript,
                    &mut trial_rng,
                )
                .unwrap();

            let mut verifier_transcript = fresh_transcript();
            assert!(verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
                tier_2,
                evaluation,
                &point,
                &proof,
                verifier_setup.clone(),
                &mut verifier_transcript,
            )
            .is_ok());

            collect_full_zk_proof_stats(&proof, &mut tracker_ones);
        }

        // Distribution C: Random polynomial
        {
            let poly = random_polynomial(poly_size);

            let (tier_2, tier_1) = poly
                .commit::<BN254, TestG1Routines>(nu, sigma, &prover_setup)
                .unwrap();

            let evaluation = poly.evaluate(&point);
            let mut transcript = fresh_transcript();
            let (proof, _) =
                create_evaluation_proof::<_, BN254, TestG1Routines, TestG2Routines, _, _, ZK, _>(
                    &poly,
                    &point,
                    Some(tier_1),
                    nu,
                    sigma,
                    &prover_setup,
                    &mut transcript,
                    &mut trial_rng,
                )
                .unwrap();

            let mut verifier_transcript = fresh_transcript();
            assert!(verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
                tier_2,
                evaluation,
                &point,
                &proof,
                verifier_setup.clone(),
                &mut verifier_transcript,
            )
            .is_ok());

            collect_full_zk_proof_stats(&proof, &mut tracker_random);
        }
    }

    // Statistical analysis
    let expected = NUM_TRIALS as f64 / NUM_BUCKETS as f64;

    // Critical value for χ² with df=15 at α=0.01 is ~30.58
    // Use lenient threshold for randomness testing
    let critical_value = 35.0;

    let mut failures = Vec::new();

    for name in tracker_zeros.all_names() {
        // Test uniformity for each witness type
        if let Some(chi2) = tracker_zeros.chi_squared(&name, expected) {
            if chi2 >= critical_value {
                failures.push(format!(
                    "zeros/{}: χ²={:.2} >= {:.2}",
                    name, chi2, critical_value
                ));
            }
        }

        if let Some(chi2) = tracker_ones.chi_squared(&name, expected) {
            if chi2 >= critical_value {
                failures.push(format!(
                    "ones/{}: χ²={:.2} >= {:.2}",
                    name, chi2, critical_value
                ));
            }
        }

        if let Some(chi2) = tracker_random.chi_squared(&name, expected) {
            if chi2 >= critical_value {
                failures.push(format!(
                    "random/{}: χ²={:.2} >= {:.2}",
                    name, chi2, critical_value
                ));
            }
        }
    }

    if !failures.is_empty() {
        panic!(
            "ZK statistical test failed - {} elements showed non-uniform distribution:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}

/// Test that proof distributions from different witnesses are similar (two-sample test)
/// Uses full ZK API with hidden y to test all proof elements including y_com.
#[test]
#[ignore] // Long-running statistical test
fn test_zk_witness_independence() {
    const NUM_TRIALS: usize = 80;

    let mut rng = StdRng::seed_from_u64(0xFEEDFACE);
    let (prover_setup, verifier_setup) = setup::<BN254, _>(&mut rng, 6);

    let nu = 2;
    let sigma = 2;
    let poly_size = 16;
    let point = random_point(nu + sigma);

    let mut tracker_skewed = BucketTracker::new();
    let mut tracker_uniform = BucketTracker::new();

    for trial in 0..NUM_TRIALS {
        let mut trial_rng = StdRng::seed_from_u64(0xABCDEF00 + trial as u64);

        // Skewed: Single non-zero coefficient at position 0 (y will be small/predictable)
        {
            let mut coeffs = vec![ArkFr::zero(); poly_size];
            coeffs[0] = ArkFr::from_u64(42);
            let poly = ArkworksPolynomial::new(coeffs);

            let (tier_2, tier_1) = poly
                .commit::<BN254, TestG1Routines>(nu, sigma, &prover_setup)
                .unwrap();

            let evaluation = poly.evaluate(&point);
            let mut transcript = fresh_transcript();
            let (proof, _) =
                create_evaluation_proof::<_, BN254, TestG1Routines, TestG2Routines, _, _, ZK, _>(
                    &poly,
                    &point,
                    Some(tier_1),
                    nu,
                    sigma,
                    &prover_setup,
                    &mut transcript,
                    &mut trial_rng,
                )
                .unwrap();

            let mut verifier_transcript = fresh_transcript();
            assert!(verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
                tier_2,
                evaluation,
                &point,
                &proof,
                verifier_setup.clone(),
                &mut verifier_transcript,
            )
            .is_ok());

            collect_full_zk_proof_stats(&proof, &mut tracker_skewed);
        }

        // Uniform: Random polynomial (y will be random)
        {
            let poly = random_polynomial(poly_size);

            let (tier_2, tier_1) = poly
                .commit::<BN254, TestG1Routines>(nu, sigma, &prover_setup)
                .unwrap();

            let evaluation = poly.evaluate(&point);
            let mut transcript = fresh_transcript();
            let (proof, _) =
                create_evaluation_proof::<_, BN254, TestG1Routines, TestG2Routines, _, _, ZK, _>(
                    &poly,
                    &point,
                    Some(tier_1),
                    nu,
                    sigma,
                    &prover_setup,
                    &mut transcript,
                    &mut trial_rng,
                )
                .unwrap();

            let mut verifier_transcript = fresh_transcript();
            assert!(verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
                tier_2,
                evaluation,
                &point,
                &proof,
                verifier_setup.clone(),
                &mut verifier_transcript,
            )
            .is_ok());

            collect_full_zk_proof_stats(&proof, &mut tracker_uniform);
        }
    }

    // Two-sample χ² test between skewed and uniform witness distributions
    fn two_sample_chi_squared(a: &[usize], b: &[usize]) -> f64 {
        let n_a: f64 = a.iter().sum::<usize>() as f64;
        let n_b: f64 = b.iter().sum::<usize>() as f64;
        let n_total = n_a + n_b;

        a.iter()
            .zip(b.iter())
            .map(|(&obs_a, &obs_b)| {
                let pooled = obs_a as f64 + obs_b as f64;
                if pooled < 1.0 {
                    return 0.0;
                }
                let expected_a = pooled * n_a / n_total;
                let expected_b = pooled * n_b / n_total;
                let term_a = if expected_a > 0.0 {
                    (obs_a as f64 - expected_a).powi(2) / expected_a
                } else {
                    0.0
                };
                let term_b = if expected_b > 0.0 {
                    (obs_b as f64 - expected_b).powi(2) / expected_b
                } else {
                    0.0
                };
                term_a + term_b
            })
            .sum()
    }

    // Critical value for two-sample χ² with df=15 at α=0.005
    // Using slightly higher threshold to reduce false positives from random variation
    let critical_value = 40.0;
    let mut failures = Vec::new();

    for name in tracker_skewed.all_names() {
        let buckets_skewed = tracker_skewed.buckets.get(&name).unwrap();
        let buckets_uniform = tracker_uniform.buckets.get(&name).unwrap();

        let chi2 = two_sample_chi_squared(buckets_skewed, buckets_uniform);
        if chi2 >= critical_value {
            failures.push(format!(
                "{}: skewed vs uniform χ²={:.2} >= {:.2}",
                name, chi2, critical_value
            ));
        }
    }

    if !failures.is_empty() {
        panic!(
            "ZK witness independence test failed - {} elements showed witness-dependent distribution:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}
