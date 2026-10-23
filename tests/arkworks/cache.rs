use dory_pcs::backends::arkworks::{ArkG1, ArkG2, ArkGT, BN254};
use dory_pcs::primitives::arithmetic::{Group, PairingCurve};

#[cfg(feature = "cache")]
use dory_pcs::backends::arkworks::ark_cache;

/// Serializes the tests that write the global prepared-point cache, so
/// their assertions hold when tests share a process (`cargo test`).
#[cfg(feature = "cache")]
static CACHE_WRITERS: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(feature = "cache")]
fn lock_cache() -> std::sync::MutexGuard<'static, ()> {
    CACHE_WRITERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(feature = "cache")]
fn random_points(n: usize) -> (Vec<ArkG1>, Vec<ArkG2>) {
    (
        (0..n).map(|_| ArkG1::random()).collect(),
        (0..n).map(|_| ArkG2::random()).collect(),
    )
}

#[cfg(feature = "cache")]
fn pair_naive(ps: &[ArkG1], qs: &[ArkG2]) -> ArkGT {
    ps.iter()
        .zip(qs)
        .fold(ArkGT::identity(), |acc, (p, q)| acc.add(&BN254::pair(p, q)))
}

#[test]
fn multi_pair_correctness() {
    let n = 10;

    let ps: Vec<ArkG1> = (0..n).map(|_| ArkG1::random()).collect();
    let qs: Vec<ArkG2> = (0..n).map(|_| ArkG2::random()).collect();

    let result = BN254::multi_pair(&ps, &qs);

    let mut expected = ArkGT::identity();
    for (p, q) in ps.iter().zip(qs.iter()) {
        expected = expected.add(&BN254::pair(p, q));
    }

    assert_eq!(result, expected);
}

#[test]
fn multi_pair_empty() {
    let empty_g1: Vec<ArkG1> = vec![];
    let empty_g2: Vec<ArkG2> = vec![];

    let result = BN254::multi_pair(&empty_g1, &empty_g2);
    assert_eq!(result, ArkGT::identity());
}

#[test]
#[should_panic(expected = "multi_pair requires equal length vectors")]
fn multi_pair_length_mismatch() {
    let ps: Vec<ArkG1> = (0..5).map(|_| ArkG1::random()).collect();
    let qs: Vec<ArkG2> = (0..3).map(|_| ArkG2::random()).collect();

    BN254::multi_pair(&ps, &qs);
}

#[cfg(feature = "cache")]
#[test]
fn cache_initialization() {
    let _guard = lock_cache();
    let g1_vec: Vec<ArkG1> = (0..10).map(|_| ArkG1::random()).collect();
    let g2_vec: Vec<ArkG2> = (0..10).map(|_| ArkG2::random()).collect();

    ark_cache::init_cache(&g1_vec, &g2_vec);

    assert!(ark_cache::is_cached());
    let cache = ark_cache::get_prepared_cache().unwrap();
    assert_eq!(cache.g1_prepared.len(), 10);
    assert_eq!(cache.g2_prepared.len(), 10);
}

#[cfg(feature = "cache")]
#[test]
fn cache_smart_reinit() {
    let _guard = lock_cache();
    // Initialize with small size
    let g1_small: Vec<ArkG1> = (0..5).map(|_| ArkG1::random()).collect();
    let g2_small: Vec<ArkG2> = (0..5).map(|_| ArkG2::random()).collect();
    ark_cache::init_cache(&g1_small, &g2_small);

    let cache = ark_cache::get_prepared_cache().unwrap();
    let small_len = cache.g1_prepared.len();

    // Re-init with same size — should be a no-op (reuses existing)
    ark_cache::init_cache(&g1_small, &g2_small);
    let cache = ark_cache::get_prepared_cache().unwrap();
    assert_eq!(cache.g1_prepared.len(), small_len);

    // Re-init with larger size — should replace cache
    let g1_large: Vec<ArkG1> = (0..20).map(|_| ArkG1::random()).collect();
    let g2_large: Vec<ArkG2> = (0..20).map(|_| ArkG2::random()).collect();
    ark_cache::init_cache(&g1_large, &g2_large);

    let cache = ark_cache::get_prepared_cache().unwrap();
    assert_eq!(cache.g1_prepared.len(), 20);
    assert_eq!(cache.g2_prepared.len(), 20);
}

#[cfg(feature = "cache")]
#[test]
fn multi_pair_with_cache_optimization() {
    let _guard = lock_cache();
    let n = 20;

    let g1_vec: Vec<ArkG1> = (0..n).map(|_| ArkG1::random()).collect();
    let g2_vec: Vec<ArkG2> = (0..n).map(|_| ArkG2::random()).collect();

    if !ark_cache::is_cached() {
        ark_cache::init_cache(&g1_vec, &g2_vec);
    }

    let ps = &g1_vec[0..10];
    let qs = &g2_vec[0..10];

    let result = BN254::multi_pair(ps, qs);

    let mut expected = ArkGT::identity();
    for (p, q) in ps.iter().zip(qs.iter()) {
        expected = expected.add(&BN254::pair(p, q));
    }

    assert_eq!(result, expected);
}

/// A cache built from other points must not change setup pairings, whether
/// the caller's points are shorter or longer than the cache.
#[cfg(feature = "cache")]
#[test]
fn foreign_cache_falls_back() {
    let _guard = lock_cache();
    let (cached_g1, cached_g2) = random_points(20);
    ark_cache::init_cache(&cached_g1, &cached_g2);

    for n in [10, 30] {
        let (ps, qs) = random_points(n);
        let expected = pair_naive(&ps, &qs);
        assert_eq!(BN254::multi_pair_g2_setup(&ps, &qs), expected, "n={n}");
        assert_eq!(BN254::multi_pair_g1_setup(&ps, &qs), expected, "n={n}");
    }
}

/// Re-initializing with other points of no larger size replaces the cache.
#[cfg(feature = "cache")]
#[test]
fn reinit_with_other_points_replaces() {
    let _guard = lock_cache();
    let (large_g1, large_g2) = random_points(20);
    ark_cache::init_cache(&large_g1, &large_g2);

    let (small_g1, small_g2) = random_points(10);
    ark_cache::init_cache(&small_g1, &small_g2);

    let cache = ark_cache::get_prepared_cache().unwrap();
    assert!(cache.g1_prepared_for(&small_g1).is_some());
    assert!(cache.g2_prepared_for(&small_g2).is_some());
    assert!(cache.g1_prepared_for(&large_g1).is_none());
    assert!(cache.g2_prepared_for(&large_g2).is_none());
}

/// A proof verifies after the cache was filled with another setup's points.
#[cfg(feature = "cache")]
#[test]
fn proof_verifies_after_foreign_cache() {
    use super::*;
    use dory_pcs::primitives::poly::Polynomial;
    use dory_pcs::{prove, verify, Transparent};

    let _guard = lock_cache();
    let (cached_g1, cached_g2) = random_points(64);
    ark_cache::init_cache(&cached_g1, &cached_g2);

    let (prover_setup, verifier_setup) = test_setup_pair(8);
    let (nu, sigma) = (4, 4);
    let poly = random_polynomial(1 << (nu + sigma));
    let point = random_point(nu + sigma);
    let (commitment, row_commitments, commit_blind) = poly
        .commit::<BN254, Transparent, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();
    let (proof, _) = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, Transparent>(
        &poly,
        &point,
        row_commitments,
        commit_blind,
        nu,
        sigma,
        &prover_setup,
        &mut fresh_transcript(),
    )
    .unwrap();
    verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        commitment,
        poly.evaluate(&point),
        &point,
        &proof,
        verifier_setup,
        &mut fresh_transcript(),
    )
    .unwrap();
}
