use dory_pcs::backends::arkworks::{ArkG1, ArkG2, ArkGT, BN254};
use dory_pcs::primitives::arithmetic::{Group, PairingCurve};
use rand::thread_rng;

#[cfg(feature = "cache")]
use dory_pcs::backends::arkworks::ark_cache;

#[test]
fn multi_pair_correctness() {
    let mut rng = thread_rng();
    let n = 10;

    let ps: Vec<ArkG1> = (0..n).map(|_| ArkG1::random(&mut rng)).collect();
    let qs: Vec<ArkG2> = (0..n).map(|_| ArkG2::random(&mut rng)).collect();

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
    let mut rng = thread_rng();

    let ps: Vec<ArkG1> = (0..5).map(|_| ArkG1::random(&mut rng)).collect();
    let qs: Vec<ArkG2> = (0..3).map(|_| ArkG2::random(&mut rng)).collect();

    BN254::multi_pair(&ps, &qs);
}

#[cfg(feature = "cache")]
#[test]
fn cache_initialization() {
    let mut rng = thread_rng();
    let g1_vec: Vec<ArkG1> = (0..10).map(|_| ArkG1::random(&mut rng)).collect();
    let g2_vec: Vec<ArkG2> = (0..10).map(|_| ArkG2::random(&mut rng)).collect();

    ark_cache::init_cache(&g1_vec, &g2_vec);

    assert!(ark_cache::is_cached());
    let cache = ark_cache::get_prepared_cache().unwrap();
    assert_eq!(cache.g1_prepared.len(), 10);
    assert_eq!(cache.g2_prepared.len(), 10);
}

#[cfg(feature = "cache")]
#[test]
fn cache_smart_reinit() {
    let mut rng = thread_rng();

    // Initialize with small size
    let g1_small: Vec<ArkG1> = (0..5).map(|_| ArkG1::random(&mut rng)).collect();
    let g2_small: Vec<ArkG2> = (0..5).map(|_| ArkG2::random(&mut rng)).collect();
    ark_cache::init_cache(&g1_small, &g2_small);

    let cache = ark_cache::get_prepared_cache().unwrap();
    let small_len = cache.g1_prepared.len();

    // Re-init with same size — should be a no-op (reuses existing)
    ark_cache::init_cache(&g1_small, &g2_small);
    let cache = ark_cache::get_prepared_cache().unwrap();
    assert_eq!(cache.g1_prepared.len(), small_len);

    // Re-init with larger size — should replace cache
    let g1_large: Vec<ArkG1> = (0..20).map(|_| ArkG1::random(&mut rng)).collect();
    let g2_large: Vec<ArkG2> = (0..20).map(|_| ArkG2::random(&mut rng)).collect();
    ark_cache::init_cache(&g1_large, &g2_large);

    let cache = ark_cache::get_prepared_cache().unwrap();
    assert_eq!(cache.g1_prepared.len(), 20);
    assert_eq!(cache.g2_prepared.len(), 20);
}

#[cfg(feature = "cache")]
#[test]
fn multi_pair_with_cache_optimization() {
    let mut rng = thread_rng();
    let n = 20;

    let g1_vec: Vec<ArkG1> = (0..n).map(|_| ArkG1::random(&mut rng)).collect();
    let g2_vec: Vec<ArkG2> = (0..n).map(|_| ArkG2::random(&mut rng)).collect();

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
