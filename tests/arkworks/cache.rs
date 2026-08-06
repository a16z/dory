use dory_pcs::backends::arkworks::{ArkG1, ArkG2, ArkGT, BN254};
use dory_pcs::primitives::arithmetic::{Group, PairingCurve};

#[cfg(feature = "cache")]
use dory_pcs::backends::arkworks::ark_cache;

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
    let g1_small: Vec<ArkG1> = (0..5).map(|_| ArkG1::random()).collect();
    let g2_small: Vec<ArkG2> = (0..5).map(|_| ArkG2::random()).collect();
    ark_cache::init_cache(&g1_small, &g2_small);

    let cache = ark_cache::get_prepared_cache().unwrap();
    let small_len = cache.g1_prepared.len();

    ark_cache::init_cache(&g1_small, &g2_small);
    let cache = ark_cache::get_prepared_cache().unwrap();
    assert_eq!(cache.g1_prepared.len(), small_len);

    let mut g1_large = g1_small.clone();
    let mut g2_large = g2_small.clone();
    g1_large.extend((0..15).map(|_| ArkG1::random()));
    g2_large.extend((0..15).map(|_| ArkG2::random()));
    ark_cache::init_cache(&g1_large, &g2_large);

    let cache = ark_cache::get_prepared_cache().unwrap();
    assert_eq!(cache.g1_prepared.len(), 20);
    assert_eq!(cache.g2_prepared.len(), 20);

    ark_cache::init_cache(&g1_small, &g2_small);
    let prefix_cache = ark_cache::get_prepared_cache().unwrap();
    assert!(std::sync::Arc::ptr_eq(&cache, &prefix_cache));
}

#[cfg(feature = "cache")]
#[test]
fn cache_reinitializes_for_different_generators_of_the_same_size() {
    let first_g1: Vec<ArkG1> = (0..8).map(|_| ArkG1::random()).collect();
    let first_g2: Vec<ArkG2> = (0..8).map(|_| ArkG2::random()).collect();
    let second_g1: Vec<ArkG1> = (0..8).map(|_| ArkG1::random()).collect();
    let second_g2: Vec<ArkG2> = (0..8).map(|_| ArkG2::random()).collect();

    ark_cache::init_cache(&first_g1, &first_g2);
    let first_cache = ark_cache::get_prepared_cache().unwrap();

    ark_cache::init_cache(&second_g1, &second_g2);
    let second_cache = ark_cache::get_prepared_cache().unwrap();

    assert!(!std::sync::Arc::ptr_eq(&first_cache, &second_cache));
}

#[cfg(feature = "cache")]
#[test]
fn cached_pairings_reject_generators_from_another_setup() {
    let cached_g1: Vec<ArkG1> = (0..8).map(|_| ArkG1::random()).collect();
    let cached_g2: Vec<ArkG2> = (0..8).map(|_| ArkG2::random()).collect();
    let other_g1: Vec<ArkG1> = (0..8).map(|_| ArkG1::random()).collect();
    let other_g2: Vec<ArkG2> = (0..8).map(|_| ArkG2::random()).collect();
    let variable_g1: Vec<ArkG1> = (0..8).map(|_| ArkG1::random()).collect();
    let variable_g2: Vec<ArkG2> = (0..8).map(|_| ArkG2::random()).collect();

    ark_cache::init_cache(&cached_g1, &cached_g2);

    assert_eq!(
        BN254::multi_pair_g2_setup(&variable_g1, &other_g2),
        BN254::multi_pair(&variable_g1, &other_g2)
    );
    assert_eq!(
        BN254::multi_pair_g1_setup(&other_g1, &variable_g2),
        BN254::multi_pair(&other_g1, &variable_g2)
    );
}

#[cfg(feature = "cache")]
#[test]
fn multi_pair_with_cache_optimization() {
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
