//! Setup generation tests

use super::*;
use dory::setup::ProverSetup;

#[test]
fn test_setup_generation_small() {
    let setup = test_setup(4);
    assert_eq!(setup.max_log_n(), 4);
    assert_eq!(setup.max_nu(), 2);
    assert_eq!(setup.max_sigma(), 2);
    assert_eq!(setup.g1_vec.len(), 4);
    assert_eq!(setup.g2_vec.len(), 4);
}

#[test]
fn test_setup_generation_medium() {
    let setup = test_setup(8);
    assert_eq!(setup.max_log_n(), 8);
    assert_eq!(setup.max_nu(), 4);
    assert_eq!(setup.max_sigma(), 4);
    assert_eq!(setup.g1_vec.len(), 16);
    assert_eq!(setup.g2_vec.len(), 16);
}

#[test]
fn test_setup_generation_large() {
    let setup = test_setup(12);
    assert_eq!(setup.max_log_n(), 12);
    assert_eq!(setup.max_nu(), 6);
    assert_eq!(setup.max_sigma(), 6);
    assert_eq!(setup.g1_vec.len(), 64);
    assert_eq!(setup.g2_vec.len(), 64);
}

#[test]
fn test_verifier_setup_derivation() {
    let prover_setup = test_setup(6);
    let verifier_setup = prover_setup.to_verifier_setup();

    assert_eq!(verifier_setup.max_log_n, 6);

    let max_nu = prover_setup.max_nu();
    assert_eq!(verifier_setup.delta_1l.len(), max_nu + 1);
    assert_eq!(verifier_setup.delta_1r.len(), max_nu + 1);
    assert_eq!(verifier_setup.delta_2l.len(), max_nu + 1);
    assert_eq!(verifier_setup.delta_2r.len(), max_nu + 1);
    assert_eq!(verifier_setup.chi.len(), max_nu + 1);
}

#[test]
fn test_setup_consistency() {
    let setup1 = test_setup(6);
    let setup2 = test_setup(6);

    assert_ne!(setup1.g1_vec[0], setup2.g1_vec[0]);
    assert_ne!(setup1.g2_vec[0], setup2.g2_vec[0]);
}

#[test]
fn test_setup_disk_persistence() {
    use dory::backends::arkworks::BN254;
    use dory::setup::{load_setup, save_setup};

    let max_log_n = 10;

    let prover = test_setup(max_log_n);
    let verifier = prover.to_verifier_setup();

    save_setup::<BN254>(&prover, &verifier, max_log_n);

    let loaded = load_setup::<BN254>(max_log_n);
    assert!(loaded.is_ok(), "Failed to load setup from disk");

    let (loaded_prover, loaded_verifier) = loaded.unwrap();

    assert_eq!(loaded_prover.g1_vec.len(), prover.g1_vec.len());
    assert_eq!(loaded_prover.g2_vec.len(), prover.g2_vec.len());
    assert_eq!(loaded_prover.g1_vec[0], prover.g1_vec[0]);
    assert_eq!(loaded_prover.g2_vec[0], prover.g2_vec[0]);
    assert_eq!(loaded_prover.h1, prover.h1);
    assert_eq!(loaded_prover.h2, prover.h2);
    assert_eq!(loaded_prover.ht, prover.ht);

    assert_eq!(loaded_verifier.max_log_n, verifier.max_log_n);
    assert_eq!(loaded_verifier.chi.len(), verifier.chi.len());
    assert_eq!(loaded_verifier.g1_0, verifier.g1_0);
    assert_eq!(loaded_verifier.g2_0, verifier.g2_0);
}

#[test]
fn test_setup_function_uses_disk() {
    use dory::backends::arkworks::BN254;
    use dory::{generate_urs, setup};
    use rand::thread_rng;

    let mut rng = thread_rng();

    let max_log_n = 11;

    let (prover1, verifier1) = generate_urs::<BN254, _>(&mut rng, max_log_n);

    let (prover2, verifier2) = setup::<BN254, _>(&mut rng, max_log_n);

    assert_eq!(prover1.g1_vec[0], prover2.g1_vec[0]);
    assert_eq!(prover1.g2_vec[0], prover2.g2_vec[0]);
    assert_eq!(verifier1.chi[0], verifier2.chi[0]);
}
