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
