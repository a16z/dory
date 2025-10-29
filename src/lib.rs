//! # dory
//!
//! A high performance and modular implementation of the Dory polynomial commitment scheme.
//!
//! Dory is a transparent polynomial commitment scheme with excellent asymptotic
//! performance, based on the work of Jonathan Lee
//! ([eprint 2020/1274](https://eprint.iacr.org/2020/1274)).
//!
//! ## Structure
//!
//! ### Core Modules
//! - [`primitives`] - Core traits and abstractions
//!   - [`primitives::arithmetic`] - Field, group, and pairing curve traits
//!   - [`primitives::poly`] - Multilinear polynomial traits and operations
//!   - [`primitives::transcript`] - Fiat-Shamir transcript trait
//!   - [`primitives::serialization`] - Serialization abstractions
//! - [`setup`] - Transparent setup generation for prover and verifier
//! - [`evaluation_proof`] - Evaluation proof creation and verification
//! - [`reduce_and_fold`] - Inner product protocol state machines (prover/verifier)
//! - [`messages`] - Protocol message structures (VMV, reduce rounds, scalar product)
//! - [`proof`] - Complete proof data structure
//! - [`error`] - Error types
//!
//! ### Backend Implementations
//! - [`backends`] - Concrete backend implementations (available with feature flags)
//!   - [`backends::arkworks`] - Arkworks backend with BN254 curve (requires `arkworks` feature)
//!   - [`backends::blake2b_transcript`] - Blake2b-based Fiat-Shamir transcript
//!
//! ## Usage
//!
//! ```ignore
//! use dory::{setup, prove, verify};
//!
//! // 1. Generate setup
//! let (prover_setup, verifier_setup) = setup::<BN254, _>(&mut rng, max_log_n);
//!
//! // 2. Commit and prove
//! let (commitment, evaluation, proof) = prove(
//!     &polynomial, &point, None, nu, sigma, &prover_setup, &mut transcript
//! )?;
//!
//! // 3. Verify
//! verify(commitment, evaluation, &point, &proof, nu, sigma, verifier_setup, &mut transcript)?;
//! ```

pub mod error;
pub mod evaluation_proof;
pub mod messages;
pub mod primitives;
pub mod proof;
pub mod reduce_and_fold;
pub mod setup;

#[cfg(feature = "arkworks")]
pub mod backends;

pub use error::DoryError;
pub use evaluation_proof::create_evaluation_proof;
pub use messages::{FirstReduceMessage, ScalarProductMessage, SecondReduceMessage, VMVMessage};
use primitives::arithmetic::{DoryRoutines, Field, Group, PairingCurve};
pub use primitives::poly::{DoryCommitment, MultilinearLagrange, Polynomial};
pub use proof::DoryProof;
pub use reduce_and_fold::{DoryProverState, DoryVerifierState};
pub use setup::{ProverSetup, VerifierSetup};

/// Generate prover and verifier setups
///
/// Creates the transparent setup parameters for Dory PCS with square matrices.
/// Supports polynomials up to 2^max_log_n coefficients arranged as n×n matrices
/// where n = 2^((max_log_n+1)/2).
///
/// # Parameters
/// - `rng`: Random number generator for setup generation
/// - `max_log_n`: Maximum log₂ of polynomial size
///
/// # Returns
/// `(ProverSetup, VerifierSetup)` - Setup parameters for proving and verification
pub fn setup<E: PairingCurve, R: rand_core::RngCore>(
    rng: &mut R,
    max_log_n: usize,
) -> (ProverSetup<E>, VerifierSetup<E>) {
    let prover_setup = ProverSetup::new(rng, max_log_n);
    let verifier_setup = prover_setup.to_verifier_setup();
    (prover_setup, verifier_setup)
}

/// Evaluate a polynomial at a point and create proof
///
/// This is the main proving function that:
/// 1. Commits to the polynomial (if commitment not provided)
/// 2. Evaluates it at the given point
/// 3. Creates an evaluation proof
///
/// # Parameters
/// - `polynomial`: Polynomial implementing MultilinearLagrange trait
/// - `point`: Evaluation point (length nu + sigma)
/// - `commitment`: Optional precomputed [`DoryCommitment`] containing both tier-1 and tier-2 commitments
/// - `nu`: Log₂ of number of rows
/// - `sigma`: Log₂ of number of columns
/// - `setup`: Prover setup
/// - `transcript`: Fiat-Shamir transcript
///
/// # Returns
/// `(commitment, evaluation, proof)` - The tier-2 commitment, polynomial evaluation, and its proof
#[allow(clippy::type_complexity)]
pub fn prove<F, E, M1, M2, P, T>(
    polynomial: &P,
    point: &[F],
    commitment: Option<DoryCommitment<E::G1, E::GT>>,
    nu: usize,
    sigma: usize,
    setup: &ProverSetup<E>,
    transcript: &mut T,
) -> Result<(E::GT, F, DoryProof<E::G1, E::G2, E::GT>), DoryError>
where
    F: Field,
    E: PairingCurve,
    E::G1: Group<Scalar = F>,
    E::G2: Group<Scalar = F>,
    E::GT: Group<Scalar = F>,
    M1: DoryRoutines<E::G1>,
    M2: DoryRoutines<E::G2>,
    P: MultilinearLagrange<F>,
    T: primitives::transcript::Transcript<Curve = E>,
{
    // 1. Commit to polynomial if not provided (get commitment and row_commitments)
    let (tier_2, row_commitments) = if let Some(comm) = commitment {
        (comm.tier_2, comm.tier_1)
    } else {
        polynomial.commit::<E, M1>(nu, sigma, setup)?
    };

    // 2. Evaluate polynomial at point
    let evaluation = polynomial.evaluate(point);

    // 3. Create evaluation proof using row_commitments
    let proof = evaluation_proof::create_evaluation_proof::<F, E, M1, M2, T, P>(
        polynomial,
        point,
        Some(row_commitments),
        nu,
        sigma,
        setup,
        transcript,
    )?;

    Ok((tier_2, evaluation, proof))
}

/// Verify an evaluation proof
///
/// Verifies that a committed polynomial evaluates to the claimed value at the given point.
///
/// # Parameters
/// - `commitment`: Polynomial commitment (in GT)
/// - `evaluation`: Claimed evaluation result
/// - `point`: Evaluation point (length nu + sigma)
/// - `proof`: Evaluation proof to verify
/// - `nu`: Log₂ of number of rows
/// - `sigma`: Log₂ of number of columns
/// - `setup`: Verifier setup
/// - `transcript`: Fiat-Shamir transcript
///
/// # Returns
/// `Ok(())` if proof is valid, `Err(DoryError)` otherwise
#[allow(clippy::too_many_arguments)]
pub fn verify<F, E, M1, M2, T>(
    commitment: E::GT,
    evaluation: F,
    point: &[F],
    proof: &DoryProof<E::G1, E::G2, E::GT>,
    nu: usize,
    sigma: usize,
    setup: VerifierSetup<E>,
    transcript: &mut T,
) -> Result<(), DoryError>
where
    F: Field,
    E: PairingCurve + Clone,
    E::G1: Group<Scalar = F>,
    E::G2: Group<Scalar = F>,
    E::GT: Group<Scalar = F>,
    M1: DoryRoutines<E::G1>,
    M2: DoryRoutines<E::G2>,
    T: primitives::transcript::Transcript<Curve = E>,
{
    evaluation_proof::verify_evaluation_proof::<F, E, M1, M2, T>(
        commitment, evaluation, point, proof, nu, sigma, setup, transcript,
    )
}
