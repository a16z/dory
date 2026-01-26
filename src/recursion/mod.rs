//! Recursion support for Dory polynomial commitment verification.
//!
//! This module provides infrastructure for recursive proof composition by enabling:
//!
//! 1. **Witness Generation**: Capture detailed traces of all arithmetic operations
//!    during verification, suitable for proving in a bespoke SNARK.
//!
//! 2. **Symbolic Verification**: Build an AST of verification operations without
//!    performing expensive group computations, for circuit generation.
//!
//! # Architecture
//!
//! The recursion system is built around these core abstractions:
//!
//! - [`TraceContext`]: Unified context managing witness generation or symbolic modes
//! - Internal trace wrappers (`TraceG1`, `TraceG2`, `TraceGT`): Auto-trace operations
//! - Internal operators (`TracePairing`): Traced pairing operations
//! - [`WitnessBackend`]: Backend-defined witness types
//!
//! # Usage
//!
//! ```ignore
//! use std::rc::Rc;
//! use dory_pcs::recursion::TraceContext;
//! use dory_pcs::verify_recursive;
//!
//! // Witness generation mode (prover)
//! let ctx = Rc::new(TraceContext::for_witness_gen());
//! verify_recursive::<_, E, M1, M2, _, W, Gen>(
//!     commitment, evaluation, &point, &proof, setup.clone(), &mut transcript, ctx.clone()
//! )?;
//! let witnesses = Rc::try_unwrap(ctx).ok().unwrap().finalize();
//!
//! // Symbolic mode (verifier recursion) - builds AST only
//! let ctx = Rc::new(TraceContext::for_symbolic());
//! verify_recursive::<_, E, M1, M2, _, W, Gen>(
//!     commitment, evaluation, &point, &proof, setup, &mut transcript, ctx
//! )?;
//! let ast = ctx.finalize_ast();
//! ```

pub mod ast;
mod backend;
pub mod challenges;
mod collection;
mod collector;
mod context;
mod trace;
mod witness;

pub use backend::TracingBackend;
pub use challenges::{precompute_challenges, ChallengeSet, RoundChallenges};
pub use collection::WitnessCollection;
pub use collector::WitnessGenerator;
pub use context::{CtxHandle, ExecutionMode, TraceContext};
pub use witness::{OpId, OpType, WitnessBackend, WitnessResult};

pub(crate) use collector::{OpIdBuilder, WitnessCollector};
pub use trace::{TraceG1, TraceG2, TraceGT};

/// A baseline witness backend/generator for BN254 (arkworks).
///
/// Upstream proof systems can use this as a default starting point, or replace it by
/// implementing [`WitnessBackend`] and [`WitnessGenerator`] with richer traces.
#[cfg(feature = "arkworks")]
pub use crate::backends::arkworks::{SimpleWitnessBackend, SimpleWitnessGenerator};
