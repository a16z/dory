//! Recursion support for Dory polynomial commitment verification.
//!
//! This module provides infrastructure for recursive proof composition by enabling:
//!
//! 1. **Witness Generation**: Capture detailed traces of all arithmetic operations
//!    during verification, suitable for proving in a bespoke SNARK.
//!
//! 2. **Hint-Based Verification**: Run verification using pre-computed hints instead
//!    of performing expensive operations, enabling faster  verification.
//!
//! # Architecture
//!
//! The recursion system is built around these core abstractions:
//!
//! - [`TraceContext`]: Unified context managing witness generation or hint-based modes
//! - Internal trace wrappers (`TraceG1`, `TraceG2`, `TraceGT`): Auto-trace operations
//! - Internal operators (`TracePairing`): Traced pairing operations
//! - [`HintMap`]: Hint storage for operation results
//! - [`WitnessBackend`]: Backend-defined witness types
//!
//! # Usage
//!
//! ```ignore
//! use std::rc::Rc;
//! use dory_pcs::recursion::TraceContext;
//! use dory_pcs::verify_recursive;
//!
//! // Witness generation mode
//! let ctx = Rc::new(TraceContext::for_witness_gen());
//! verify_recursive::<_, E, M1, M2, _, W, Gen>(
//!     commitment, evaluation, &point, &proof, setup.clone(), &mut transcript, ctx.clone()
//! )?;
//! let witnesses = Rc::try_unwrap(ctx).ok().unwrap().finalize();
//!
//! // Convert to lightweight hints
//! let hints = witnesses.unwrap().to_hints::<E>();
//!
//! // Hint-based verification (with fallback on missing hints)
//! let ctx = Rc::new(TraceContext::for_hints(hints));
//! verify_recursive::<_, E, M1, M2, _, W, Gen>(
//!     commitment, evaluation, &point, &proof, setup, &mut transcript, ctx
//! )?;
//! ```

pub mod ast;
pub mod challenges;
mod collection;
mod collector;
mod context;
mod hint_map;
pub mod input_provider;
pub mod parallel;
mod trace;
mod witness;

pub use challenges::{precompute_challenges, ChallengeSet, RoundChallenges};
pub use collection::WitnessCollection;
pub use collector::WitnessGenerator;
pub use context::{CtxHandle, ExecutionMode, TraceContext};
pub use hint_map::{HintMap, HintResult};
pub use input_provider::{DoryInputProvider, DoryInputProviderWithCommitment};
pub use parallel::{EvalResult, InputProvider, OperationEvaluator, TaskExecutor};
pub use witness::{OpId, OpType, WitnessBackend, WitnessResult};

pub(crate) use collector::{OpIdBuilder, WitnessCollector};
pub(crate) use trace::{TraceG1, TraceG2, TraceGT, TracePairing};
