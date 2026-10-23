//! Transcript trait for Fiat-Shamir transformations
//!
//! Dory's transcript use is positional. The verifier fixes the order, the
//! type and the serialized length of every absorbed message from the
//! statement and the proof shape (`nu`, `sigma`, the mode), so the trait
//! takes no labels. A transcript that wants domain separation applies it
//! once, before Dory runs.
//!
//! Each draw names its [`Challenge`] role instead. The role carries the
//! soundness facts a transcript needs to size the draw: how many challenge
//! values can let a false claim through ([`Challenge::bad_values`]) and
//! whether the draw may be short ([`Challenge::width`]).
//!
//! # Draw order
//!
//! With `r = sigma` reduce rounds, Dory draws, in order:
//!
//! - Transparent mode: (`Beta`, `Alpha`) × r, `Gamma`, `D`.
//! - Zero-knowledge mode: `Sigma1`, `Sigma2`, (`Beta`, `Alpha`) × r,
//!   `Gamma`, `ScalarProduct`, `D`.
//!
//! Every draw follows an absorb except `Gamma`, which follows the last
//! `Alpha` directly. `tests/arkworks/draw_schedule.rs` pins this order and
//! the absorbs between the draws. Changing it is a breaking change.

use crate::primitives::arithmetic::{Group, PairingCurve};
use crate::primitives::DorySerialize;

/// A Fiat-Shamir challenge Dory draws, by its role in the protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Challenge {
    /// `β`, drawn in each reduce round after the first reduce message.
    Beta,
    /// `α`, drawn in each reduce round after the second reduce message.
    Alpha,
    /// `γ`, the Fold-Scalars challenge. It is drawn right after the last
    /// round's `α`, with no absorb in between.
    Gamma,
    /// `d`, the batching challenge of the final pairing check. It is Dory's
    /// last draw: a caller that draws again before absorbing adds that draw
    /// to `d`'s squeeze run.
    D,
    /// `c` of the Σ₁ proof of the evaluation commitment (zero-knowledge mode).
    Sigma1,
    /// `c₂` of the Σ₂ proof of the VMV constraint (zero-knowledge mode).
    Sigma2,
    /// `c` of the scalar-product Σ-proof (zero-knowledge mode).
    ScalarProduct,
}

/// How wide a transcript may draw a [`Challenge`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChallengeWidth {
    /// Uniform over the scalar field.
    Full,
    /// Uniform over the integers `[0, 2^b)`, for any `b` below the scalar
    /// field's bit length with `2^b ≥ loss · 2^λ`, where `λ` is the
    /// transcript's soundness target per squeeze run. Then a false claim
    /// survives the squeeze run this draw opens with probability at most
    /// `2^-λ`.
    ///
    /// `loss` covers this draw and every full-width draw that follows it
    /// before the next absorb. A full-width draw's set is larger than
    /// `2^b`, so its bad values cost no more than this draw's.
    ///
    /// The value 0 can be drawn. The verifier rejects it, because it inverts
    /// the challenge. A transcript may always draw full width instead.
    Short {
        /// Bad values charged to this draw's squeeze run.
        loss: u64,
    },
}

impl Challenge {
    /// The most challenge values for which a false claim survives this draw.
    ///
    /// The verifier's checks after the draw are Laurent polynomials in the
    /// challenge `x`. When the claim before the draw is false, the prover's
    /// messages (in the algebraic group model, under SXDH) make some check
    /// a nonzero Laurent polynomial spanning `x^lo` to `x^hi`. Otherwise the
    /// prover has broken Dory's binding. Such a polynomial has at most
    /// `hi - lo` nonzero roots. The spans are:
    ///
    /// - `Beta`: `β⁻¹` to `β` in the round's `C`, `D` and `E` updates. 2.
    /// - `Alpha`: `α⁻¹` to `α` in the fold. 2.
    /// - `Gamma`: `γ⁻¹` to `γ` in Fold-Scalars. 2.
    /// - `D`: `d⁻¹` to `d²` in the final pairing check. 3.
    /// - `Sigma1`, `Sigma2`: the responses are linear in `c`. 1.
    /// - `ScalarProduct`: the response `r₃` is quadratic in `c`. 2.
    pub const fn bad_values(self) -> u64 {
        match self {
            Self::Beta | Self::Alpha | Self::Gamma | Self::ScalarProduct => 2,
            Self::D => 3,
            Self::Sigma1 | Self::Sigma2 => 1,
        }
    }

    /// How wide a transcript may draw this challenge.
    ///
    /// The verifier multiplies group elements, `GT` ones included, by `β`,
    /// `α` and `d`, in every round for `β` and `α`. So those three are short,
    /// which halves the cost of those multiplications. The others stay full
    /// width. The verifier uses `γ` only as `-γ` and `γ⁻¹`, and it squares
    /// the `Sigma2` and `ScalarProduct` challenges or multiplies them by
    /// other challenges, so those values are full width anyway. The `Sigma1`
    /// challenge scales one `G1` and one `G2` element once, which is too
    /// little to be worth shortening.
    ///
    /// The last `α` opens a squeeze run that `γ` closes, so `Alpha` is
    /// charged for `γ`'s bad values too. Every `α` takes that loss, so all
    /// rounds draw alike.
    pub const fn width(self) -> ChallengeWidth {
        match self {
            Self::Beta | Self::D => ChallengeWidth::Short {
                loss: self.bad_values(),
            },
            Self::Alpha => ChallengeWidth::Short {
                loss: Self::Alpha.bad_values() + Self::Gamma.bad_values(),
            },
            Self::Gamma | Self::Sigma1 | Self::Sigma2 | Self::ScalarProduct => ChallengeWidth::Full,
        }
    }
}

/// The scalar field of a transcript's curve.
pub type TranscriptScalar<T> = <<<T as Transcript>::Curve as PairingCurve>::G1 as Group>::Scalar;

/// Transcript to standardize Fiat-Shamir across different transcript
/// implementations.
pub trait Transcript {
    /// The pairing curve whose scalars the transcript draws.
    type Curve: PairingCurve;

    /// Absorbs one prover message. Its type, and so its serialized length,
    /// is fixed by its position in the protocol.
    fn append_serde<S: DorySerialize>(&mut self, s: &S);

    /// Draws the challenge `challenge`, at a width
    /// [`Challenge::width`] allows.
    fn challenge_scalar(&mut self, challenge: Challenge) -> TranscriptScalar<Self>;
}
