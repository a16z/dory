//! Pins the order, roles and widths of Dory's Fiat-Shamir draws.
//!
//! A transcript sizes each draw from its [`Challenge`] role. That is sound
//! only while the draws come in the order the trait documents, and each
//! short draw opens a squeeze run whose bad values its loss covers. These
//! tests record real proofs and check both, so a change to the draw order
//! fails here.

use super::*;
use ark_ff::{BigInteger, PrimeField};
use dory_pcs::backends::arkworks::{ArkG1, ArkG2, ArkGT};
use dory_pcs::primitives::arithmetic::Group;
use dory_pcs::primitives::poly::Polynomial;
use dory_pcs::primitives::transcript::{Challenge, ChallengeWidth, Transcript};
use dory_pcs::primitives::DorySerialize;
use dory_pcs::{prove, verify, Mode, Transparent};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Event {
    /// An absorbed message, by its compressed length in bytes.
    Absorb(usize),
    Draw(Challenge),
}

/// A transcript that logs every absorb and draw of the transcript it wraps.
struct Recording<T> {
    inner: T,
    events: Vec<Event>,
}

impl<T> Recording<T> {
    fn new(inner: T) -> Self {
        Self {
            inner,
            events: Vec::new(),
        }
    }
}

impl<T: Transcript<Curve = BN254>> Transcript for Recording<T> {
    type Curve = BN254;

    fn append_serde<S: DorySerialize>(&mut self, s: &S) {
        self.events.push(Event::Absorb(s.compressed_size()));
        self.inner.append_serde(s);
    }

    fn challenge_scalar(&mut self, challenge: Challenge) -> ArkFr {
        self.events.push(Event::Draw(challenge));
        self.inner.challenge_scalar(challenge)
    }
}

/// The soundness target per squeeze run of [`Shortening`].
const SECURITY_BITS: u32 = 128;

/// The least `b` with `2^b ≥ loss · 2^SECURITY_BITS`.
fn short_bits(loss: u64) -> u32 {
    SECURITY_BITS + (u64::BITS - (loss - 1).leading_zeros())
}

/// A transcript that draws short challenges at the narrowest width their
/// loss allows, by masking a full-width draw. Masking a value reduced
/// modulo the field order is close enough to uniform for a completeness
/// test, but not for a real transcript.
struct Shortening(Blake2bTranscript<BN254>);

impl Transcript for Shortening {
    type Curve = BN254;

    fn append_serde<S: DorySerialize>(&mut self, s: &S) {
        self.0.append_serde(s);
    }

    fn challenge_scalar(&mut self, challenge: Challenge) -> ArkFr {
        let full = self.0.challenge_scalar(challenge);
        let ChallengeWidth::Short { loss } = challenge.width() else {
            return full;
        };
        let bits = short_bits(loss) as usize;
        let mut bytes = Vec::new();
        full.serialize_compressed(&mut bytes).unwrap();
        for (index, byte) in bytes.iter_mut().enumerate() {
            let kept = bits.saturating_sub(8 * index).min(8);
            *byte &= ((1u16 << kept) - 1) as u8;
        }
        ArkFr(ark_bn254::Fr::from_le_bytes_mod_order(&bytes))
    }
}

fn gt() -> Event {
    Event::Absorb(ArkGT::identity().compressed_size())
}

fn g1() -> Event {
    Event::Absorb(ArkG1::identity().compressed_size())
}

fn g2() -> Event {
    Event::Absorb(ArkG2::identity().compressed_size())
}

#[cfg(feature = "zk")]
fn fr() -> Event {
    Event::Absorb(ArkFr::zero().compressed_size())
}

fn draw(challenge: Challenge) -> Event {
    Event::Draw(challenge)
}

/// The VMV message `(C, D₂, E₁)`.
fn vmv() -> Vec<Event> {
    vec![gt(), gt(), g1()]
}

/// Each reduce round: the first message, `β`, the second message, `α`.
fn reduce_rounds(rounds: usize) -> Vec<Event> {
    let round = [
        gt(),
        gt(),
        gt(),
        gt(),
        g1(),
        g2(),
        draw(Challenge::Beta),
        gt(),
        gt(),
        g1(),
        g1(),
        g2(),
        g2(),
        draw(Challenge::Alpha),
    ];
    round.repeat(rounds)
}

fn transparent_schedule(rounds: usize) -> Vec<Event> {
    let mut events = vmv();
    events.extend(reduce_rounds(rounds));
    events.push(draw(Challenge::Gamma));
    // The revealed final witness `(E₁, E₂)`.
    events.extend([g1(), g2(), draw(Challenge::D)]);
    events
}

#[cfg(feature = "zk")]
fn zk_schedule(rounds: usize) -> Vec<Event> {
    let mut events = vmv();
    // `E₂` and the evaluation commitment.
    events.extend([g2(), g1()]);
    // Σ₁: commitments `(A₁, A₂)`, then `c`. Its responses are checked at
    // once and not absorbed.
    events.extend([g2(), g1(), draw(Challenge::Sigma1)]);
    // Σ₂: commitment `A`, then `c₂`, then the responses `(z₁, z₂)`.
    events.extend([gt(), draw(Challenge::Sigma2), fr(), fr()]);
    events.extend(reduce_rounds(rounds));
    events.push(draw(Challenge::Gamma));
    // Scalar-product Σ-proof: `(P₁, P₂, Q, R)`, then `c`, then the
    // responses `(E₁, E₂, r₁, r₂, r₃)`.
    events.extend([gt(), gt(), gt(), gt(), draw(Challenge::ScalarProduct)]);
    events.extend([g1(), g2(), fr(), fr(), fr(), draw(Challenge::D)]);
    events
}

/// `(nu, sigma)` shapes, square and not.
const SHAPES: [(usize, usize); 5] = [(1, 1), (1, 2), (2, 2), (2, 3), (3, 3)];

/// Proves and verifies one random evaluation in mode `Mo` with transcripts
/// built by `transcript`, and returns the prover's and verifier's logs.
fn record<Mo: Mode, T: Transcript<Curve = BN254>>(
    nu: usize,
    sigma: usize,
    transcript: impl Fn() -> T,
) -> (Vec<Event>, Vec<Event>) {
    let (prover_setup, verifier_setup) = test_setup_pair(2 * sigma);
    let poly = random_polynomial(1 << (nu + sigma));
    let point = random_point(nu + sigma);
    let (commitment, row_commitments, commit_blind) = poly
        .commit::<BN254, Mo, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let mut prover_transcript = Recording::new(transcript());
    let (proof, _) = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, Mo>(
        &poly,
        &point,
        row_commitments,
        commit_blind,
        nu,
        sigma,
        &prover_setup,
        &mut prover_transcript,
    )
    .unwrap();

    let mut verifier_transcript = Recording::new(transcript());
    verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        commitment,
        poly.evaluate(&point),
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    )
    .unwrap();

    (prover_transcript.events, verifier_transcript.events)
}

/// Checks that each short draw opens a squeeze run, a maximal sequence of
/// draws with no absorb between them, and that its loss covers the bad
/// values of every draw in the run.
fn check_squeeze_runs(events: &[Event]) {
    let mut index = 0;
    while index < events.len() {
        if !matches!(events[index], Event::Draw(_)) {
            index += 1;
            continue;
        }
        let run: Vec<Challenge> = events[index..]
            .iter()
            .map_while(|event| match event {
                Event::Draw(challenge) => Some(*challenge),
                Event::Absorb(_) => None,
            })
            .collect();
        assert!(
            matches!(events.get(index.wrapping_sub(1)), Some(Event::Absorb(_))),
            "the run at {index} does not follow an absorb"
        );
        for later in &run[1..] {
            assert_eq!(
                later.width(),
                ChallengeWidth::Full,
                "short {later:?} does not open its run {run:?}"
            );
        }
        if let ChallengeWidth::Short { loss } = run[0].width() {
            let bad: u64 = run.iter().map(|challenge| challenge.bad_values()).sum();
            assert!(loss >= bad, "{run:?} has {bad} bad values, charged {loss}");
        }
        index += run.len();
    }
}

#[test]
fn widths_and_bad_values_are_pinned() {
    use Challenge::*;
    let table = [
        (Beta, 2, ChallengeWidth::Short { loss: 2 }),
        (Alpha, 2, ChallengeWidth::Short { loss: 4 }),
        (Gamma, 2, ChallengeWidth::Full),
        (D, 3, ChallengeWidth::Short { loss: 3 }),
        (Sigma1, 1, ChallengeWidth::Full),
        (Sigma2, 1, ChallengeWidth::Full),
        (ScalarProduct, 2, ChallengeWidth::Full),
    ];
    for (challenge, bad, width) in table {
        assert_eq!(challenge.bad_values(), bad, "{challenge:?}");
        assert_eq!(challenge.width(), width, "{challenge:?}");
    }
    // At a 128-bit target: β at 129 bits, α and d at 130.
    assert_eq!(short_bits(2), 129);
    assert_eq!(short_bits(3), 130);
    assert_eq!(short_bits(4), 130);
}

#[test]
fn transparent_draw_schedule() {
    for (nu, sigma) in SHAPES {
        let (prover, verifier) = record::<Transparent, _>(nu, sigma, fresh_transcript);
        assert_eq!(prover, verifier, "nu={nu}, sigma={sigma}");
        assert_eq!(
            verifier,
            transparent_schedule(sigma),
            "nu={nu}, sigma={sigma}"
        );
        check_squeeze_runs(&verifier);
    }
}

#[cfg(feature = "zk")]
#[test]
fn zk_draw_schedule() {
    for (nu, sigma) in SHAPES {
        let (prover, verifier) = record::<dory_pcs::ZK, _>(nu, sigma, fresh_transcript);
        assert_eq!(prover, verifier, "nu={nu}, sigma={sigma}");
        assert_eq!(verifier, zk_schedule(sigma), "nu={nu}, sigma={sigma}");
        check_squeeze_runs(&verifier);
    }
}

/// Dory proves and verifies with short `β`, `α` and `d`.
#[test]
fn short_draws_verify() {
    let shortening = || Shortening(fresh_transcript());
    for (nu, sigma) in SHAPES {
        record::<Transparent, _>(nu, sigma, shortening);
        #[cfg(feature = "zk")]
        record::<dory_pcs::ZK, _>(nu, sigma, shortening);
    }

    let mut transcript = Shortening(fresh_transcript());
    transcript.append_serde(&ArkFr::one());
    let beta = transcript.challenge_scalar(Challenge::Beta);
    assert!(beta.0.into_bigint().num_bits() <= short_bits(2));
}
