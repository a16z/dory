//! GPU-accelerated pairing via Metal.
//!
//! Provides both standalone functions and a `MetalBN254` type that implements
//! `PairingCurve`, so you can use it as a drop-in replacement for `BN254`:
//!
//! ```ignore
//! // Standalone:
//! let result = dory_pcs::backends::metal::multi_pair(&ps, &qs);
//!
//! // Via trait (works with prove/verify):
//! prove::<_, MetalBN254, G1Routines, G2Routines, _, _, Transparent>(...);
//! ```
//!
//! A lazily-initialized `MetalGpu` is shared across calls. The GPU path
//! is only used when the batch size exceeds [`config::min_gpu_pairs()`].

use std::sync::{Mutex, OnceLock};

use ark_bn254::{Bn254, G1Affine, G2Affine};
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;

use crate::backends::arkworks::{ArkG1, ArkG2, ArkGT};
use crate::primitives::arithmetic::PairingCurve;

use super::gpu::MetalGpu;

fn gpu() -> &'static Mutex<MetalGpu> {
    static GPU: OnceLock<Mutex<MetalGpu>> = OnceLock::new();
    GPU.get_or_init(|| Mutex::new(MetalGpu::new()))
}

fn to_g1_affines(ps: &[ArkG1]) -> Vec<G1Affine> {
    ps.iter().map(|p| p.0.into_affine()).collect()
}

fn to_g2_affines(qs: &[ArkG2]) -> Vec<G2Affine> {
    qs.iter().map(|q| q.0.into_affine()).collect()
}

/// GPU-accelerated multi-pairing: Π e(p_i, q_i).
///
/// Drop-in replacement for `BN254::multi_pair`. Falls back to CPU
/// when `n < config::min_gpu_pairs()`.
pub fn multi_pair(ps: &[ArkG1], qs: &[ArkG2]) -> ArkGT {
    assert_eq!(ps.len(), qs.len());
    if ps.is_empty() {
        return ArkGT::default();
    }

    let g1s = to_g1_affines(ps);
    let g2s = to_g2_affines(qs);

    let result = gpu()
        .lock()
        .expect("MetalGpu lock poisoned")
        .multi_pair(&g1s, &g2s);

    ArkGT(result.0)
}

/// GPU-accelerated multi-pairing for G2 points from setup.
///
/// Drop-in replacement for `BN254::multi_pair_g2_setup`.
pub fn multi_pair_g2_setup(ps: &[ArkG1], qs: &[ArkG2]) -> ArkGT {
    multi_pair(ps, qs)
}

/// GPU-accelerated multi-pairing for G1 points from setup.
///
/// Drop-in replacement for `BN254::multi_pair_g1_setup`.
pub fn multi_pair_g1_setup(ps: &[ArkG1], qs: &[ArkG2]) -> ArkGT {
    multi_pair(ps, qs)
}

/// GPU-accelerated BN254 pairing curve.
///
/// Implements `PairingCurve` so it can be used directly with `prove`/`verify`:
/// ```ignore
/// prove::<_, MetalBN254, G1Routines, G2Routines, _, _, Transparent>(...);
/// ```
///
/// Reuses the same `ArkG1`/`ArkG2`/`ArkGT` types as `BN254`, so all existing
/// setup data, proofs, and group routines work unchanged.
#[derive(Default, Clone, Debug)]
pub struct MetalBN254;

impl PairingCurve for MetalBN254 {
    type G1 = ArkG1;
    type G2 = ArkG2;
    type GT = ArkGT;

    fn pair(p: &Self::G1, q: &Self::G2) -> Self::GT {
        ArkGT(Bn254::pairing(p.0, q.0).0)
    }

    fn multi_pair(ps: &[Self::G1], qs: &[Self::G2]) -> Self::GT {
        multi_pair(ps, qs)
    }

    fn multi_pair_g2_setup(ps: &[Self::G1], qs: &[Self::G2]) -> Self::GT {
        multi_pair_g2_setup(ps, qs)
    }

    fn multi_pair_g1_setup(ps: &[Self::G1], qs: &[Self::G2]) -> Self::GT {
        multi_pair_g1_setup(ps, qs)
    }
}
