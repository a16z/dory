//! Hardware-dependent GPU dispatch thresholds.
//!
//! Below [`min_gpu_pairs`] the CPU arkworks path is faster due to GPU dispatch
//! overhead. Run `cargo bench --bench metal_crossover --features metal-gpu,arkworks`
//! to calibrate for your hardware.

/// Minimum number of pairing pairs before the GPU path is worthwhile.
///
/// Below this threshold, `multi_miller_loop` / `multi_pair` fall back to
/// the CPU arkworks implementation automatically.
///
/// Default is calibrated for Apple M-series (M1/M2/M3) — re-run the
/// `metal_crossover` benchmark on other hardware and update accordingly.
static MIN_GPU_PAIRS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(DEFAULT_MIN_GPU_PAIRS);

/// Default calibrated on Apple M-series: GPU dispatch overhead is ~70ms,
/// CPU runs at ~135µs/pair, so crossover is around 512 pairs.
const DEFAULT_MIN_GPU_PAIRS: usize = 512;

/// Get the current GPU dispatch threshold.
pub fn min_gpu_pairs() -> usize {
    MIN_GPU_PAIRS.load(std::sync::atomic::Ordering::Relaxed)
}

/// Override the GPU dispatch threshold at runtime.
///
/// Call this after running the crossover benchmark to set the optimal
/// value for the current hardware.
pub fn set_min_gpu_pairs(n: usize) {
    MIN_GPU_PAIRS.store(n, std::sync::atomic::Ordering::Relaxed);
}
