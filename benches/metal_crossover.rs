//! Find the GPU vs CPU crossover point for multi_miller_loop.
//!
//! Binary-searches over batch sizes to find the smallest n where GPU is faster.
//! Run with: cargo bench --bench metal_crossover --features metal-gpu,arkworks
//!
//! The output can be used to set `config::set_min_gpu_pairs()` for your hardware.

#![allow(missing_docs)]

use std::time::Instant;

use ark_bn254::{Bn254, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{pairing::Pairing, CurveGroup};
use ark_ff::UniformRand;
use dory_pcs::backends::metal::gpu::{EllCoeffLimbs, FpLimbs, NUM_ELL_COEFFS};
use dory_pcs::backends::metal::MetalGpu;

fn ark_fq_to_limbs(f: &ark_bn254::Fq) -> FpLimbs {
    let limbs64: [u64; 4] = unsafe { std::mem::transmute(*f) };
    let mut limbs = [0u32; 8];
    for (i, &w) in limbs64.iter().enumerate() {
        limbs[2 * i] = w as u32;
        limbs[2 * i + 1] = (w >> 32) as u32;
    }
    FpLimbs { limbs }
}

fn ark_fq2_to_gpu(f: &ark_bn254::Fq2) -> dory_pcs::backends::metal::gpu::Fp2Limbs {
    dory_pcs::backends::metal::gpu::Fp2Limbs {
        c0: ark_fq_to_limbs(&f.c0),
        c1: ark_fq_to_limbs(&f.c1),
    }
}

fn prepared_to_gpu(g2_prep: &<Bn254 as Pairing>::G2Prepared) -> Vec<EllCoeffLimbs> {
    g2_prep
        .ell_coeffs
        .iter()
        .map(|(c0, c1, c2)| EllCoeffLimbs {
            c0: ark_fq2_to_gpu(c0),
            c1: ark_fq2_to_gpu(c1),
            c2: ark_fq2_to_gpu(c2),
        })
        .collect()
}

const WARMUP_ITERS: usize = 3;
const BENCH_ITERS: usize = 5;

/// Measure median CPU time for n independent Miller loops + product reduction.
fn bench_cpu(g1s: &[G1Affine], g2_preps: &[<Bn254 as Pairing>::G2Prepared]) -> f64 {
    // Warmup
    for _ in 0..WARMUP_ITERS {
        let ps: Vec<<Bn254 as Pairing>::G1Prepared> = g1s.iter().copied().map(Into::into).collect();
        let _ = std::hint::black_box(Bn254::multi_miller_loop(ps, g2_preps.to_vec()));
    }

    let mut times = Vec::with_capacity(BENCH_ITERS);
    for _ in 0..BENCH_ITERS {
        let ps: Vec<<Bn254 as Pairing>::G1Prepared> = g1s.iter().copied().map(Into::into).collect();
        let start = Instant::now();
        let _ = std::hint::black_box(Bn254::multi_miller_loop(ps, g2_preps.to_vec()));
        times.push(start.elapsed().as_secs_f64());
    }
    times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    times[BENCH_ITERS / 2]
}

/// Measure median GPU time for n Miller loops + CPU product reduction.
/// Uses pre-allocated buffers to isolate kernel time.
fn bench_gpu(
    gpu: &mut MetalGpu,
    g1s: &[G1Affine],
    g2_preps: &[<Bn254 as Pairing>::G2Prepared],
) -> f64 {
    let n = g1s.len();
    let mut g1_xy = Vec::with_capacity(2 * n);
    let mut all_coeffs = Vec::with_capacity(n * NUM_ELL_COEFFS);
    for i in 0..n {
        g1_xy.push(ark_fq_to_limbs(&g1s[i].x));
        g1_xy.push(ark_fq_to_limbs(&g1s[i].y));
        all_coeffs.extend_from_slice(&prepared_to_gpu(&g2_preps[i]));
    }

    let bufs = gpu.alloc_miller(&g1_xy, &all_coeffs);
    let pipeline = gpu.pipeline("miller_loop").clone();

    // Warmup
    for _ in 0..WARMUP_ITERS {
        gpu.dispatch_miller(&pipeline, &bufs);
    }

    let mut times = Vec::with_capacity(BENCH_ITERS);
    for _ in 0..BENCH_ITERS {
        let start = Instant::now();
        gpu.dispatch_miller(&pipeline, &bufs);
        let results = MetalGpu::read_miller_results(&bufs);
        std::hint::black_box(&results);
        times.push(start.elapsed().as_secs_f64());
    }
    times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    times[BENCH_ITERS / 2]
}

/// Generate random test points of size n.
fn gen_points(n: usize) -> (Vec<G1Affine>, Vec<<Bn254 as Pairing>::G2Prepared>) {
    let mut rng = ark_std::test_rng();
    let g1s: Vec<G1Affine> = (0..n)
        .map(|_| G1Projective::rand(&mut rng).into_affine())
        .collect();
    let g2s: Vec<G2Affine> = (0..n)
        .map(|_| G2Projective::rand(&mut rng).into_affine())
        .collect();
    let g2_preps: Vec<_> = g2s
        .iter()
        .map(|q| <Bn254 as Pairing>::G2Prepared::from(*q))
        .collect();
    (g1s, g2_preps)
}

/// Returns true if GPU is faster than CPU at size n.
fn gpu_wins(gpu: &mut MetalGpu, n: usize) -> bool {
    let (g1s, g2_preps) = gen_points(n);
    let cpu_time = bench_cpu(&g1s, &g2_preps);
    let gpu_time = bench_gpu(gpu, &g1s, &g2_preps);
    let winner = if gpu_time < cpu_time { "GPU" } else { "CPU" };
    println!(
        "  n={n:>6}  cpu={cpu_ms:>8.2}ms  gpu={gpu_ms:>8.2}ms  winner={winner}",
        cpu_ms = cpu_time * 1000.0,
        gpu_ms = gpu_time * 1000.0,
    );
    gpu_time < cpu_time
}

fn main() {
    println!("Metal GPU vs CPU multi_miller_loop crossover finder");
    println!("====================================================\n");

    let mut gpu = MetalGpu::new();

    // GPU warmup — first dispatch compiles shaders
    println!("Warming up GPU...");
    {
        let (g1s, g2_preps) = gen_points(16);
        let mut g1_xy = Vec::new();
        let mut coeffs = Vec::new();
        for i in 0..16 {
            g1_xy.push(ark_fq_to_limbs(&g1s[i].x));
            g1_xy.push(ark_fq_to_limbs(&g1s[i].y));
            coeffs.extend_from_slice(&prepared_to_gpu(&g2_preps[i]));
        }
        let bufs = gpu.alloc_miller(&g1_xy, &coeffs);
        let pipeline = gpu.pipeline("miller_loop").clone();
        for _ in 0..5 {
            gpu.dispatch_miller(&pipeline, &bufs);
        }
    }
    println!("Warmup done.\n");

    // Phase 1: exponential scan to bracket the crossover
    println!("Phase 1: Exponential scan to bracket crossover region");
    println!("------------------------------------------------------");
    let mut lo;
    let mut hi;

    // Find first n where GPU wins
    let mut n = 4;
    loop {
        if gpu_wins(&mut gpu, n) {
            hi = n;
            lo = if n > 4 { n / 2 } else { 1 };
            break;
        }
        if n >= 1 << 16 {
            println!("\nGPU never won up to n={n}. CPU is faster for all tested sizes.");
            println!("Recommended: set_min_gpu_pairs({})", n + 1);
            return;
        }
        n *= 2;
    }

    println!("\nCrossover bracketed: [{lo}, {hi}]");
    println!();

    // Phase 2: binary search within bracket
    println!("Phase 2: Binary search for exact crossover");
    println!("--------------------------------------------");
    while hi - lo > 4 {
        let mid = (lo + hi) / 2;
        // Round to nearest power-of-2 aligned value for cleaner results
        if gpu_wins(&mut gpu, mid) {
            hi = mid;
        } else {
            lo = mid;
        }
    }

    // Phase 3: fine-grained sweep of the narrow region
    println!("\nPhase 3: Fine sweep of [{lo}, {hi}]");
    println!("-------------------------------------");
    let mut crossover = hi;
    for n in lo..=hi {
        if gpu_wins(&mut gpu, n) {
            crossover = n;
            break;
        }
    }

    println!("\n====================================================");
    println!("RESULT: GPU becomes faster at n >= {crossover}");
    println!("====================================================");
    println!();
    println!("To apply this threshold in your code:");
    println!("  dory_pcs::backends::metal::config::set_min_gpu_pairs({crossover});");
}
