// Multi-Scalar Multiplication via Pippenger's bucket method for BN254 G1.
//
// Algorithm: Pippenger with signed-digit scalar decomposition and
// counting-sort-based bucket assignment.
//
// Kernel pipeline (dispatched sequentially by the host):
//   1. g1_msm_decompose  — scalar -> signed-digit windows
//   2. g1_msm_histogram  — count points per bucket (atomic)
//   3. g1_msm_prefix_sum — exclusive scan for scatter offsets
//   4. g1_msm_scatter    — write point indices in sorted order (atomic)
//   5. g1_msm_accumulate — sum points in each bucket via mixed_add
//   6. g1_msm_reduce     — running-sum bucket reduction per window
//   7. g1_msm_finalize   — Horner combination across windows
//
// This file is concatenated after ec.metal by the Rust shader loader.

// ── MSM parameters (passed as constant buffer) ──────────────────

struct MsmParams {
    uint n;           // number of (scalar, point) pairs
    uint c;           // window size in bits
    uint num_windows; // ceil(256 / c)
    uint num_buckets; // 1 << (c - 1)  — signed-digit halving
};

// 256-bit scalar as 8 x 32-bit LE limbs.
// Same memory layout as Fp; treated as raw unsigned integer for bit ops.
struct Scalar256 {
    uint limbs[8];
};

// Extract `c` contiguous bits starting at `bit_offset` from a 256-bit scalar.
inline uint extract_bits(thread const Scalar256& s, uint bit_offset, uint c) {
    uint word  = bit_offset >> 5;
    uint shift = bit_offset & 31u;
    uint mask  = (1u << c) - 1u;
    uint val   = (word < 8) ? (s.limbs[word] >> shift) : 0u;
    if (shift + c > 32 && word + 1 < 8) {
        val |= s.limbs[word + 1] << (32u - shift);
    }
    return val & mask;
}

// ── Kernel 1: Signed-digit decomposition ────────────────────────
//
// Decomposes each 256-bit scalar into `num_windows` signed digits.
// Each digit d satisfies -(2^(c-1)-1) <= d <= 2^(c-1) via carry propagation.
// Output encoding: d > 0 → bucket |d|, add point normally
//                  d < 0 → bucket |d|, negate point before adding
//                  d == 0 → point skipped for this window
//
// Grid: n threads

kernel void g1_msm_decompose(
    device const Scalar256* scalars  [[buffer(0)]],
    device int*             digits   [[buffer(1)]],
    constant MsmParams&     params   [[buffer(2)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid >= params.n) return;

    Scalar256 s = scalars[tid];
    int half_range = int(1u << (params.c - 1u));
    int full_range = int(1u << params.c);
    int carry = 0;

    uint base = tid * params.num_windows;
    for (uint w = 0; w < params.num_windows; w++) {
        int raw = int(extract_bits(s, w * params.c, params.c)) + carry;
        if (raw >= half_range) {
            digits[base + w] = raw - full_range;
            carry = 1;
        } else {
            digits[base + w] = raw;
            carry = 0;
        }
    }
}

// ── Kernel 2: Histogram ─────────────────────────────────────────
//
// Atomically counts how many points map to each (window, bucket) pair.
// Grid: n threads; each thread iterates over all windows.

kernel void g1_msm_histogram(
    device const int*   digits    [[buffer(0)]],
    device atomic_uint* histogram [[buffer(1)]],
    constant MsmParams& params    [[buffer(2)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid >= params.n) return;

    uint dbase = tid * params.num_windows;
    for (uint w = 0; w < params.num_windows; w++) {
        int d = digits[dbase + w];
        if (d != 0) {
            uint bucket = uint(d > 0 ? d : -d) - 1u;
            atomic_fetch_add_explicit(
                &histogram[w * params.num_buckets + bucket],
                1u, memory_order_relaxed);
        }
    }
}

// ── Kernel 3: Exclusive prefix sum per window ───────────────────
//
// Sequential scan: adequate for num_buckets <= 32768.
// Grid: num_windows threads

kernel void g1_msm_prefix_sum(
    device const uint*  histogram [[buffer(0)]],
    device uint*        prefix    [[buffer(1)]],
    constant MsmParams& params    [[buffer(2)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid >= params.num_windows) return;

    uint offset = tid * params.num_buckets;
    uint sum = 0;
    for (uint b = 0; b < params.num_buckets; b++) {
        prefix[offset + b] = sum;
        sum += histogram[offset + b];
    }
}

// ── Kernel 4: Scatter ───────────────────────────────────────────
//
// Places each point index into the position determined by its
// (window, bucket) membership.  Packs index (bits 0-30) and
// sign (bit 31) into a single uint32.
// Grid: n threads

kernel void g1_msm_scatter(
    device const int*   digits          [[buffer(0)]],
    device const uint*  prefix          [[buffer(1)]],
    device atomic_uint* scatter_offsets [[buffer(2)]],
    device uint*        sorted          [[buffer(3)]],
    constant MsmParams& params          [[buffer(4)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid >= params.n) return;

    uint dbase = tid * params.num_windows;
    for (uint w = 0; w < params.num_windows; w++) {
        int d = digits[dbase + w];
        if (d != 0) {
            uint bucket = uint(d > 0 ? d : -d) - 1u;
            uint wb = w * params.num_buckets + bucket;
            uint local_slot = atomic_fetch_add_explicit(
                &scatter_offsets[wb], 1u, memory_order_relaxed);
            uint slot = prefix[wb] + local_slot;
            uint sign_bit = (d < 0) ? (1u << 31) : 0u;
            sorted[w * params.n + slot] = tid | sign_bit;
        }
    }
}

// ── Kernel 5: Bucket accumulation ───────────────────────────────
//
// Each thread processes one (window, bucket) pair: reads all point
// indices from the sorted array and accumulates via mixed addition.
// Grid: num_windows * num_buckets threads

kernel void g1_msm_accumulate(
    device const g1_affine* points         [[buffer(0)]],
    device const uint*      sorted         [[buffer(1)]],
    device const uint*      prefix         [[buffer(2)]],
    device const uint*      histogram_ro   [[buffer(3)]],
    device g1_jacobian*     bucket_results [[buffer(4)]],
    constant MsmParams&     params         [[buffer(5)]],
    uint tid [[thread_position_in_grid]]
) {
    uint total = params.num_windows * params.num_buckets;
    if (tid >= total) return;

    uint w = tid / params.num_buckets;
    uint b = tid % params.num_buckets;
    uint wb = w * params.num_buckets + b;

    uint start = prefix[wb];
    uint count = histogram_ro[wb];

    g1_jacobian acc = g1_jacobian_identity();
    uint sbase = w * params.n;

    for (uint i = 0; i < count; i++) {
        uint packed = sorted[sbase + start + i];
        uint idx  = packed & 0x7FFFFFFFu;
        uint sign = packed >> 31;

        g1_affine pt = points[idx];
        if (sign) pt = g1_affine_neg(pt);

        acc = g1_mixed_add(acc, pt);
    }

    bucket_results[tid] = acc;
}

// ── Kernel 6: Running-sum bucket reduction per window ───────────
//
// Computes window_result = Σ_{b=1}^{num_buckets} b * bucket[b]
// using the running-sum trick (num_buckets additions instead of
// num_buckets scalar multiplications).
// Grid: num_windows threads

kernel void g1_msm_reduce(
    device const g1_jacobian* bucket_results [[buffer(0)]],
    device g1_jacobian*       window_results [[buffer(1)]],
    constant MsmParams&       params         [[buffer(2)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid >= params.num_windows) return;

    uint base = tid * params.num_buckets;

    g1_jacobian running = g1_jacobian_identity();
    g1_jacobian sum     = g1_jacobian_identity();

    for (uint b = params.num_buckets; b > 0; b--) {
        running = g1_full_add(running, bucket_results[base + b - 1]);
        sum     = g1_full_add(sum, running);
    }

    window_results[tid] = sum;
}

// ── Kernel 7: Horner window combination ─────────────────────────
//
// Combines W per-window results into the final MSM output using
// Horner's method: result = w[W-1]; for w = W-2..0: result = 2^c * result + w[w].
// Grid: 1 thread

kernel void g1_msm_finalize(
    device const g1_jacobian* window_results [[buffer(0)]],
    device g1_jacobian*       result         [[buffer(1)]],
    constant MsmParams&       params         [[buffer(2)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid != 0) return;

    g1_jacobian acc = window_results[params.num_windows - 1];

    for (int w = int(params.num_windows) - 2; w >= 0; w--) {
        for (uint i = 0; i < params.c; i++) {
            acc = g1_double(acc);
        }
        acc = g1_full_add(acc, window_results[uint(w)]);
    }

    result[0] = acc;
}
