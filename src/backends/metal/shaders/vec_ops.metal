// Vector operations for Dory reduce-and-fold on Metal GPU.
//
// Three AXPY-pattern kernels matching DoryRoutines trait methods:
//
//   g1/g2_scale_bases_add:  out[i] = vs[i] + scalar * bases[i]
//     → fixed_scalar_mul_bases_then_add
//
//   g1/g2_scale_vs_add:    out[i] = scalar * vs[i] + addends[i]
//     → fixed_scalar_mul_vs_then_add
//
//   fr_axpy:               out[i] = scalar * left[i] + right[i]
//     → fold_field_vectors
//
// EC scalar: passed in buffer(3) as a single Fr element in RAW
//            (non-Montgomery) form. Caller converts before upload.
// Fr scalar: passed in buffer(3) as a single Fr element in Montgomery form.
//
// All kernels use broadcast scalar — identical branching across threads.
//
// This file is concatenated after ec.metal by the Rust shader loader.

// ══════════════════════════════════════════════════════════════════════
// G1 vector ops
// ══════════════════════════════════════════════════════════════════════

// out[i] = vs[i] + scalar * bases[i]   (GLV-2 accelerated)
kernel void g1_scale_bases_add(
    device const g1_jacobian* bases  [[buffer(0)]],
    device const g1_jacobian* vs     [[buffer(1)]],
    device       g1_jacobian* out    [[buffer(2)]],
    device const GlvScalar2*  scalar [[buffer(3)]],
    uint tid [[thread_position_in_grid]]
) {
    g1_jacobian scaled = g1_glv_scalar_mul(bases[tid], *scalar);
    out[tid] = g1_full_add(vs[tid], scaled);
}

// out[i] = scalar * vs[i] + addends[i]   (GLV-2 accelerated)
kernel void g1_scale_vs_add(
    device const g1_jacobian* vs      [[buffer(0)]],
    device const g1_jacobian* addends [[buffer(1)]],
    device       g1_jacobian* out     [[buffer(2)]],
    device const GlvScalar2*  scalar  [[buffer(3)]],
    uint tid [[thread_position_in_grid]]
) {
    g1_jacobian scaled = g1_glv_scalar_mul(vs[tid], *scalar);
    out[tid] = g1_full_add(scaled, addends[tid]);
}

// ══════════════════════════════════════════════════════════════════════
// G2 vector ops
// ══════════════════════════════════════════════════════════════════════

// out[i] = vs[i] + scalar * bases[i]
kernel void g2_scale_bases_add(
    device const g2_jacobian* bases  [[buffer(0)]],
    device const g2_jacobian* vs     [[buffer(1)]],
    device       g2_jacobian* out    [[buffer(2)]],
    device const Fr*          scalar [[buffer(3)]],
    uint tid [[thread_position_in_grid]]
) {
    g2_jacobian scaled = g2_scalar_mul(bases[tid], *scalar);
    out[tid] = g2_full_add(vs[tid], scaled);
}

// out[i] = scalar * vs[i] + addends[i]
kernel void g2_scale_vs_add(
    device const g2_jacobian* vs      [[buffer(0)]],
    device const g2_jacobian* addends [[buffer(1)]],
    device       g2_jacobian* out     [[buffer(2)]],
    device const Fr*          scalar  [[buffer(3)]],
    uint tid [[thread_position_in_grid]]
) {
    g2_jacobian scaled = g2_scalar_mul(vs[tid], *scalar);
    out[tid] = g2_full_add(scaled, addends[tid]);
}

// ══════════════════════════════════════════════════════════════════════
// Fr (scalar field) vector ops
// ══════════════════════════════════════════════════════════════════════

// out[i] = scalar * left[i] + right[i]
// All values in Montgomery form.
kernel void fr_axpy(
    device const Fr* left    [[buffer(0)]],
    device const Fr* right   [[buffer(1)]],
    device       Fr* out     [[buffer(2)]],
    device const Fr* scalar  [[buffer(3)]],
    uint tid [[thread_position_in_grid]]
) {
    out[tid] = fr_add(fr_mul(*scalar, left[tid]), right[tid]);
}
