// Elliptic curve point operations for BN254 G1 and G2 on Metal GPU.
//
// G1: y^2 = x^3 + 3 over Fp          (short Weierstrass, a=0, b=3)
// G2: y^2 = x^3 + 3/(9+u) over Fp2   (D-type sextic twist)
//
// Coordinate systems:
//   Affine:   (x, y) with an explicit infinity flag
//   Jacobian: (X, Y, Z) where x = X/Z^2, y = Y/Z^3; identity has Z=0
//
// All Fp/Fp2 values are in Montgomery form, matching fp.metal conventions.
// Inputs to add/double may be in loose [0, 2p) form; outputs are loose.
//
// This file is concatenated after fp.metal by the Rust shader loader.
// Do not add #include directives.

// ══════════════════════════════════════════════════════════════════════
// Macro-templated EC operations
// ══════════════════════════════════════════════════════════════════════
//
// We define point types and operations generically over the base field
// via a macro so that G1 (over Fp) and G2 (over Fp2) share identical
// logic without duplication.

#define DEFINE_EC_TYPES(PREFIX, FP)                                              \
                                                                                 \
struct PREFIX##_affine {                                                          \
    FP x;                                                                        \
    FP y;                                                                         \
    uint is_inf;                                                                 \
};                                                                               \
                                                                                 \
struct PREFIX##_jacobian {                                                        \
    FP x;                                                                        \
    FP y;                                                                         \
    FP z;                                                                        \
};

#define DEFINE_EC_OPS(PREFIX, FP,                                                \
                      FP_MUL, FP_SQR, FP_ADD, FP_SUB,                           \
                      FP_REDUCE, FP_ZERO, FP_ONE, FP_NEG, FP_EQ)                \
                                                                                 \
/* ── Identity constructors ─────────────────────────────────────── */            \
                                                                                 \
inline PREFIX##_affine PREFIX##_affine_identity() {                              \
    PREFIX##_affine r;                                                           \
    r.x = FP_ZERO();                                                             \
    r.y = FP_ONE();                                                              \
    r.is_inf = 1;                                                                \
    return r;                                                                    \
}                                                                                \
                                                                                 \
inline PREFIX##_jacobian PREFIX##_jacobian_identity() {                          \
    PREFIX##_jacobian r;                                                         \
    r.x = FP_ONE();                                                              \
    r.y = FP_ONE();                                                              \
    r.z = FP_ZERO();                                                             \
    return r;                                                                    \
}                                                                                \
                                                                                 \
inline bool PREFIX##_jacobian_is_identity(PREFIX##_jacobian p) {                 \
    return FP_EQ(p.z, FP_ZERO());                                               \
}                                                                                \
                                                                                 \
/* ── Affine to Jacobian ────────────────────────────────────────── */            \
                                                                                 \
inline PREFIX##_jacobian PREFIX##_affine_to_jacobian(PREFIX##_affine a) {        \
    if (a.is_inf) return PREFIX##_jacobian_identity();                           \
    PREFIX##_jacobian r;                                                         \
    r.x = a.x;                                                                  \
    r.y = a.y;                                                                   \
    r.z = FP_ONE();                                                              \
    return r;                                                                    \
}                                                                                \
                                                                                 \
/* ── Negate ────────────────────────────────────────────────────── */            \
                                                                                 \
inline PREFIX##_affine PREFIX##_affine_neg(PREFIX##_affine a) {                  \
    if (a.is_inf) return a;                                                      \
    PREFIX##_affine r;                                                           \
    r.x = a.x;                                                                  \
    r.y = FP_NEG(a.y);                                                           \
    r.is_inf = 0;                                                                \
    return r;                                                                    \
}                                                                                \
                                                                                 \
inline PREFIX##_jacobian PREFIX##_jacobian_neg(PREFIX##_jacobian p) {            \
    PREFIX##_jacobian r;                                                         \
    r.x = p.x;                                                                  \
    r.y = FP_NEG(p.y);                                                           \
    r.z = p.z;                                                                   \
    return r;                                                                    \
}                                                                                \
                                                                                 \
/* ── Doubling (Jacobian, a = 0) ────────────────────────────────── */           \
/*                                                                   */          \
/*   A = Y^2                                                         */          \
/*   B = 4*X*A                                                       */          \
/*   C = 8*A^2                                                       */          \
/*   D = 3*X^2                                                       */          \
/*   X' = D^2 - 2*B                                                  */          \
/*   Y' = D*(B - X') - C                                             */          \
/*   Z' = 2*Y*Z                                                      */          \
/*   Cost: 3M + 4S                                                   */          \
/*                                                                   */          \
inline PREFIX##_jacobian PREFIX##_double(PREFIX##_jacobian p) {                  \
    if (PREFIX##_jacobian_is_identity(p)) return p;                              \
                                                                                 \
    FP a = FP_SQR(p.y);                                                         \
    FP b = FP_MUL(p.x, a);                                                      \
    b = FP_ADD(b, b);                                                            \
    b = FP_ADD(b, b);                                                            \
                                                                                 \
    FP c = FP_SQR(a);                                                            \
    c = FP_ADD(c, c);                                                            \
    c = FP_ADD(c, c);                                                            \
    c = FP_ADD(c, c);                                                            \
                                                                                 \
    FP x_sq = FP_SQR(p.x);                                                      \
    FP d = FP_ADD(x_sq, FP_ADD(x_sq, x_sq));                                    \
                                                                                 \
    FP x3 = FP_REDUCE(FP_SUB(FP_SQR(d), FP_ADD(b, b)));                        \
    FP y3 = FP_SUB(FP_MUL(d, FP_SUB(b, x3)), c);                               \
    FP z3 = FP_MUL(p.y, p.z);                                                   \
    z3 = FP_ADD(z3, z3);                                                         \
                                                                                 \
    PREFIX##_jacobian r;                                                         \
    r.x = FP_REDUCE(x3);                                                        \
    r.y = FP_REDUCE(y3);                                                         \
    r.z = FP_REDUCE(z3);                                                         \
    return r;                                                                    \
}                                                                                \
                                                                                 \
/* ── Mixed addition (Jacobian + Affine -> Jacobian) ────────────── */           \
/*                                                                   */          \
/* EFD "madd-2007-bl":                                               */          \
/*   Z1Z1 = Z1^2                                                    */          \
/*   U2   = X2*Z1Z1                                                 */          \
/*   S2   = Y2*Z1*Z1Z1                                              */          \
/*   H    = U2 - X1                                                  */          \
/*   HH   = H^2                                                     */          \
/*   I    = 4*HH                                                     */          \
/*   J    = H*I                                                      */          \
/*   r    = 2*(S2 - Y1)                                              */          \
/*   V    = X1*I                                                     */          \
/*   X3   = r^2 - J - 2*V                                           */          \
/*   Y3   = r*(V - X3) - 2*Y1*J                                     */          \
/*   Z3   = (Z1 + H)^2 - Z1Z1 - HH                                 */          \
/*   Cost: 7M + 4S                                                   */          \
/*                                                                   */          \
inline PREFIX##_jacobian PREFIX##_mixed_add(                                     \
    PREFIX##_jacobian p, PREFIX##_affine q                                       \
) {                                                                              \
    if (q.is_inf) return p;                                                      \
    if (PREFIX##_jacobian_is_identity(p)) return PREFIX##_affine_to_jacobian(q); \
                                                                                 \
    FP z1z1 = FP_REDUCE(FP_SQR(p.z));                                           \
    FP u2   = FP_MUL(q.x, z1z1);                                                \
    FP s2   = FP_MUL(q.y, FP_MUL(p.z, z1z1));                                  \
                                                                                 \
    FP h    = FP_SUB(u2, p.x);                                                   \
    FP hh   = FP_REDUCE(FP_SQR(h));                                             \
    FP i    = FP_ADD(hh, hh);                                                    \
    i       = FP_ADD(i, i);                                                      \
    FP j    = FP_MUL(h, i);                                                      \
                                                                                 \
    FP rr   = FP_SUB(s2, p.y);                                                   \
    rr      = FP_ADD(rr, rr);                                                    \
    FP v    = FP_MUL(p.x, i);                                                   \
                                                                                 \
    FP r_sq = FP_REDUCE(FP_SQR(rr));                                            \
    FP x3   = FP_SUB(FP_SUB(r_sq, j), FP_ADD(v, v));                           \
                                                                                 \
    FP y1j  = FP_MUL(p.y, j);                                                   \
    FP y3   = FP_SUB(FP_MUL(rr, FP_SUB(v, x3)), FP_ADD(y1j, y1j));            \
                                                                                 \
    FP z_sum = FP_ADD(p.z, h);                                                   \
    FP z3    = FP_SUB(FP_SUB(FP_SQR(z_sum), z1z1), hh);                        \
                                                                                 \
    PREFIX##_jacobian out;                                                       \
    out.x = FP_REDUCE(x3);                                                      \
    out.y = FP_REDUCE(y3);                                                       \
    out.z = FP_REDUCE(z3);                                                       \
    return out;                                                                  \
}                                                                                \
                                                                                 \
/* ── Full addition (Jacobian + Jacobian -> Jacobian) ───────────── */           \
/*                                                                   */          \
/* "add-2007-bl" formulas.  Falls back to double when P == Q.        */          \
/* Cost: 11M + 5S                                                    */          \
/*                                                                   */          \
inline PREFIX##_jacobian PREFIX##_full_add(                                      \
    PREFIX##_jacobian p, PREFIX##_jacobian q                                     \
) {                                                                              \
    if (PREFIX##_jacobian_is_identity(p)) return q;                              \
    if (PREFIX##_jacobian_is_identity(q)) return p;                              \
                                                                                 \
    FP z1z1 = FP_REDUCE(FP_SQR(p.z));                                           \
    FP z2z2 = FP_REDUCE(FP_SQR(q.z));                                           \
                                                                                 \
    FP u1 = FP_MUL(p.x, z2z2);                                                  \
    FP u2 = FP_MUL(q.x, z1z1);                                                  \
    FP s1 = FP_MUL(p.y, FP_MUL(q.z, z2z2));                                    \
    FP s2 = FP_MUL(q.y, FP_MUL(p.z, z1z1));                                    \
                                                                                 \
    FP h = FP_SUB(u2, u1);                                                       \
    FP rr = FP_SUB(s2, s1);                                                      \
                                                                                 \
    if (FP_EQ(FP_REDUCE(h), FP_ZERO())) {                                       \
        if (FP_EQ(FP_REDUCE(rr), FP_ZERO())) {                                  \
            return PREFIX##_double(p);                                           \
        }                                                                        \
        return PREFIX##_jacobian_identity();                                     \
    }                                                                            \
                                                                                 \
    FP h2 = FP_ADD(h, h);                                                        \
    FP ii = FP_REDUCE(FP_SQR(h2));                                              \
    FP j  = FP_MUL(h, ii);                                                       \
    rr    = FP_ADD(rr, rr);                                                      \
    FP v  = FP_MUL(u1, ii);                                                      \
                                                                                 \
    FP r_sq = FP_REDUCE(FP_SQR(rr));                                            \
    FP x3   = FP_SUB(FP_SUB(r_sq, j), FP_ADD(v, v));                           \
                                                                                 \
    FP s1j = FP_MUL(s1, j);                                                     \
    FP y3  = FP_SUB(FP_MUL(rr, FP_SUB(v, x3)), FP_ADD(s1j, s1j));             \
                                                                                 \
    FP z_sum = FP_ADD(p.z, q.z);                                                 \
    FP z3    = FP_MUL(FP_SUB(FP_SUB(FP_SQR(z_sum), z1z1), z2z2), h);          \
                                                                                 \
    PREFIX##_jacobian out;                                                       \
    out.x = FP_REDUCE(x3);                                                      \
    out.y = FP_REDUCE(y3);                                                       \
    out.z = FP_REDUCE(z3);                                                       \
    return out;                                                                  \
}

// ══════════════════════════════════════════════════════════════════════
// Instantiate for G1 (over Fp)
// ══════════════════════════════════════════════════════════════════════

DEFINE_EC_TYPES(g1, Fp)
DEFINE_EC_OPS(g1, Fp,
              fp_mul, fp_sqr, fp_add, fp_sub,
              fp_reduce, fp_zero, fp_one, fp_neg, fp_eq)

// ══════════════════════════════════════════════════════════════════════
// Instantiate for G2 (over Fp2)
// ══════════════════════════════════════════════════════════════════════

DEFINE_EC_TYPES(g2, Fp2)
DEFINE_EC_OPS(g2, Fp2,
              fp2_mul, fp2_sqr, fp2_add, fp2_sub,
              fp2_reduce, fp2_zero, fp2_one, fp2_neg, fp2_eq)

// ══════════════════════════════════════════════════════════════════════
// Scalar multiplication — double-and-add over Jacobian
// ══════════════════════════════════════════════════════════════════════
//
// The scalar is a 254-bit Fr element in RAW (non-Montgomery) form.
// Caller must convert from Montgomery before passing to these functions.
//
// For broadcast scalars (same across all threads), all threads follow
// identical branching — perfect SIMD coherence.

#define DEFINE_EC_SCALAR_MUL(PREFIX, FP,                                        \
                             FP_ZERO, FP_EQ)                                    \
                                                                                 \
inline PREFIX##_jacobian PREFIX##_scalar_mul(                                    \
    PREFIX##_jacobian p, Fr scalar_raw                                           \
) {                                                                              \
    PREFIX##_jacobian acc = PREFIX##_jacobian_identity();                        \
                                                                                 \
    /* BN254 Fr is 254 bits, so bit 253 is the highest possible set bit */      \
    for (int i = 253; i >= 0; i--) {                                             \
        acc = PREFIX##_double(acc);                                              \
        uint limb = scalar_raw.limbs[i >> 5];                                    \
        uint bit = (limb >> (i & 31)) & 1u;                                      \
        if (bit) {                                                               \
            acc = PREFIX##_full_add(acc, p);                                     \
        }                                                                        \
    }                                                                            \
    return acc;                                                                  \
}

DEFINE_EC_SCALAR_MUL(g1, Fp, fp_zero, fp_eq)
DEFINE_EC_SCALAR_MUL(g2, Fp2, fp2_zero, fp2_eq)

// ══════════════════════════════════════════════════════════════════════
// GLV-2 scalar multiplication for G1 (Shamir's trick)
// ══════════════════════════════════════════════════════════════════════
//
// BN254 has endomorphism φ(x, y) = (β·x, y) where [λ]P = φ(P).
// Decompose scalar s = k1 + k2·λ with k1, k2 ~128 bits.
// Then s·P = k1·P + k2·φ(P) via Shamir's simultaneous double-and-add.
//
// β in Montgomery form (cube root of unity in Fp):
//   21888242871839275220042445260109153167277707414472061641714758635765020556616

constant uint ENDO_BETA_LIMBS[8] = {
    0x13e80b9c, 0x3350c88e, 0xdb5e56b9, 0x7dce557c,
    0xb615564a, 0x6001b4b8, 0x020217e0, 0x2682e617
};

inline Fp endo_beta() {
    Fp r;
    for (int i = 0; i < 8; i++) r.limbs[i] = ENDO_BETA_LIMBS[i];
    return r;
}

// GLV decomposed scalar: two ~128-bit sub-scalars + negate flags.
struct GlvScalar2 {
    Fr k1;
    Fr k2;
    uint negate1;
    uint negate2;
};

inline g1_jacobian g1_glv_scalar_mul(g1_jacobian p, GlvScalar2 glv) {
    // φ(P) = (β·x, y, z)
    g1_jacobian p_endo = p;
    p_endo.x = fp_mul(endo_beta(), p.x);

    // Apply sign: negate base if the sub-scalar was negative
    if (glv.negate1) p = g1_jacobian_neg(p);
    if (glv.negate2) p_endo = g1_jacobian_neg(p_endo);

    // Precompute P + φ(P) for the (1,1) case
    g1_jacobian p_both = g1_full_add(p, p_endo);

    g1_jacobian acc = g1_jacobian_identity();

    // Both sub-scalars are ~128 bits
    for (int i = 127; i >= 0; i--) {
        acc = g1_double(acc);

        uint limb1 = glv.k1.limbs[i >> 5];
        uint bit1 = (limb1 >> (i & 31)) & 1u;
        uint limb2 = glv.k2.limbs[i >> 5];
        uint bit2 = (limb2 >> (i & 31)) & 1u;

        uint sel = bit1 | (bit2 << 1);
        if (sel == 3u) {
            acc = g1_full_add(acc, p_both);
        } else if (sel == 1u) {
            acc = g1_full_add(acc, p);
        } else if (sel == 2u) {
            acc = g1_full_add(acc, p_endo);
        }
    }

    return acc;
}

// ══════════════════════════════════════════════════════════════════════
// Test kernels — G1
// ══════════════════════════════════════════════════════════════════════

kernel void g1_mixed_add_test(
    device const g1_affine*    p    [[buffer(0)]],
    device const g1_affine*    q    [[buffer(1)]],
    device g1_jacobian*        out  [[buffer(2)]],
    uint tid                        [[thread_position_in_grid]]
) {
    g1_jacobian pj = g1_affine_to_jacobian(p[tid]);
    out[tid] = g1_mixed_add(pj, q[tid]);
}

kernel void g1_double_test(
    device const g1_affine*    p    [[buffer(0)]],
    device const g1_affine*    dummy [[buffer(1)]],
    device g1_jacobian*        out  [[buffer(2)]],
    uint tid                        [[thread_position_in_grid]]
) {
    g1_jacobian pj = g1_affine_to_jacobian(p[tid]);
    out[tid] = g1_double(pj);
}

kernel void g1_full_add_test(
    device const g1_affine*    p    [[buffer(0)]],
    device const g1_affine*    q    [[buffer(1)]],
    device g1_jacobian*        out  [[buffer(2)]],
    uint tid                        [[thread_position_in_grid]]
) {
    g1_jacobian pj = g1_affine_to_jacobian(p[tid]);
    g1_jacobian qj = g1_affine_to_jacobian(q[tid]);
    out[tid] = g1_full_add(pj, qj);
}

kernel void g1_negate_test(
    device const g1_affine*    p    [[buffer(0)]],
    device const g1_affine*    dummy [[buffer(1)]],
    device g1_affine*          out  [[buffer(2)]],
    uint tid                        [[thread_position_in_grid]]
) {
    out[tid] = g1_affine_neg(p[tid]);
}

// Chain: accumulate n points by sequential mixed addition.
// Tests the pattern used in MSM bucket accumulation.
kernel void g1_accumulate_test(
    device const g1_affine*    points [[buffer(0)]],
    device const uint*         counts [[buffer(1)]],
    device g1_jacobian*        out    [[buffer(2)]],
    uint tid                          [[thread_position_in_grid]]
) {
    uint n = counts[tid];
    g1_jacobian acc = g1_jacobian_identity();
    for (uint i = 0; i < n; i++) {
        acc = g1_mixed_add(acc, points[tid * n + i]);
    }
    out[tid] = acc;
}

// Scalar multiplication test: out[tid] = scalar * p[tid]
// scalar is broadcast (single element in buffer 1, reinterpreted as Fr raw limbs)
kernel void g1_scalar_mul_test(
    device const g1_jacobian*  p      [[buffer(0)]],
    device const Fr*           scalar [[buffer(1)]],
    device g1_jacobian*        out    [[buffer(2)]],
    uint tid                          [[thread_position_in_grid]]
) {
    out[tid] = g1_scalar_mul(p[tid], *scalar);
}

// ══════════════════════════════════════════════════════════════════════
// Test kernels — G2
// ══════════════════════════════════════════════════════════════════════

kernel void g2_mixed_add_test(
    device const g2_affine*    p    [[buffer(0)]],
    device const g2_affine*    q    [[buffer(1)]],
    device g2_jacobian*        out  [[buffer(2)]],
    uint tid                        [[thread_position_in_grid]]
) {
    g2_jacobian pj = g2_affine_to_jacobian(p[tid]);
    out[tid] = g2_mixed_add(pj, q[tid]);
}

kernel void g2_double_test(
    device const g2_affine*    p    [[buffer(0)]],
    device const g2_affine*    dummy [[buffer(1)]],
    device g2_jacobian*        out  [[buffer(2)]],
    uint tid                        [[thread_position_in_grid]]
) {
    g2_jacobian pj = g2_affine_to_jacobian(p[tid]);
    out[tid] = g2_double(pj);
}

kernel void g2_full_add_test(
    device const g2_affine*    p    [[buffer(0)]],
    device const g2_affine*    q    [[buffer(1)]],
    device g2_jacobian*        out  [[buffer(2)]],
    uint tid                        [[thread_position_in_grid]]
) {
    g2_jacobian pj = g2_affine_to_jacobian(p[tid]);
    g2_jacobian qj = g2_affine_to_jacobian(q[tid]);
    out[tid] = g2_full_add(pj, qj);
}

kernel void g2_scalar_mul_test(
    device const g2_jacobian*  p      [[buffer(0)]],
    device const Fr*           scalar [[buffer(1)]],
    device g2_jacobian*        out    [[buffer(2)]],
    uint tid                          [[thread_position_in_grid]]
) {
    out[tid] = g2_scalar_mul(p[tid], *scalar);
}
