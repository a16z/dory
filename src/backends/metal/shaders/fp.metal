// BN254 field arithmetic for Metal GPU
//
// Provides 256-bit Montgomery-form field operations for both:
//   Fp  – base field (coordinates of curve points)
//   Fr  – scalar field (exponents / scalar multipliers)
//
// Representation: 8 × 32-bit limbs, little-endian (limb 0 = LSB).
// Values are kept in Montgomery form: a_mont = a · R mod p, where R = 2^256.
//
// Reduction strategy:
//   - Multiplications (mul/sqr) always produce fully reduced [0, p) output.
//   - This ensures add/sub inputs are in [0, p), where single-conditional
//     corrections (one p addition/subtraction) are always sufficient.
//   - Carry propagation within mul uses 64-bit accumulators; we never
//     need to reduce between the 8 inner-loop iterations of CIOS.
//
// Montgomery multiplication uses CIOS (Coarsely Integrated Operand
// Scanning) with a 32-bit digit: in each of the 8 outer iterations we
// perform one multiply-accumulate pass and one reduction pass, both
// running across the 8 limbs.  Carries are kept in 64-bit (ulong)
// accumulators and propagated inline.
//
// Field operations are generated via DEFINE_FIELD_OPS so that Fp and Fr
// share the same implementation with different modular constants.

#include <metal_stdlib>
using namespace metal;

// ──────────────────────────────────────────────────────────────────────
// Helpers (field-independent)
// ──────────────────────────────────────────────────────────────────────

// Add with carry: result = a + b + carry_in.  Returns (sum, carry_out).
inline uint2 adc(uint a, uint b, uint carry_in) {
    ulong s = ulong(a) + ulong(b) + ulong(carry_in);
    return uint2(uint(s), uint(s >> 32));
}

// Subtract with borrow: result = a - b - borrow_in.  Returns (diff, borrow_out).
inline uint2 sbb(uint a, uint b, uint borrow_in) {
    ulong s = ulong(a) - ulong(b) - ulong(borrow_in);
    return uint2(uint(s), uint(s >> 63));
}

// ──────────────────────────────────────────────────────────────────────
// Constants — Fp (BN254 base field)
// ──────────────────────────────────────────────────────────────────────

// p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
constant uint FP_MODULUS[8] = {
    0xd87cfd47u, 0x3c208c16u, 0x6871ca8du, 0x97816a91u,
    0x8181585du, 0xb85045b6u, 0xe131a029u, 0x30644e72u,
};

// -p^{-1} mod 2^{32}
constant uint FP_INV32 = 0xe4866389u;

// R^2 mod p
constant uint FP_R2[8] = {
    0x538afa89u, 0xf32cfc5bu, 0xd44501fbu, 0xb5e71911u,
    0x0a417ff6u, 0x47ab1effu, 0xcab8351fu, 0x06d89f71u,
};

// R mod p (Montgomery representation of 1)
constant uint FP_ONE[8] = {
    0xc58f0d9du, 0xd35d438du, 0xf5c70b3du, 0x0a78eb28u,
    0x7879462cu, 0x666ea36fu, 0x9a07df2fu, 0x0e0a77c1u,
};

// 9·R mod p (Montgomery representation of 9, for Fp6 non-residue ξ = 9 + u)
constant uint FP_NINE[8] = {
    0x410d7ff7u, 0xf60647ceu, 0xd31bd011u, 0x2f3d6f4du,
    0x3940c6d1u, 0x2943337eu, 0xa7e39857u, 0x1d9598e8u,
};

// ──────────────────────────────────────────────────────────────────────
// Constants — Fr (BN254 scalar field)
// ──────────────────────────────────────────────────────────────────────

// r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
constant uint FR_MODULUS[8] = {
    0xf0000001u, 0x43e1f593u, 0x79b97091u, 0x2833e848u,
    0x8181585du, 0xb85045b6u, 0xe131a029u, 0x30644e72u,
};

// -r^{-1} mod 2^{32}
constant uint FR_INV32 = 0xefffffffu;

// R^2 mod r
constant uint FR_R2[8] = {
    0xae216da7u, 0x1bb8e645u, 0xe35c59e3u, 0x53fe3ab1u,
    0x53bb8085u, 0x8c49833du, 0x7f4e44a5u, 0x0216d0b1u,
};

// R mod r (Montgomery representation of 1)
constant uint FR_ONE[8] = {
    0x4ffffffbu, 0xac96341cu, 0x9f60cd29u, 0x36fc7695u,
    0x7879462eu, 0x666ea36fu, 0x9a07df2fu, 0x0e0a77c1u,
};

// ──────────────────────────────────────────────────────────────────────
// Field type macro
// ──────────────────────────────────────────────────────────────────────

#define DEFINE_FIELD_TYPE(NAME) \
struct NAME {                   \
    uint limbs[8];              \
};

// ──────────────────────────────────────────────────────────────────────
// CIOS round — parameterized over modulus and Montgomery inverse
// ──────────────────────────────────────────────────────────────────────
//
// Single CIOS iteration: T += a[] * b_j, then reduce+shift.
// Factored out to encourage the compiler to keep T in registers.

#define CIOS_ROUND(T, a, b_j, T9_out, MODULUS, INV32)                      \
{                                                                            \
    ulong carry = 0;                                                         \
    for (int i = 0; i < 8; i++) {                                            \
        ulong sum = ulong(T[i]) + ulong(a.limbs[i]) * ulong(b_j) + carry;   \
        T[i] = uint(sum);                                                    \
        carry = sum >> 32;                                                   \
    }                                                                        \
    ulong t8c = ulong(T[8]) + carry;                                         \
    T[8] = uint(t8c);                                                        \
    T9_out = uint(t8c >> 32);                                                \
    uint m = T[0] * INV32;                                                   \
    carry = (ulong(T[0]) + ulong(m) * ulong(MODULUS[0])) >> 32;             \
    for (int i = 1; i < 8; i++) {                                            \
        ulong sum2 = ulong(T[i]) + ulong(m) * ulong(MODULUS[i]) + carry;    \
        T[i - 1] = uint(sum2);                                              \
        carry = sum2 >> 32;                                                  \
    }                                                                        \
    ulong fs = ulong(T[8]) + carry;                                          \
    T[7] = uint(fs);                                                         \
    T[8] = T9_out + uint(fs >> 32);                                          \
}

// ──────────────────────────────────────────────────────────────────────
// Field operations macro
// ──────────────────────────────────────────────────────────────────────
//
// Generates: PREFIX_add, PREFIX_sub, PREFIX_reduce, PREFIX_mul,
//            PREFIX_sqr, PREFIX_to_mont, PREFIX_from_mont,
//            PREFIX_zero, PREFIX_one, PREFIX_neg, PREFIX_eq

#define DEFINE_FIELD_OPS(PREFIX, TYPE, MODULUS, INV32, R2_CONST, ONE_CONST)  \
                                                                             \
/* ── Addition – loose output in [0, 2p) ───────────────────────── */       \
                                                                             \
inline TYPE PREFIX##_add(TYPE a, TYPE b) {                                   \
    TYPE result;                                                             \
    uint carry = 0;                                                          \
    for (int i = 0; i < 8; i++) {                                            \
        uint2 r = adc(a.limbs[i], b.limbs[i], carry);                       \
        result.limbs[i] = r.x;                                              \
        carry = r.y;                                                         \
    }                                                                        \
    TYPE reduced;                                                            \
    uint borrow = 0;                                                         \
    for (int i = 0; i < 8; i++) {                                            \
        uint2 r = sbb(result.limbs[i], MODULUS[i], borrow);                  \
        reduced.limbs[i] = r.x;                                             \
        borrow = r.y;                                                        \
    }                                                                        \
    uint use_reduced = (carry >= borrow) ? 1u : 0u;                          \
    for (int i = 0; i < 8; i++) {                                            \
        result.limbs[i] = use_reduced ? reduced.limbs[i] : result.limbs[i];  \
    }                                                                        \
    return result;                                                           \
}                                                                            \
                                                                             \
/* ── Subtraction – loose output in [0, 2p) ────────────────────── */       \
                                                                             \
inline TYPE PREFIX##_sub(TYPE a, TYPE b) {                                   \
    TYPE result;                                                             \
    uint borrow = 0;                                                         \
    for (int i = 0; i < 8; i++) {                                            \
        uint2 r = sbb(a.limbs[i], b.limbs[i], borrow);                      \
        result.limbs[i] = r.x;                                              \
        borrow = r.y;                                                        \
    }                                                                        \
    uint carry = 0;                                                          \
    for (int i = 0; i < 8; i++) {                                            \
        uint addend = borrow ? MODULUS[i] : 0u;                              \
        uint2 r = adc(result.limbs[i], addend, carry);                       \
        result.limbs[i] = r.x;                                              \
        carry = r.y;                                                         \
    }                                                                        \
    return result;                                                           \
}                                                                            \
                                                                             \
/* ── Full reduction to [0, p) ─────────────────────────────────── */       \
                                                                             \
inline TYPE PREFIX##_reduce(TYPE a) {                                        \
    TYPE reduced;                                                            \
    uint borrow = 0;                                                         \
    for (int i = 0; i < 8; i++) {                                            \
        uint2 r = sbb(a.limbs[i], MODULUS[i], borrow);                       \
        reduced.limbs[i] = r.x;                                             \
        borrow = r.y;                                                        \
    }                                                                        \
    for (int i = 0; i < 8; i++) {                                            \
        a.limbs[i] = borrow ? a.limbs[i] : reduced.limbs[i];                \
    }                                                                        \
    return a;                                                                \
}                                                                            \
                                                                             \
/* ── Montgomery multiplication (CIOS, 32-bit digit) ──────────── */       \
                                                                             \
inline TYPE PREFIX##_mul(TYPE a, TYPE b) {                                   \
    uint T[9] = {0, 0, 0, 0, 0, 0, 0, 0, 0};                               \
    uint T9;                                                                 \
    CIOS_ROUND(T, a, b.limbs[0], T9, MODULUS, INV32);                       \
    CIOS_ROUND(T, a, b.limbs[1], T9, MODULUS, INV32);                       \
    CIOS_ROUND(T, a, b.limbs[2], T9, MODULUS, INV32);                       \
    CIOS_ROUND(T, a, b.limbs[3], T9, MODULUS, INV32);                       \
    CIOS_ROUND(T, a, b.limbs[4], T9, MODULUS, INV32);                       \
    CIOS_ROUND(T, a, b.limbs[5], T9, MODULUS, INV32);                       \
    CIOS_ROUND(T, a, b.limbs[6], T9, MODULUS, INV32);                       \
    CIOS_ROUND(T, a, b.limbs[7], T9, MODULUS, INV32);                       \
    TYPE result;                                                             \
    for (int i = 0; i < 8; i++) result.limbs[i] = T[i];                     \
    return PREFIX##_reduce(result);                                          \
}                                                                            \
                                                                             \
/* ── Squaring (calls mul — can be specialised later) ──────────── */       \
                                                                             \
inline TYPE PREFIX##_sqr(TYPE a) {                                           \
    return PREFIX##_mul(a, a);                                               \
}                                                                            \
                                                                             \
/* ── Conversion helpers ───────────────────────────────────────── */       \
                                                                             \
inline TYPE PREFIX##_to_mont(TYPE a) {                                       \
    TYPE r2;                                                                 \
    for (int i = 0; i < 8; i++) r2.limbs[i] = R2_CONST[i];                  \
    return PREFIX##_mul(a, r2);                                              \
}                                                                            \
                                                                             \
inline TYPE PREFIX##_from_mont(TYPE a) {                                     \
    TYPE one;                                                                \
    one.limbs[0] = 1;                                                        \
    for (int i = 1; i < 8; i++) one.limbs[i] = 0;                           \
    return PREFIX##_reduce(PREFIX##_mul(a, one));                             \
}                                                                            \
                                                                             \
inline TYPE PREFIX##_zero() {                                                \
    TYPE z;                                                                  \
    for (int i = 0; i < 8; i++) z.limbs[i] = 0;                             \
    return z;                                                                \
}                                                                            \
                                                                             \
inline TYPE PREFIX##_one() {                                                 \
    TYPE o;                                                                  \
    for (int i = 0; i < 8; i++) o.limbs[i] = ONE_CONST[i];                  \
    return o;                                                                \
}                                                                            \
                                                                             \
inline TYPE PREFIX##_neg(TYPE a) {                                           \
    return PREFIX##_sub(PREFIX##_zero(), a);                                  \
}                                                                            \
                                                                             \
inline bool PREFIX##_eq(TYPE a, TYPE b) {                                    \
    TYPE ar = PREFIX##_reduce(a);                                            \
    TYPE br = PREFIX##_reduce(b);                                            \
    bool eq = true;                                                          \
    for (int i = 0; i < 8; i++) {                                            \
        eq = eq && (ar.limbs[i] == br.limbs[i]);                             \
    }                                                                        \
    return eq;                                                               \
}

// ══════════════════════════════════════════════════════════════════════
// Instantiate Fp (base field)
// ══════════════════════════════════════════════════════════════════════

DEFINE_FIELD_TYPE(Fp)
DEFINE_FIELD_OPS(fp, Fp, FP_MODULUS, FP_INV32, FP_R2, FP_ONE)

// ══════════════════════════════════════════════════════════════════════
// Instantiate Fr (scalar field)
// ══════════════════════════════════════════════════════════════════════

DEFINE_FIELD_TYPE(Fr)
DEFINE_FIELD_OPS(fr, Fr, FR_MODULUS, FR_INV32, FR_R2, FR_ONE)

// ══════════════════════════════════════════════════════════════════════
// Fp2 = Fp[u] / (u² + 1)
// ══════════════════════════════════════════════════════════════════════

struct Fp2 {
    Fp c0; // real part
    Fp c1; // imaginary part (coefficient of u)
};

inline Fp2 fp2_add(Fp2 a, Fp2 b) {
    return {fp_add(a.c0, b.c0), fp_add(a.c1, b.c1)};
}

inline Fp2 fp2_sub(Fp2 a, Fp2 b) {
    return {fp_sub(a.c0, b.c0), fp_sub(a.c1, b.c1)};
}

inline Fp2 fp2_neg(Fp2 a) {
    return {fp_neg(a.c0), fp_neg(a.c1)};
}

// Karatsuba multiplication:  (a0 + a1·u)(b0 + b1·u) = (a0·b0 − a1·b1) + (a0·b1 + a1·b0)·u
// Using Karatsuba: c1 = (a0+a1)(b0+b1) − v0 − v1,  c0 = v0 − v1
// 3 Fp muls instead of 4.
//
// Note: fp_add outputs are in [0, 2p) and fp_mul accepts [0, 2p), so the
// inputs to the cross-product multiplication are valid.  For c1 we subtract
// (v0 + v1) in one shot to avoid chained subtractions that can accumulate
// a reduction error.
inline Fp2 fp2_mul(Fp2 a, Fp2 b) {
    Fp v0 = fp_mul(a.c0, b.c0);
    Fp v1 = fp_mul(a.c1, b.c1);

    Fp c0 = fp_sub(v0, v1);
    Fp cross = fp_mul(fp_add(a.c0, a.c1), fp_add(b.c0, b.c1));
    Fp c1 = fp_sub(fp_sub(cross, v0), v1);

    return {c0, c1};
}

// Squaring: (a0 + a1·u)² = (a0+a1)(a0-a1) + 2·a0·a1·u
// 2 Fp muls instead of 3.
inline Fp2 fp2_sqr(Fp2 a) {
    Fp c0 = fp_mul(fp_add(a.c0, a.c1), fp_sub(a.c0, a.c1));
    Fp c1 = fp_mul(a.c0, a.c1);
    // c1 = 2 * a0 * a1 — we add it to itself instead of multiplying by 2
    c1 = fp_add(c1, c1);
    return {c0, c1};
}

// Multiply by the non-residue ξ = 9 + u (used in Fp6/Fp12 tower).
// (a0 + a1·u)(9 + u) = (9·a0 - a1) + (9·a1 + a0)·u
inline Fp2 fp2_mul_by_nonresidue(Fp2 a) {
    Fp nine;
    for (int i = 0; i < 8; i++) nine.limbs[i] = FP_NINE[i];
    Fp a0_9 = fp_mul(a.c0, nine);
    Fp a1_9 = fp_mul(a.c1, nine);
    return {fp_sub(a0_9, a.c1), fp_add(a1_9, a.c0)};
}

inline Fp2 fp2_zero() {
    return {fp_zero(), fp_zero()};
}

inline Fp2 fp2_one() {
    return {fp_one(), fp_zero()};
}

// Scale Fp2 by an Fp scalar: (a0 + a1·u) * s = a0·s + a1·s·u
inline Fp2 fp2_scale(Fp2 a, Fp s) {
    return {fp_mul(a.c0, s), fp_mul(a.c1, s)};
}

inline Fp2 fp2_reduce(Fp2 a) {
    return {fp_reduce(a.c0), fp_reduce(a.c1)};
}

inline bool fp2_eq(Fp2 a, Fp2 b) {
    return fp_eq(a.c0, b.c0) && fp_eq(a.c1, b.c1);
}

// ══════════════════════════════════════════════════════════════════════
// Fp6 = Fp2[v] / (v³ − ξ),  ξ = 9 + u
// ══════════════════════════════════════════════════════════════════════
//
// An Fp6 element is c0 + c1·v + c2·v²  with c0, c1, c2 ∈ Fp2.
// Key identity: v³ = ξ, so multiplying by v³ is fp2_mul_by_nonresidue.

struct Fp6 {
    Fp2 c0;
    Fp2 c1;
    Fp2 c2;
};

inline Fp6 fp6_add(Fp6 a, Fp6 b) {
    return {fp2_add(a.c0, b.c0), fp2_add(a.c1, b.c1), fp2_add(a.c2, b.c2)};
}

inline Fp6 fp6_sub(Fp6 a, Fp6 b) {
    return {fp2_sub(a.c0, b.c0), fp2_sub(a.c1, b.c1), fp2_sub(a.c2, b.c2)};
}

inline Fp6 fp6_neg(Fp6 a) {
    return {fp2_neg(a.c0), fp2_neg(a.c1), fp2_neg(a.c2)};
}

inline Fp6 fp6_zero() {
    return {fp2_zero(), fp2_zero(), fp2_zero()};
}

inline Fp6 fp6_one() {
    return {fp2_one(), fp2_zero(), fp2_zero()};
}

// Karatsuba multiplication for cubic extension.
// Reference: Devegili–OhEig–Scott–Dahab, Section 4.
//
// (d + e·v + f·v²) × (a + b·v + c·v²):
//   ad = d·a,  be = e·b,  cf = f·c
//   x  = (e+f)(b+c) − be − cf           → coefficient of v³ = ξ·x contributes to c0
//   y  = (d+e)(a+b) − ad − be           → coefficient of v
//   z  = (d+f)(a+c) − ad + be − cf      → coefficient of v²
//   c0 = ad + ξ·x
//   c1 = y  + ξ·cf
//   c2 = z
inline Fp6 fp6_mul(Fp6 self, Fp6 other) {
    Fp2 ad = fp2_mul(self.c0, other.c0);
    Fp2 be = fp2_mul(self.c1, other.c1);
    Fp2 cf = fp2_mul(self.c2, other.c2);

    Fp2 x = fp2_sub(fp2_sub(
        fp2_mul(fp2_add(self.c1, self.c2), fp2_add(other.c1, other.c2)),
        be), cf);

    Fp2 y = fp2_sub(fp2_sub(
        fp2_mul(fp2_add(self.c0, self.c1), fp2_add(other.c0, other.c1)),
        ad), be);

    Fp2 z = fp2_sub(fp2_add(fp2_sub(
        fp2_mul(fp2_add(self.c0, self.c2), fp2_add(other.c0, other.c2)),
        ad), be), cf);

    Fp2 c0 = fp2_add(ad, fp2_mul_by_nonresidue(x));
    Fp2 c1 = fp2_add(y, fp2_mul_by_nonresidue(cf));
    Fp2 c2 = z;

    return {c0, c1, c2};
}

// CH-SQR2 squaring for cubic extension.
// (a + b·v + c·v²)²:
//   s0 = a²
//   s1 = 2·a·b
//   s2 = (a − b + c)²
//   s3 = 2·b·c
//   s4 = c²
//   c0 = s0 + ξ·s3
//   c1 = s1 + ξ·s4
//   c2 = s1 + s2 + s3 − s0 − s4
inline Fp6 fp6_sqr(Fp6 a) {
    Fp2 s0 = fp2_sqr(a.c0);
    Fp2 ab = fp2_mul(a.c0, a.c1);
    Fp2 s1 = fp2_add(ab, ab);
    Fp2 s2 = fp2_sqr(fp2_add(fp2_sub(a.c0, a.c1), a.c2));
    Fp2 bc = fp2_mul(a.c1, a.c2);
    Fp2 s3 = fp2_add(bc, bc);
    Fp2 s4 = fp2_sqr(a.c2);

    Fp2 c0 = fp2_add(s0, fp2_mul_by_nonresidue(s3));
    Fp2 c1 = fp2_add(s1, fp2_mul_by_nonresidue(s4));
    Fp2 c2 = fp2_sub(fp2_sub(fp2_add(fp2_add(s1, s2), s3), s0), s4);

    return {c0, c1, c2};
}

// Sparse multiplication: self × (c0 + c1·v + 0·v²)
// Used in pairing line evaluation where the v² coefficient is zero.
inline Fp6 fp6_mul_by_01(Fp6 self, Fp2 c0, Fp2 c1) {
    Fp2 a_a = fp2_mul(self.c0, c0);
    Fp2 b_b = fp2_mul(self.c1, c1);

    Fp2 t1 = fp2_sub(fp2_mul(c1, fp2_add(self.c1, self.c2)), b_b);
    t1 = fp2_add(fp2_mul_by_nonresidue(t1), a_a);

    Fp2 t3 = fp2_add(fp2_sub(fp2_mul(c0, fp2_add(self.c0, self.c2)), a_a), b_b);

    Fp2 t2 = fp2_sub(fp2_sub(
        fp2_mul(fp2_add(c0, c1), fp2_add(self.c0, self.c1)),
        a_a), b_b);

    return {t1, t2, t3};
}

// Sparse multiplication: self × (0 + c1·v + 0·v²) = self × c1·v
inline Fp6 fp6_mul_by_1(Fp6 self, Fp2 c1) {
    Fp2 b_b = fp2_mul(self.c1, c1);

    Fp2 t1 = fp2_sub(fp2_mul(c1, fp2_add(self.c1, self.c2)), b_b);
    t1 = fp2_mul_by_nonresidue(t1);

    Fp2 t2 = fp2_sub(fp2_mul(c1, fp2_add(self.c0, self.c1)), b_b);

    return {t1, t2, b_b};
}

// Full reduction of all Fp2 components to [0, p)
inline Fp6 fp6_reduce(Fp6 a) {
    return {fp2_reduce(a.c0), fp2_reduce(a.c1), fp2_reduce(a.c2)};
}

// ══════════════════════════════════════════════════════════════════════
// Fp12 = Fp6[w] / (w² − v)
// ══════════════════════════════════════════════════════════════════════
//
// An Fp12 element is c0 + c1·w  with c0, c1 ∈ Fp6.
// Key identity: w² = v,  so multiplying an Fp6 element by the
// non-residue means multiplying by v in Fp6:
//   (a0 + a1·v + a2·v²) · v = ξ·a2 + a0·v + a1·v²

struct Fp12 {
    Fp6 c0;
    Fp6 c1;
};

// Multiply an Fp6 element by v (the Fp12 non-residue in Fp6).
// (a0 + a1·v + a2·v²) · v = ξ·a2 + a0·v + a1·v²
inline Fp6 fp6_mul_by_v(Fp6 a) {
    return {fp2_mul_by_nonresidue(a.c2), a.c0, a.c1};
}

inline Fp12 fp12_add(Fp12 a, Fp12 b) {
    return {fp6_add(a.c0, b.c0), fp6_add(a.c1, b.c1)};
}

inline Fp12 fp12_sub(Fp12 a, Fp12 b) {
    return {fp6_sub(a.c0, b.c0), fp6_sub(a.c1, b.c1)};
}

inline Fp12 fp12_neg(Fp12 a) {
    return {fp6_neg(a.c0), fp6_neg(a.c1)};
}

inline Fp12 fp12_zero() {
    return {fp6_zero(), fp6_zero()};
}

inline Fp12 fp12_one() {
    return {fp6_one(), fp6_zero()};
}

// Karatsuba multiplication for Fp12 = Fp6[w]/(w² − v):
//   (c0 + c1·w)(d0 + d1·w) = (c0·d0 + c1·d1·v) + ((c0+c1)(d0+d1) − c0·d0 − c1·d1)·w
inline Fp12 fp12_mul(Fp12 self, Fp12 other) {
    Fp6 v0 = fp6_mul(self.c0, other.c0);
    Fp6 v1 = fp6_mul(self.c1, other.c1);

    Fp6 c0 = fp6_add(v0, fp6_mul_by_v(v1));
    Fp6 c1 = fp6_sub(fp6_sub(
        fp6_mul(fp6_add(self.c0, self.c1), fp6_add(other.c0, other.c1)),
        v0), v1);

    return {c0, c1};
}

// Squaring in Fp12 = Fp6[w]/(w² − v).
// General complex squaring (non-residue ≠ −1):
//   v0 = c0 − c1
//   v3 = c0 − v·c1   (v = non-residue)
//   v2 = c0 · c1
//   result.c0 = v0·v3 + v·v2 + v2  = v0·v3 + (v+1)·v2
//   result.c1 = 2·v2
inline Fp12 fp12_sqr(Fp12 a) {
    Fp6 v0 = fp6_sub(a.c0, a.c1);
    Fp6 v3 = fp6_sub(a.c0, fp6_mul_by_v(a.c1));
    Fp6 v2 = fp6_mul(a.c0, a.c1);

    Fp6 c0 = fp6_add(fp6_add(fp6_mul(v0, v3), fp6_mul_by_v(v2)), v2);
    Fp6 c1 = fp6_add(v2, v2);

    return {c0, c1};
}

// Conjugate: for cyclotomic Fp12 elements (a + b·w)* = a − b·w
inline Fp12 fp12_conjugate(Fp12 a) {
    return {a.c0, fp6_neg(a.c1)};
}

// Full reduction of all components to [0, p)
inline Fp12 fp12_reduce(Fp12 a) {
    return {fp6_reduce(a.c0), fp6_reduce(a.c1)};
}

// Sparse Fp12 mul for D-type twist: f × (c0 + c3·w + c4·v·w)
// The sparse element decomposes as:
//   other.c0 = Fp6(c0, 0, 0)   — scalar Fp6 (only first Fp2 component)
//   other.c1 = Fp6(c3, c4, 0)  — sparse Fp6 (only first two Fp2 components)
//
// Uses Karatsuba: result.c0 = a + v·b,  result.c1 = e − a − b
// where a = self.c0 * other.c0,  b = self.c1 * other.c1,
// e = (self.c0 + self.c1) * (other.c0 + other.c1)
inline Fp12 fp12_mul_by_034(Fp12 self, Fp2 c0, Fp2 c3, Fp2 c4) {
    Fp6 a = {fp2_mul(self.c0.c0, c0), fp2_mul(self.c0.c1, c0), fp2_mul(self.c0.c2, c0)};

    // b = self.c1 * (c3, c4, 0)  — sparse Fp6 mul
    Fp6 b = fp6_mul_by_01(self.c1, c3, c4);

    // e = (self.c0 + self.c1) * ((c0 + c3), c4, 0)
    Fp6 sum01 = fp6_add(self.c0, self.c1);
    Fp2 c0_plus_c3 = fp2_add(c0, c3);
    Fp6 e = fp6_mul_by_01(sum01, c0_plus_c3, c4);

    Fp6 rc1 = fp6_sub(fp6_sub(e, a), b);
    Fp6 rc0 = fp6_add(a, fp6_mul_by_v(b));

    return {rc0, rc1};
}

// ══════════════════════════════════════════════════════════════════════
// Miller Loop
// ══════════════════════════════════════════════════════════════════════

// Line evaluation coefficient (3 × Fp2)
struct EllCoeff {
    Fp2 c0;
    Fp2 c1;
    Fp2 c2;
};

// BN254 ATE_LOOP_COUNT: 65 entries, processed from index 63 down to 0.
// Non-zero entries at the positions used in the loop (i-1 when iterating i from 64 to 1).
constant int ATE_LOOP_BITS[64] = {
    0, 0, 0, 1, 0, 1, 0, -1, 0, 0, -1, 0, 0, 0, 1, 0,
    0, -1, 0, -1, 0, 0, 0, 1, 0, -1, 0, 0, 0, 0, -1, 0,
    0, 1, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, -1,
    0, 1, 0, -1, 0, 0, 0, -1, 0, -1, 0, 0, 0, 1, 0, 1,
};

// Total number of precomputed line coefficients per pairing:
// 64 (one double per iteration) + 21 (non-zero bits) + 2 (final q1, q2) = 87
constant uint NUM_ELL_COEFFS = 87;

// Apply line evaluation (D-type twist): scale coefficients by G1 point, then
// sparse-multiply into f.
inline Fp12 ell(Fp12 f, EllCoeff coeff, Fp px, Fp py) {
    // D-type: c0 *= py, c1 *= px, then mul_by_034
    Fp2 sc0 = fp2_scale(coeff.c0, py);
    Fp2 sc1 = fp2_scale(coeff.c1, px);
    return fp12_mul_by_034(f, sc0, sc1, coeff.c2);
}

// Single-pairing Miller loop kernel.
// Each thread processes one (G1, G2Prepared) pair independently.
//
// Inputs:
//   g1_xy:  n × 2 Fp values (x, y pairs, interleaved)
//   coeffs: n × NUM_ELL_COEFFS EllCoeff values (precomputed line coefficients)
// Output:
//   result: n Fp12 values (before final exponentiation)
kernel void miller_loop(
    device const Fp*        g1_xy   [[buffer(0)]],
    device const EllCoeff*  coeffs  [[buffer(1)]],
    device Fp12*            result  [[buffer(2)]],
    uint tid                        [[thread_position_in_grid]]
) {
    Fp px = g1_xy[tid * 2];
    Fp py = g1_xy[tid * 2 + 1];

    uint ci = tid * NUM_ELL_COEFFS;
    Fp12 f = fp12_one();

    for (int i = 63; i >= 0; i--) {
        if (i != 63) {
            f = fp12_sqr(f);
        }

        f = ell(f, coeffs[ci], px, py);
        ci++;

        if (ATE_LOOP_BITS[i] != 0) {
            f = ell(f, coeffs[ci], px, py);
            ci++;
        }
    }

    // BN254: X_IS_NEGATIVE = false, so no conjugation

    // Two final ell calls (q1 and q2 Frobenius corrections)
    f = ell(f, coeffs[ci], px, py);
    ci++;
    f = ell(f, coeffs[ci], px, py);

    result[tid] = f;
}

// ──────────────────────────────────────────────────────────────────────
// Test kernels — Fp
// ──────────────────────────────────────────────────────────────────────

kernel void fp_mul_test(
    device const Fp* a       [[buffer(0)]],
    device const Fp* b       [[buffer(1)]],
    device Fp* result        [[buffer(2)]],
    uint tid                 [[thread_position_in_grid]]
) {
    result[tid] = fp_reduce(fp_mul(a[tid], b[tid]));
}

kernel void fp_add_test(
    device const Fp* a       [[buffer(0)]],
    device const Fp* b       [[buffer(1)]],
    device Fp* result        [[buffer(2)]],
    uint tid                 [[thread_position_in_grid]]
) {
    result[tid] = fp_reduce(fp_add(a[tid], b[tid]));
}

kernel void fp_sub_test(
    device const Fp* a       [[buffer(0)]],
    device const Fp* b       [[buffer(1)]],
    device Fp* result        [[buffer(2)]],
    uint tid                 [[thread_position_in_grid]]
) {
    result[tid] = fp_reduce(fp_sub(a[tid], b[tid]));
}

// ──────────────────────────────────────────────────────────────────────
// Test kernels — Fr
// ──────────────────────────────────────────────────────────────────────

kernel void fr_mul_test(
    device const Fr* a       [[buffer(0)]],
    device const Fr* b       [[buffer(1)]],
    device Fr* result        [[buffer(2)]],
    uint tid                 [[thread_position_in_grid]]
) {
    result[tid] = fr_reduce(fr_mul(a[tid], b[tid]));
}

kernel void fr_add_test(
    device const Fr* a       [[buffer(0)]],
    device const Fr* b       [[buffer(1)]],
    device Fr* result        [[buffer(2)]],
    uint tid                 [[thread_position_in_grid]]
) {
    result[tid] = fr_reduce(fr_add(a[tid], b[tid]));
}

kernel void fr_sub_test(
    device const Fr* a       [[buffer(0)]],
    device const Fr* b       [[buffer(1)]],
    device Fr* result        [[buffer(2)]],
    uint tid                 [[thread_position_in_grid]]
) {
    result[tid] = fr_reduce(fr_sub(a[tid], b[tid]));
}

// ──────────────────────────────────────────────────────────────────────
// Test kernels — Fp2
// ──────────────────────────────────────────────────────────────────────

kernel void fp2_mul_test(
    device const Fp2* a      [[buffer(0)]],
    device const Fp2* b      [[buffer(1)]],
    device Fp2* result       [[buffer(2)]],
    uint tid                 [[thread_position_in_grid]]
) {
    result[tid] = fp2_mul(a[tid], b[tid]);
}

kernel void fp2_sqr_test(
    device const Fp2* a      [[buffer(0)]],
    device const Fp2* b      [[buffer(1)]],  // unused, but keeps binary kernel interface
    device Fp2* result       [[buffer(2)]],
    uint tid                 [[thread_position_in_grid]]
) {
    result[tid] = fp2_sqr(a[tid]);
}

kernel void fp2_add_test(
    device const Fp2* a      [[buffer(0)]],
    device const Fp2* b      [[buffer(1)]],
    device Fp2* result       [[buffer(2)]],
    uint tid                 [[thread_position_in_grid]]
) {
    result[tid] = fp2_reduce(fp2_add(a[tid], b[tid]));
}

kernel void fp2_sub_test(
    device const Fp2* a      [[buffer(0)]],
    device const Fp2* b      [[buffer(1)]],
    device Fp2* result       [[buffer(2)]],
    uint tid                 [[thread_position_in_grid]]
) {
    result[tid] = fp2_reduce(fp2_sub(a[tid], b[tid]));
}

// ──────────────────────────────────────────────────────────────────────
// Test kernels — Fp6
// ──────────────────────────────────────────────────────────────────────

kernel void fp6_mul_test(
    device const Fp6* a      [[buffer(0)]],
    device const Fp6* b      [[buffer(1)]],
    device Fp6* result       [[buffer(2)]],
    uint tid                 [[thread_position_in_grid]]
) {
    result[tid] = fp6_reduce(fp6_mul(a[tid], b[tid]));
}

kernel void fp6_sqr_test(
    device const Fp6* a      [[buffer(0)]],
    device const Fp6* b      [[buffer(1)]],
    device Fp6* result       [[buffer(2)]],
    uint tid                 [[thread_position_in_grid]]
) {
    result[tid] = fp6_reduce(fp6_sqr(a[tid]));
}

kernel void fp6_add_test(
    device const Fp6* a      [[buffer(0)]],
    device const Fp6* b      [[buffer(1)]],
    device Fp6* result       [[buffer(2)]],
    uint tid                 [[thread_position_in_grid]]
) {
    result[tid] = fp6_reduce(fp6_add(a[tid], b[tid]));
}

kernel void fp6_sub_test(
    device const Fp6* a      [[buffer(0)]],
    device const Fp6* b      [[buffer(1)]],
    device Fp6* result       [[buffer(2)]],
    uint tid                 [[thread_position_in_grid]]
) {
    result[tid] = fp6_reduce(fp6_sub(a[tid], b[tid]));
}

// ──────────────────────────────────────────────────────────────────────
// Test kernels — Fp12
// ──────────────────────────────────────────────────────────────────────

kernel void fp12_mul_test(
    device const Fp12* a     [[buffer(0)]],
    device const Fp12* b     [[buffer(1)]],
    device Fp12* result      [[buffer(2)]],
    uint tid                 [[thread_position_in_grid]]
) {
    result[tid] = fp12_reduce(fp12_mul(a[tid], b[tid]));
}

// Test fp12_mul_by_034: 'a' is the Fp12 operand, 'b' packs the sparse coefficients:
//   c0 = b.c0.c0,  c3 = b.c0.c1,  c4 = b.c0.c2  (rest of b is ignored)
kernel void fp12_mul_by_034_test(
    device const Fp12* a     [[buffer(0)]],
    device const Fp12* b     [[buffer(1)]],
    device Fp12* result      [[buffer(2)]],
    uint tid                 [[thread_position_in_grid]]
) {
    result[tid] = fp12_reduce(fp12_mul_by_034(
        a[tid], b[tid].c0.c0, b[tid].c0.c1, b[tid].c0.c2));
}

kernel void fp12_sqr_test(
    device const Fp12* a     [[buffer(0)]],
    device const Fp12* b     [[buffer(1)]],
    device Fp12* result      [[buffer(2)]],
    uint tid                 [[thread_position_in_grid]]
) {
    result[tid] = fp12_reduce(fp12_sqr(a[tid]));
}
