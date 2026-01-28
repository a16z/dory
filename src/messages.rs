//! Protocol messages exchanged between prover and verifier
//!
//! These messages correspond to the Extended Dory Reduce protocol from Section 3.2
//! and the VMV transformation for polynomial commitments.

/// First prover message in the Dory-Reduce protocol (Section 3.2)
///
/// Contains D₁L, D₁R, D₂L, D₂R, E₁β, E₂β
#[derive(Clone, Debug)]
pub struct FirstReduceMessage<G1, G2, GT> {
    /// D₁L - left pairing for first set
    pub d1_left: GT,
    /// D₁R - right pairing for first set
    pub d1_right: GT,
    /// D₂L - left pairing for second set
    pub d2_left: GT,
    /// D₂R - right pairing for second set
    pub d2_right: GT,
    /// E₁β - extension element in G1 (Section 4.2)
    pub e1_beta: G1,
    /// E₂β - extension element in G2 (Section 4.2)
    pub e2_beta: G2,
}

/// Second prover message in the Dory-Reduce protocol (Section 3.2)
///
/// Contains C₊, C₋, E₁₊, E₁₋, E₂₊, E₂₋
#[derive(Clone, Debug)]
pub struct SecondReduceMessage<G1, G2, GT> {
    /// C₊ - plus combination
    pub c_plus: GT,
    /// C₋ - minus combination
    pub c_minus: GT,
    /// E₁₊ - extension element plus in G1
    pub e1_plus: G1,
    /// E₁₋ - extension element minus in G1
    pub e1_minus: G1,
    /// E₂₊ - extension element plus in G2
    pub e2_plus: G2,
    /// E₂₋ - extension element minus in G2
    pub e2_minus: G2,
}

/// Vector-Matrix-Vector message for polynomial commitment transformation
///
/// Contains C, D₂, E₁. In transparent mode, E₂ = y·Γ₂,fin is computed by verifier.
/// In ZK mode, E₂ and y_com are stored in the proof's optional fields.
#[derive(Clone, Debug)]
pub struct VMVMessage<G1, GT> {
    /// C = e(MSM(T_vec', v_vec), Γ₂,fin) + r_c·HT
    pub c: GT,
    /// D₂ = e(MSM(Γ₁\[nu\], v_vec), Γ₂,fin) + r_d2·HT
    pub d2: GT,
    /// E₁ = MSM(T_vec', L_vec) + r_e1·H1
    pub e1: G1,
}

/// Final scalar product message (Section 3.1)
///
/// Contains E₁, E₂ for the final pairing verification
#[derive(Clone, Debug)]
pub struct ScalarProductMessage<G1, G2> {
    /// E₁ - final G1 element
    pub e1: G1,
    /// E₂ - final G2 element
    pub e2: G2,
}

/// ZK VMV Σ-protocol 1: proves knowledge of (y, rE2, ry) such that:
/// - E2 = y·Γ2,fin + rE2·H2
/// - yC = y·Γ1,fin + ry·H1
///
/// This proves the commitment yC is consistent with E2.
#[cfg(feature = "zk")]
#[derive(Clone, Debug)]
pub struct Sigma1Proof<G1, G2, F> {
    /// Commitment A1 = k1·Γ2,fin + k2·H2 (for E2 relation)
    pub a1: G2,
    /// Commitment A2 = k1·Γ1,fin + k3·H1 (for yC relation)
    pub a2: G1,
    /// Response z1 = k1 + c·y
    pub z1: F,
    /// Response z2 = k2 + c·rE2
    pub z2: F,
    /// Response z3 = k3 + c·ry
    pub z3: F,
}

/// ZK VMV Σ-protocol 2: proves knowledge of (t1, t2) such that:
/// e(E1, Γ2,fin) - D2 = e(H1, t1·Γ2,fin + t2·H2)
///
/// Where t1 = rE1 + rv and t2 = -rD2.
/// This proves the relation between E1 and D2 with blinds.
#[cfg(feature = "zk")]
#[derive(Clone, Debug)]
pub struct Sigma2Proof<F, GT> {
    /// Commitment A = e(H1, k1·Γ2,fin + k2·H2)
    pub a: GT,
    /// Response z1 = k1 + c·t1
    pub z1: F,
    /// Response z2 = k2 + c·t2
    pub z2: F,
}

/// Zero-knowledge scalar product proof (Σ-protocol)
///
/// Proves knowledge of (v1, v2, rC, rD1, rD2) for relation L1:
/// - C = e(v1, v2) + rC·HT
/// - D1 = e(v1, Γ2) + rD1·HT
/// - D2 = e(Γ1, v2) + rD2·HT
///
/// Protocol from Dory paper Section 3.1.
#[cfg(feature = "zk")]
#[derive(Clone, Debug)]
pub struct ScalarProductProof<G1, G2, F, GT> {
    /// P1 = e(d1, Γ2) + rP1·HT
    pub p1: GT,
    /// P2 = e(Γ1, d2) + rP2·HT
    pub p2: GT,
    /// Q = e(d1, v2) + e(v1, d2) + rQ·HT
    pub q: GT,
    /// R = e(d1, d2) + rR·HT
    pub r: GT,
    /// E1 = d1 + c·v1
    pub e1: G1,
    /// E2 = d2 + c·v2
    pub e2: G2,
    /// r1 = rP1 + c·rD1
    pub r1: F,
    /// r2 = rP2 + c·rD2
    pub r2: F,
    /// r3 = rR + c·rQ + c²·rC
    pub r3: F,
}
