//! Protocol messages exchanged between prover and verifier
//!
//! These messages correspond to the Extended Dory Reduce protocol from Section 3.2
//! and the VMV transformation for polynomial commitments.

/// First prover message in the Dory-Reduce protocol (Section 3.2)
///
/// Contains D₁L, D₁R, D₂L, D₂R, E₁β, E₂β
#[derive(Clone, Debug, PartialEq)]
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
#[derive(Clone, Debug, PartialEq)]
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

/// Final scalar product message (Section 3.1)
///
/// Contains E₁, E₂ for the final pairing verification
#[derive(Clone, Debug, PartialEq)]
pub struct ScalarProductMessage<G1, G2> {
    /// E₁ - final G1 element
    pub e1: G1,
    /// E₂ - final G2 element
    pub e2: G2,
}

/// ZK scalar product proof: proves (C, D1, D2) are consistent with blinded v1, v2.
#[derive(Clone, Debug, PartialEq)]
#[allow(missing_docs)]
pub struct ScalarProductProof<G1, G2, F, GT> {
    pub p1: GT,
    pub p2: GT,
    pub q: GT,
    pub r: GT,
    pub e1: G1,
    pub e2: G2,
    pub r1: F,
    pub r2: F,
    pub r3: F,
}
