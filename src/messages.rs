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
/// Contains C, D₂, E₁. Note: E₂ can be computed by verifier as y·Γ₂,fin
#[derive(Clone, Debug)]
pub struct VMVMessage<G1, GT> {
    /// C = e(MSM(T_vec', v_vec), Γ₂,fin)
    pub c: GT,
    /// D₂ = e(MSM(Γ₁\[nu\], v_vec), Γ₂,fin)
    pub d2: GT,
    /// E₁ = MSM(T_vec', L_vec)
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

impl<G1, G2, GT> FirstReduceMessage<G1, G2, GT> {
    /// Generate a FirstReduceMessage
    ///
    /// This function converts the FirstReduceMessage to a different GT type and is currently used for compression.
    pub fn convert_gt<GT2>(&self) -> FirstReduceMessage<G1, G2, GT2>
    where
        GT: Into<GT2> + Clone,
        G1: Clone,
        G2: Clone,
    {
        FirstReduceMessage {
            d1_left: self.d1_left.clone().into(),
            d1_right: self.d1_right.clone().into(),
            d2_left: self.d2_left.clone().into(),
            d2_right: self.d2_right.clone().into(),
            e1_beta: self.e1_beta.clone(),
            e2_beta: self.e2_beta.clone(),
        }
    }
}

impl<G1, G2, GT> SecondReduceMessage<G1, G2, GT> {
    /// Generate a SecondReduceMessage
    ///
    /// This function converts the SecondReduceMessage to a different GT type and is currently used for compression.
    pub fn convert_gt<GT2>(&self) -> SecondReduceMessage<G1, G2, GT2>
    where
        GT: Into<GT2> + Clone,
        G1: Clone,
        G2: Clone,
    {
        SecondReduceMessage {
            c_plus: self.c_plus.clone().into(),
            c_minus: self.c_minus.clone().into(),
            e1_plus: self.e1_plus.clone(),
            e1_minus: self.e1_minus.clone(),
            e2_plus: self.e2_plus.clone(),
            e2_minus: self.e2_minus.clone(),
        }
    }
}
