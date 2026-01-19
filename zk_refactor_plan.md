# ZK Implementation Refactoring Plan (v2)

## Design Philosophy

Use Rust's trait system to unify Transparent and ZK modes into **single code paths**. The `Mode` trait with associated types determines all behavioral differences at compile time.

**Two modes only:**
- `Transparent` - no blinds, evaluation `y` revealed to verifier
- `ZK` - full blinds, evaluation hidden (verifier receives `y_com`)

---

## Core Design: The Mode Trait

```rust
pub trait Mode: 'static + Clone {
    /// Witness provided to verifier
    /// - Transparent: the evaluation F
    /// - ZK: commitment to evaluation G1
    type Witness<F: Field, G1: Group<Scalar = F>>: Clone;

    /// Extra proof elements
    /// - Transparent: ()
    /// - ZK: ZkProofs (sigma1, sigma2, scalar_product)
    type Extras<G1: Group, G2: Group<Scalar = G1::Scalar>, GT: Group<Scalar = G1::Scalar>>: Clone + Default;

    /// VMV message extension
    /// - Transparent: ()
    /// - ZK: (E2, y_com) tuple
    type VmvExtras<G1: Group, G2: Group<Scalar = G1::Scalar>>: Clone + Default;

    /// Sample blinding factor (zero for Transparent, random for ZK)
    fn sample<F: Field, R: RngCore>(rng: &mut R) -> F;

    /// Mask group element (identity for Transparent, adds blind for ZK)
    fn mask<G: Group>(value: G, base: &G, blind: &G::Scalar) -> G;

    /// Create witness and VMV extras from evaluation y
    fn create_witness<E: PairingCurve, R: RngCore>(
        y: &E::Scalar,
        r_e2: &E::Scalar,
        setup: &ProverSetup<E>,
        rng: &mut R,
    ) -> (Self::Witness<E::Scalar, E::G1>, Self::VmvExtras<E::G1, E::G2>, WitnessSecrets<E::Scalar>)
    where
        E::G1: Group<Scalar = E::Scalar>,
        E::G2: Group<Scalar = E::Scalar>;

    /// Extract E2 for verifier state
    /// - Transparent: compute from witness (y · Γ2,fin)
    /// - ZK: extract from VMV extras
    fn verifier_e2<E: PairingCurve>(
        witness: &Self::Witness<E::Scalar, E::G1>,
        vmv_extras: &Self::VmvExtras<E::G1, E::G2>,
        setup: &VerifierSetup<E>,
    ) -> E::G2
    where
        E::G1: Group<Scalar = E::Scalar>,
        E::G2: Group<Scalar = E::Scalar>;

    /// Generate extra proofs (sigma proofs for ZK, no-op for Transparent)
    fn generate_extras<E: PairingCurve, T: Transcript<Curve = E>, R: RngCore>(
        witness_secrets: &WitnessSecrets<E::Scalar>,
        vmv_blinds: &VmvBlinds<E::Scalar>,
        prover_state: &DoryProverState<E>,
        setup: &ProverSetup<E>,
        transcript: &mut T,
        rng: &mut R,
    ) -> Self::Extras<E::G1, E::G2, E::GT>
    where
        E::G1: Group<Scalar = E::Scalar>,
        E::G2: Group<Scalar = E::Scalar>,
        E::GT: Group<Scalar = E::Scalar>;

    /// Verify extra proofs (no-op for Transparent)
    fn verify_extras<E: PairingCurve, T: Transcript<Curve = E>>(
        extras: &Self::Extras<E::G1, E::G2, E::GT>,
        vmv_extras: &Self::VmvExtras<E::G1, E::G2>,
        vmv_message: &VMVMessage<E::G1, E::GT>,
        setup: &VerifierSetup<E>,
        transcript: &mut T,
    ) -> Result<(), DoryError>
    where
        E::G1: Group<Scalar = E::Scalar>,
        E::G2: Group<Scalar = E::Scalar>,
        E::GT: Group<Scalar = E::Scalar>;

    /// Append VMV extras to transcript (no-op for Transparent)
    fn append_vmv_extras_to_transcript<E: PairingCurve, T: Transcript<Curve = E>>(
        vmv_extras: &Self::VmvExtras<E::G1, E::G2>,
        transcript: &mut T,
    ) where
        E::G1: Group<Scalar = E::Scalar>,
        E::G2: Group<Scalar = E::Scalar>;

    /// Final verification dispatch
    fn verify_final<E: PairingCurve>(
        verifier_state: &mut DoryVerifierState<E>,
        extras: &Self::Extras<E::G1, E::G2, E::GT>,
        final_message: &ScalarProductMessage<E::G1, E::G2>,
        gamma: &E::Scalar,
        d: &E::Scalar,
    ) -> Result<(), DoryError>
    where
        E::G1: Group<Scalar = E::Scalar>,
        E::G2: Group<Scalar = E::Scalar>,
        E::GT: Group<Scalar = E::Scalar>;
}
```

---

## Mode Implementations

### Transparent Mode

```rust
#[derive(Clone, Copy, Default)]
pub struct Transparent;

impl Mode for Transparent {
    type Witness<F: Field, G1: Group<Scalar = F>> = F;
    type Extras<G1: Group, G2: Group<Scalar = G1::Scalar>, GT: Group<Scalar = G1::Scalar>> = ();
    type VmvExtras<G1: Group, G2: Group<Scalar = G1::Scalar>> = ();

    fn sample<F: Field, R: RngCore>(_rng: &mut R) -> F {
        F::zero()
    }

    fn mask<G: Group>(value: G, _base: &G, _blind: &G::Scalar) -> G {
        value
    }

    fn create_witness<E: PairingCurve, R: RngCore>(
        y: &E::Scalar,
        _r_e2: &E::Scalar,
        _setup: &ProverSetup<E>,
        _rng: &mut R,
    ) -> (E::Scalar, (), WitnessSecrets<E::Scalar>)
    where
        E::G1: Group<Scalar = E::Scalar>,
        E::G2: Group<Scalar = E::Scalar>,
    {
        (*y, (), WitnessSecrets::default())
    }

    fn verifier_e2<E: PairingCurve>(
        witness: &E::Scalar,
        _vmv_extras: &(),
        setup: &VerifierSetup<E>,
    ) -> E::G2
    where
        E::G1: Group<Scalar = E::Scalar>,
        E::G2: Group<Scalar = E::Scalar>,
    {
        // E2 = y · Γ2,fin
        setup.g2_0.scale(witness)
    }

    fn generate_extras<E: PairingCurve, T: Transcript<Curve = E>, R: RngCore>(
        _witness_secrets: &WitnessSecrets<E::Scalar>,
        _vmv_blinds: &VmvBlinds<E::Scalar>,
        _prover_state: &DoryProverState<E>,
        _setup: &ProverSetup<E>,
        _transcript: &mut T,
        _rng: &mut R,
    ) -> ()
    where
        E::G1: Group<Scalar = E::Scalar>,
        E::G2: Group<Scalar = E::Scalar>,
        E::GT: Group<Scalar = E::Scalar>,
    {
        ()
    }

    fn verify_extras<E: PairingCurve, T: Transcript<Curve = E>>(
        _extras: &(),
        _vmv_extras: &(),
        _vmv_message: &VMVMessage<E::G1, E::GT>,
        _setup: &VerifierSetup<E>,
        _transcript: &mut T,
    ) -> Result<(), DoryError>
    where
        E::G1: Group<Scalar = E::Scalar>,
        E::G2: Group<Scalar = E::Scalar>,
        E::GT: Group<Scalar = E::Scalar>,
    {
        Ok(())
    }

    fn append_vmv_extras_to_transcript<E: PairingCurve, T: Transcript<Curve = E>>(
        _vmv_extras: &(),
        _transcript: &mut T,
    ) where
        E::G1: Group<Scalar = E::Scalar>,
        E::G2: Group<Scalar = E::Scalar>,
    {
        // No extras to append
    }

    fn verify_final<E: PairingCurve>(
        verifier_state: &mut DoryVerifierState<E>,
        _extras: &(),
        final_message: &ScalarProductMessage<E::G1, E::G2>,
        gamma: &E::Scalar,
        d: &E::Scalar,
    ) -> Result<(), DoryError>
    where
        E::G1: Group<Scalar = E::Scalar>,
        E::G2: Group<Scalar = E::Scalar>,
        E::GT: Group<Scalar = E::Scalar>,
    {
        verifier_state.verify_final(final_message, gamma, d)
    }
}
```

### ZK Mode

```rust
#[derive(Clone, Copy, Default)]
#[cfg(feature = "zk")]
pub struct ZK;

/// Secrets generated during witness creation, needed for sigma proofs
#[cfg(feature = "zk")]
pub struct WitnessSecrets<F> {
    pub r_y: F,      // blind for y_com
    pub r_e2: F,     // blind for E2
}

/// VMV extras for ZK mode
#[cfg(feature = "zk")]
#[derive(Clone)]
pub struct ZkVmvExtras<G1, G2> {
    pub e2: G2,      // E2 = y·Γ2,fin + r_e2·H2
    pub y_com: G1,   // y_com = y·Γ1,fin + r_y·H1
}

/// Extra proofs for ZK mode
#[cfg(feature = "zk")]
#[derive(Clone)]
pub struct ZkProofs<G1, G2, F, GT> {
    pub sigma1: Sigma1Proof<G1, G2, F>,
    pub sigma2: Sigma2Proof<F, GT>,
    pub scalar_product: ScalarProductProof<G1, G2, F, GT>,
}

#[cfg(feature = "zk")]
impl Mode for ZK {
    type Witness<F: Field, G1: Group<Scalar = F>> = G1;  // y_com
    type Extras<G1: Group, G2: Group<Scalar = G1::Scalar>, GT: Group<Scalar = G1::Scalar>> =
        ZkProofs<G1, G2, G1::Scalar, GT>;
    type VmvExtras<G1: Group, G2: Group<Scalar = G1::Scalar>> = ZkVmvExtras<G1, G2>;

    fn sample<F: Field, R: RngCore>(rng: &mut R) -> F {
        F::random(rng)
    }

    fn mask<G: Group>(value: G, base: &G, blind: &G::Scalar) -> G {
        value + base.scale(blind)
    }

    fn create_witness<E: PairingCurve, R: RngCore>(
        y: &E::Scalar,
        r_e2: &E::Scalar,
        setup: &ProverSetup<E>,
        rng: &mut R,
    ) -> (E::G1, ZkVmvExtras<E::G1, E::G2>, WitnessSecrets<E::Scalar>)
    where
        E::G1: Group<Scalar = E::Scalar>,
        E::G2: Group<Scalar = E::Scalar>,
    {
        let r_y = E::Scalar::random(rng);

        // y_com = y·Γ1,fin + r_y·H1
        let y_com = setup.g1_vec[0].scale(y) + setup.h1.scale(&r_y);

        // E2 = y·Γ2,fin + r_e2·H2
        let e2 = setup.g2_vec[0].scale(y) + setup.h2.scale(r_e2);

        let vmv_extras = ZkVmvExtras { e2, y_com };
        let secrets = WitnessSecrets { r_y, r_e2: *r_e2 };

        (y_com, vmv_extras, secrets)
    }

    fn verifier_e2<E: PairingCurve>(
        _witness: &E::G1,
        vmv_extras: &ZkVmvExtras<E::G1, E::G2>,
        _setup: &VerifierSetup<E>,
    ) -> E::G2
    where
        E::G1: Group<Scalar = E::Scalar>,
        E::G2: Group<Scalar = E::Scalar>,
    {
        // E2 comes from prover's VMV message
        vmv_extras.e2
    }

    fn generate_extras<E: PairingCurve, T: Transcript<Curve = E>, R: RngCore>(
        witness_secrets: &WitnessSecrets<E::Scalar>,
        vmv_blinds: &VmvBlinds<E::Scalar>,
        prover_state: &DoryProverState<E>,
        setup: &ProverSetup<E>,
        transcript: &mut T,
        rng: &mut R,
    ) -> ZkProofs<E::G1, E::G2, E::Scalar, E::GT>
    where
        E::G1: Group<Scalar = E::Scalar>,
        E::G2: Group<Scalar = E::Scalar>,
        E::GT: Group<Scalar = E::Scalar>,
    {
        // Generate sigma1: proves y_com and E2 commit to same y
        let sigma1 = generate_sigma1_proof(/* ... */);

        // Generate sigma2: proves VMV relation holds with blinds
        let sigma2 = generate_sigma2_proof(/* ... */);

        // Generate scalar product proof
        let scalar_product = prover_state.scalar_product_proof(transcript, rng);

        ZkProofs { sigma1, sigma2, scalar_product }
    }

    fn verify_extras<E: PairingCurve, T: Transcript<Curve = E>>(
        extras: &ZkProofs<E::G1, E::G2, E::Scalar, E::GT>,
        vmv_extras: &ZkVmvExtras<E::G1, E::G2>,
        vmv_message: &VMVMessage<E::G1, E::GT>,
        setup: &VerifierSetup<E>,
        transcript: &mut T,
    ) -> Result<(), DoryError>
    where
        E::G1: Group<Scalar = E::Scalar>,
        E::G2: Group<Scalar = E::Scalar>,
        E::GT: Group<Scalar = E::Scalar>,
    {
        verify_sigma1_proof(&vmv_extras.e2, &vmv_extras.y_com, &extras.sigma1, setup, transcript)?;
        verify_sigma2_proof(&vmv_message.e1, &vmv_message.d2, &extras.sigma2, setup, transcript)?;
        Ok(())
    }

    fn append_vmv_extras_to_transcript<E: PairingCurve, T: Transcript<Curve = E>>(
        vmv_extras: &ZkVmvExtras<E::G1, E::G2>,
        transcript: &mut T,
    ) where
        E::G1: Group<Scalar = E::Scalar>,
        E::G2: Group<Scalar = E::Scalar>,
    {
        transcript.append_serde(b"vmv_e2", &vmv_extras.e2);
        transcript.append_serde(b"vmv_y_com", &vmv_extras.y_com);
    }

    fn verify_final<E: PairingCurve>(
        verifier_state: &mut DoryVerifierState<E>,
        extras: &ZkProofs<E::G1, E::G2, E::Scalar, E::GT>,
        _final_message: &ScalarProductMessage<E::G1, E::G2>,
        _gamma: &E::Scalar,
        d: &E::Scalar,
    ) -> Result<(), DoryError>
    where
        E::G1: Group<Scalar = E::Scalar>,
        E::G2: Group<Scalar = E::Scalar>,
        E::GT: Group<Scalar = E::Scalar>,
    {
        // Derive challenge c from scalar product proof (already in transcript)
        let c = /* from transcript */;
        verifier_state.verify_final_zk_with_challenge(&extras.scalar_product, &c, d)
    }
}
```

---

## Unified Data Structures

### DoryProof (Single Type)

```rust
/// Complete Dory evaluation proof, parameterized by Mode
pub struct DoryProof<G1, G2, GT, M: Mode>
where
    G1: Group,
    G2: Group<Scalar = G1::Scalar>,
    GT: Group<Scalar = G1::Scalar>,
{
    /// VMV message (C, D2, E1)
    pub vmv_message: VMVMessage<G1, GT>,

    /// VMV extras (empty for Transparent, E2/y_com for ZK)
    pub vmv_extras: M::VmvExtras<G1, G2>,

    /// Reduce round messages
    pub first_messages: Vec<FirstReduceMessage<G1, G2, GT>>,
    pub second_messages: Vec<SecondReduceMessage<G1, G2, GT>>,

    /// Final scalar product message
    pub final_message: ScalarProductMessage<G1, G2>,

    /// Mode-specific extra proofs (empty for Transparent, sigma proofs for ZK)
    pub extras: M::Extras<G1, G2, GT>,

    /// Matrix dimensions
    pub nu: usize,
    pub sigma: usize,
}
```

### VMVMessage (Unchanged)

```rust
/// VMV message - same for both modes
/// Mode-specific data (E2, y_com) stored in DoryProof::vmv_extras
pub struct VMVMessage<G1, GT> {
    pub c: GT,
    pub d2: GT,
    pub e1: G1,
}
```

---

## Unified API

### Single prove Function

```rust
/// Create evaluation proof
///
/// Returns (proof, witness) where witness is:
/// - Transparent: the evaluation y (type F)
/// - ZK: commitment to y (type G1)
pub fn prove<F, E, M1, M2, P, T, M, R>(
    polynomial: &P,
    point: &[F],
    row_commitments: Vec<E::G1>,
    nu: usize,
    sigma: usize,
    setup: &ProverSetup<E>,
    transcript: &mut T,
    rng: &mut R,
) -> Result<(DoryProof<E::G1, E::G2, E::GT, M>, M::Witness<F, E::G1>), DoryError>
where
    F: Field,
    E: PairingCurve,
    E::G1: Group<Scalar = F>,
    E::G2: Group<Scalar = F>,
    E::GT: Group<Scalar = F>,
    M1: DoryRoutines<E::G1>,
    M2: DoryRoutines<E::G2>,
    P: MultilinearLagrange<F>,
    T: Transcript<Curve = E>,
    M: Mode,
    R: RngCore,
{
    // Validation
    if point.len() != nu + sigma {
        return Err(DoryError::InvalidPointDimension { ... });
    }
    if nu > sigma {
        return Err(DoryError::InvalidSize { ... });
    }

    // Compute evaluation vectors
    let (left_vec, right_vec) = polynomial.compute_evaluation_vectors(point, nu, sigma);
    let v_vec = polynomial.vector_matrix_product(&left_vec, nu, sigma);

    // Compute y
    let y = polynomial.evaluate(point);

    // Sample VMV blinds using Mode
    let r_c: F = M::sample(rng);
    let r_d2: F = M::sample(rng);
    let r_e1: F = M::sample(rng);
    let r_e2: F = M::sample(rng);
    let vmv_blinds = VmvBlinds { r_c, r_d2, r_e1, r_e2 };

    // Create witness and VMV extras using Mode
    let (witness, vmv_extras, witness_secrets) = M::create_witness(&y, &r_e2, setup, rng);

    // Compute VMV message using Mode::mask
    let g2_fin = &setup.g2_vec[0];
    let t_vec_v = M1::msm(&padded_row_commitments, &v_vec);
    let c = M::mask(E::pair(&t_vec_v, g2_fin), &setup.ht, &r_c);

    let g1_bases = &setup.g1_vec[..1 << sigma];
    let gamma1_v = M1::msm(g1_bases, &v_vec);
    let d2 = M::mask(E::pair(&gamma1_v, g2_fin), &setup.ht, &r_d2);

    let e1 = M::mask(M1::msm(&row_commitments, &left_vec), &setup.h1, &r_e1);

    let vmv_message = VMVMessage { c, d2, e1 };

    // Append to transcript
    transcript.append_serde(b"vmv_c", &vmv_message.c);
    transcript.append_serde(b"vmv_d2", &vmv_message.d2);
    transcript.append_serde(b"vmv_e1", &vmv_message.e1);
    M::append_vmv_extras_to_transcript::<E, T>(&vmv_extras, transcript);

    // Initialize prover state
    let mut prover_state = DoryProverState::new_with_blinds(
        padded_row_commitments, v2, Some(v_vec),
        padded_right_vec, padded_left_vec,
        setup, r_c, r_d2, r_e1, r_e2,
    );

    // Reduce-and-fold rounds (identical for both modes)
    let mut first_messages = Vec::with_capacity(num_rounds);
    let mut second_messages = Vec::with_capacity(num_rounds);

    for _ in 0..num_rounds {
        let (first_msg, r_d1_l, r_d1_r, r_d2_l, r_d2_r) =
            prover_state.compute_first_message::<M1, M2, M, R>(rng);
        // ... append to transcript, get beta ...
        prover_state.apply_first_challenge::<M1, M2>(&beta);
        first_messages.push(first_msg);

        let (second_msg, ...) = prover_state.compute_second_message::<M1, M2, M, R>(rng);
        // ... append to transcript, get alpha ...
        prover_state.apply_second_challenge::<M1, M2>(...);
        second_messages.push(second_msg);
    }

    let gamma = transcript.challenge_scalar(b"gamma");

    // Generate mode-specific extras (sigma proofs for ZK, nothing for Transparent)
    let extras = M::generate_extras(&witness_secrets, &vmv_blinds, &prover_state, setup, transcript, rng);

    let final_message = prover_state.compute_final_message::<M1, M2>(&gamma);

    transcript.append_serde(b"final_e1", &final_message.e1);
    transcript.append_serde(b"final_e2", &final_message.e2);
    let _d = transcript.challenge_scalar(b"d");

    Ok((
        DoryProof {
            vmv_message,
            vmv_extras,
            first_messages,
            second_messages,
            final_message,
            extras,
            nu,
            sigma,
        },
        witness,
    ))
}
```

### Single verify Function

```rust
/// Verify evaluation proof
///
/// Takes witness which is:
/// - Transparent: the evaluation y (type F)
/// - ZK: commitment to y (type G1)
pub fn verify<F, E, M1, M2, T, M>(
    commitment: E::GT,
    witness: M::Witness<F, E::G1>,
    point: &[F],
    proof: &DoryProof<E::G1, E::G2, E::GT, M>,
    setup: VerifierSetup<E>,
    transcript: &mut T,
) -> Result<(), DoryError>
where
    F: Field,
    E: PairingCurve,
    E::G1: Group<Scalar = F>,
    E::G2: Group<Scalar = F>,
    E::GT: Group<Scalar = F>,
    M1: DoryRoutines<E::G1>,
    M2: DoryRoutines<E::G2>,
    T: Transcript<Curve = E>,
    M: Mode,
{
    let nu = proof.nu;
    let sigma = proof.sigma;

    if point.len() != nu + sigma {
        return Err(DoryError::InvalidPointDimension { ... });
    }

    // Append VMV to transcript
    transcript.append_serde(b"vmv_c", &proof.vmv_message.c);
    transcript.append_serde(b"vmv_d2", &proof.vmv_message.d2);
    transcript.append_serde(b"vmv_e1", &proof.vmv_message.e1);
    M::append_vmv_extras_to_transcript::<E, T>(&proof.vmv_extras, transcript);

    // Verify mode-specific extras (sigma proofs for ZK)
    M::verify_extras(&proof.extras, &proof.vmv_extras, &proof.vmv_message, &setup, transcript)?;

    // Get E2 based on mode
    let e2 = M::verifier_e2::<E>(&witness, &proof.vmv_extras, &setup);

    // Initialize verifier state
    let mut verifier_state = DoryVerifierState::new(
        proof.vmv_message.c,
        commitment,
        proof.vmv_message.d2,
        proof.vmv_message.e1,
        e2,
        s1_coords,
        s2_coords,
        num_rounds,
        setup.clone(),
    );

    // Process rounds (identical for both modes)
    for round in 0..num_rounds {
        let first_msg = &proof.first_messages[round];
        let second_msg = &proof.second_messages[round];
        // ... append to transcript, get challenges ...
        verifier_state.process_round(first_msg, second_msg, &alpha, &beta);
    }

    let gamma = transcript.challenge_scalar(b"gamma");

    // Append final message
    transcript.append_serde(b"final_e1", &proof.final_message.e1);
    transcript.append_serde(b"final_e2", &proof.final_message.e2);
    let d = transcript.challenge_scalar(b"d");

    // Final verification dispatch based on mode
    M::verify_final(&mut verifier_state, &proof.extras, &proof.final_message, &gamma, &d)
}
```

---

## Usage Examples

### Transparent Mode

```rust
// Prove
let (proof, evaluation) = prove::<_, BN254, G1Routines, G2Routines, _, _, Transparent, _>(
    &poly, &point, tier_1, nu, sigma, &prover_setup, &mut transcript, &mut rng
)?;

// Verify
verify::<_, BN254, G1Routines, G2Routines, _, Transparent>(
    tier_2, evaluation, &point, &proof, verifier_setup, &mut transcript
)?;
```

### ZK Mode

```rust
// Prove - returns y_com instead of y
let (proof, y_com) = prove::<_, BN254, G1Routines, G2Routines, _, _, ZK, _>(
    &poly, &point, tier_1, nu, sigma, &prover_setup, &mut transcript, &mut rng
)?;

// Verify - takes y_com instead of y
verify::<_, BN254, G1Routines, G2Routines, _, ZK>(
    tier_2, y_com, &point, &proof, verifier_setup, &mut transcript
)?;
```

---

## Files to Modify

### Delete Entirely
- `src/backends/arkworks/ark_poly.rs`: `commit_zk` method (~60 lines)
- `src/primitives/poly.rs`: `commit_zk` trait method (~15 lines)

### Major Refactor
| File | Changes |
|------|---------|
| `src/mode.rs` | Expand Mode trait with associated types and methods |
| `src/proof.rs` | Single `DoryProof<..., M: Mode>`, delete `ZkDoryProof` |
| `src/messages.rs` | Delete `ZkVMVMessage`, add `ZkVmvExtras` |
| `src/evaluation_proof.rs` | Single `prove`/`verify`, delete duplicates (~350 lines removed) |
| `src/reduce_and_fold.rs` | Delete duplicate `scalar_product_proof`, keep single impl |
| `src/lib.rs` | Update exports |

### Minor Updates
| File | Changes |
|------|---------|
| `tests/arkworks/*.rs` | Update to new API |
| `examples/*.rs` | Update to new API (add `Transparent` parameter) |

---

## Expected Diff Reduction

| Component | Before | After | Reduction |
|-----------|--------|-------|-----------|
| `evaluation_proof.rs` | +453 | ~+50 | -400 |
| `reduce_and_fold.rs` | +783 | ~+300 | -483 |
| `proof.rs` | +56 | ~+20 | -36 |
| `messages.rs` | +97 | ~+40 | -57 |
| `ark_poly.rs` | +58 | 0 | -58 |
| **Total** | +1494 | ~+450 | **-1044 (70%)** |

---

## Implementation Order

1. **Expand Mode trait** in `src/mode.rs`
   - Add associated types
   - Add all trait methods with Transparent impl
   - Add ZK impl (feature-gated)

2. **Unify proof types** in `src/proof.rs` and `src/messages.rs`
   - Single `DoryProof<..., M>`
   - Add `ZkVmvExtras`, `ZkProofs`
   - Delete `ZkDoryProof`, `ZkVMVMessage`

3. **Unify prove/verify** in `src/evaluation_proof.rs`
   - Single `prove` function using Mode methods
   - Single `verify` function using Mode methods
   - Delete `create_zk_evaluation_proof`, `verify_zk_evaluation_proof`

4. **Clean up reduce_and_fold.rs**
   - Delete duplicate `scalar_product_proof`
   - Update to use Mode trait

5. **Delete dead code**
   - Remove `commit_zk` from trait and impl

6. **Update tests and examples**
   - Add explicit `Transparent` or `ZK` mode parameter

---

## Verification Checklist

- [ ] `cargo nextest run --features backends` passes (Transparent mode)
- [ ] `cargo nextest run --features "backends,zk"` passes (both modes)
- [ ] `cargo clippy --features "backends,zk"` clean
- [ ] `cargo doc --features "backends,zk"` builds
- [ ] Statistical ZK tests still pass
- [ ] No performance regression in Transparent mode
