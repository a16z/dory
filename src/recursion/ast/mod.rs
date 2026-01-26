//! AST/DAG representation of verification computations for recursive proof composition.
//!
//! This module provides an explicit graph representation of group/pairing operations
//! performed during Dory verification. The AST enables:
//!
//! - **Wiring constraints**: track that "output of op A is input of op B"
//! - **Circuit generation**: upstream crates can consume the AST to generate constraints
//! - **Debugging**: operation names and scalar labels aid in understanding the computation
//!
//! # Design
//!
//! - **Group elements** (`G1`, `G2`, `GT`) are tracked as `ValueId`s with explicit wiring.
//! - **Scalars** are embedded directly in operations (not tracked as `ValueId`s).
//! - The AST is a strict superset of the existing `OpId`-based witness/hint system.
//!
//! # Example
//!
//! ```ignore
//! use dory_pcs::recursion::ast::{AstBuilder, ValueType, InputSource, AstOp, ScalarValue};
//!
//! let mut builder = AstBuilder::<E>::new();
//!
//! // Intern setup elements
//! let g1_0 = builder.intern_input(ValueType::G1, InputSource::Setup { name: "g1_0", index: None });
//! let chi_0 = builder.intern_input(ValueType::GT, InputSource::Setup { name: "chi", index: Some(0) });
//!
//! // Record a scalar multiplication
//! let scaled = builder.push(ValueType::G1, AstOp::G1ScalarMul {
//!     op_id: Some(op_id),
//!     point: g1_0,
//!     scalar: ScalarValue::named(beta, "beta"),
//! });
//!
//! let graph = builder.finalize();
//! graph.validate().expect("valid DAG");
//! ```

mod analysis;
mod core;
mod wiring;

pub use core::*;
pub use wiring::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backends::arkworks::BN254;
    use crate::primitives::arithmetic::{Field, Group, PairingCurve};
    use crate::recursion::witness::{OpId, OpType};

    // Type alias for convenience - use the public re-export
    type Fr = <BN254 as PairingCurve>::G1;
    type Scalar = <Fr as Group>::Scalar;

    #[test]
    fn test_empty_graph_is_valid() {
        let graph: AstGraph<BN254> = AstGraph::default();
        assert!(graph.validate().is_ok());
        assert!(graph.is_empty());
    }

    #[test]
    fn test_single_input_node() {
        let mut builder = AstBuilder::<BN254>::new();
        let g1 = builder.intern_input(
            ValueType::G1,
            InputSource::Setup {
                name: "g1_0",
                index: None,
            },
        );
        assert_eq!(g1, ValueId(0));

        let graph = builder.finalize();
        assert!(graph.validate().is_ok());
        assert_eq!(graph.len(), 1);
    }

    #[test]
    fn test_intern_deduplicates() {
        let mut builder = AstBuilder::<BN254>::new();
        let source = InputSource::Setup {
            name: "g1_0",
            index: None,
        };

        let id1 = builder.intern_input(ValueType::G1, source.clone());
        let id2 = builder.intern_input(ValueType::G1, source);

        assert_eq!(id1, id2);
        assert_eq!(builder.len(), 1);
    }

    #[test]
    fn test_simple_add_chain() {
        let mut builder = AstBuilder::<BN254>::new();

        let a = builder.intern_input(
            ValueType::G1,
            InputSource::Setup {
                name: "g1_0",
                index: None,
            },
        );
        let b = builder.intern_input(
            ValueType::G1,
            InputSource::Setup {
                name: "g1_1",
                index: Some(1),
            },
        );
        let c = builder.push(ValueType::G1, AstOp::G1Add { op_id: None, a, b });

        assert_eq!(c, ValueId(2));

        let graph = builder.finalize();
        assert!(graph.validate().is_ok());
        assert_eq!(graph.len(), 3);
    }

    #[test]
    fn test_input_ids_matches_input_slots_projection() {
        let mut builder = AstBuilder::<BN254>::new();

        // Inputs
        let g1_0 = builder.intern_input(
            ValueType::G1,
            InputSource::Setup {
                name: "g1_0",
                index: None,
            },
        );
        let g1_1 = builder.intern_input(
            ValueType::G1,
            InputSource::Setup {
                name: "g1_1",
                index: Some(1),
            },
        );
        let g2_0 = builder.intern_input(
            ValueType::G2,
            InputSource::Setup {
                name: "g2_0",
                index: None,
            },
        );
        let g2_1 = builder.intern_input(
            ValueType::G2,
            InputSource::Setup {
                name: "g2_1",
                index: Some(1),
            },
        );
        let gt_0 = builder.intern_input(
            ValueType::GT,
            InputSource::Setup {
                name: "chi",
                index: Some(0),
            },
        );
        let gt_1 = builder.intern_input(
            ValueType::GT,
            InputSource::Setup {
                name: "chi",
                index: Some(1),
            },
        );

        // Exercise every AstOp variant that has ValueId inputs.
        let _ = builder.push(
            ValueType::G1,
            AstOp::G1Add {
                op_id: None,
                a: g1_0,
                b: g1_1,
            },
        );
        let _ = builder.push(
            ValueType::G2,
            AstOp::G2Add {
                op_id: None,
                a: g2_0,
                b: g2_1,
            },
        );

        let s0: Scalar = Scalar::from_u64(3);
        let s1: Scalar = Scalar::from_u64(5);

        let _ = builder.push(
            ValueType::G1,
            AstOp::G1ScalarMul {
                op_id: None,
                point: g1_0,
                scalar: ScalarValue::new(s0),
            },
        );
        let _ = builder.push(
            ValueType::G2,
            AstOp::G2ScalarMul {
                op_id: None,
                point: g2_0,
                scalar: ScalarValue::new(s1),
            },
        );

        let _ = builder.push(
            ValueType::GT,
            AstOp::GTMul {
                op_id: None,
                lhs: gt_0,
                rhs: gt_1,
            },
        );
        let _ = builder.push(
            ValueType::GT,
            AstOp::GTExp {
                op_id: None,
                base: gt_0,
                scalar: ScalarValue::new(s0),
            },
        );

        let _ = builder.push(
            ValueType::GT,
            AstOp::Pairing {
                op_id: None,
                g1: g1_0,
                g2: g2_0,
            },
        );
        let _ = builder.push(
            ValueType::GT,
            AstOp::MultiPairing {
                op_id: None,
                g1s: vec![g1_0, g1_1],
                g2s: vec![g2_0, g2_1],
            },
        );

        let _ = builder.push(
            ValueType::G1,
            AstOp::MsmG1 {
                op_id: None,
                points: vec![g1_0, g1_1],
                scalars: vec![ScalarValue::new(s0), ScalarValue::new(s1)],
            },
        );
        let _ = builder.push(
            ValueType::G2,
            AstOp::MsmG2 {
                op_id: None,
                points: vec![g2_0, g2_1],
                scalars: vec![ScalarValue::new(s0), ScalarValue::new(s1)],
            },
        );

        let graph = builder.finalize();
        graph.validate().unwrap();

        for node in &graph.nodes {
            let from_slots: Vec<ValueId> = node
                .op
                .input_slots()
                .into_iter()
                .map(|(id, _)| id)
                .collect();
            assert_eq!(
                from_slots,
                node.op.input_ids(),
                "input_ids != projected input_slots for op {}",
                node.op.op_name()
            );
        }
    }

    #[test]
    fn test_scalar_mul_with_opid() {
        let mut builder = AstBuilder::<BN254>::new();

        let point = builder.intern_input(
            ValueType::G1,
            InputSource::Setup {
                name: "g1_0",
                index: None,
            },
        );

        let op_id = OpId::new(1, OpType::G1ScalarMul, 0);
        let scalar_value: Scalar = Scalar::from_u64(42);
        let scaled = builder.push_with_opid(
            ValueType::G1,
            AstOp::G1ScalarMul {
                op_id: Some(op_id),
                point,
                scalar: ScalarValue::named(scalar_value, "beta"),
            },
            op_id,
        );

        let graph = builder.finalize();
        assert!(graph.validate().is_ok());
        assert_eq!(graph.opid_to_value.get(&op_id), Some(&scaled));
    }

    #[test]
    fn test_pairing_type_check() {
        let mut builder = AstBuilder::<BN254>::new();

        let g1 = builder.intern_input(
            ValueType::G1,
            InputSource::Setup {
                name: "g1_0",
                index: None,
            },
        );
        let g2 = builder.intern_input(
            ValueType::G2,
            InputSource::Setup {
                name: "g2_0",
                index: None,
            },
        );
        let _gt = builder.push(
            ValueType::GT,
            AstOp::Pairing {
                op_id: None,
                g1,
                g2,
            },
        );

        let graph = builder.finalize();
        assert!(graph.validate().is_ok());
    }

    #[test]
    fn test_type_mismatch_detected() {
        let mut builder = AstBuilder::<BN254>::new();

        let g1 = builder.intern_input(
            ValueType::G1,
            InputSource::Setup {
                name: "g1_0",
                index: None,
            },
        );
        // Try to add G1 + G1 but claim it's a G2Add (wrong types)
        let _bad = builder.push(
            ValueType::G2,
            AstOp::G2Add {
                op_id: None,
                a: g1,
                b: g1,
            },
        );

        let graph = builder.finalize();
        let result = graph.validate();
        assert!(matches!(
            result,
            Err(AstValidationError::TypeMismatch { .. })
        ));
    }

    #[test]
    fn test_undefined_input_detected() {
        let mut builder = AstBuilder::<BN254>::new();

        // Reference a ValueId that doesn't exist
        let _bad = builder.push(
            ValueType::G1,
            AstOp::G1Add {
                op_id: None,
                a: ValueId(99),
                b: ValueId(100),
            },
        );

        let graph = builder.finalize();
        let result = graph.validate();
        assert!(matches!(
            result,
            Err(AstValidationError::UndefinedInput { .. })
        ));
    }

    #[test]
    fn test_multi_pairing_length_mismatch() {
        let mut builder = AstBuilder::<BN254>::new();

        let g1 = builder.intern_input(
            ValueType::G1,
            InputSource::Setup {
                name: "g1_0",
                index: None,
            },
        );
        let g2 = builder.intern_input(
            ValueType::G2,
            InputSource::Setup {
                name: "g2_0",
                index: None,
            },
        );

        let _bad = builder.push(
            ValueType::GT,
            AstOp::MultiPairing {
                op_id: None,
                g1s: vec![g1, g1], // 2 elements
                g2s: vec![g2],     // 1 element
            },
        );

        let graph = builder.finalize();
        let result = graph.validate();
        assert!(matches!(
            result,
            Err(AstValidationError::MultiPairingLengthMismatch { .. })
        ));
    }

    #[test]
    fn test_constraint_validation() {
        let mut builder = AstBuilder::<BN254>::new();

        let a = builder.intern_input(
            ValueType::GT,
            InputSource::Setup {
                name: "chi",
                index: Some(0),
            },
        );

        // Add a constraint referencing undefined value
        builder.push_eq(a, ValueId(999), "bad constraint");

        let graph = builder.finalize();
        let result = graph.validate();
        assert!(matches!(
            result,
            Err(AstValidationError::ConstraintUndefinedValue { .. })
        ));

        // Valid constraint should pass
        let mut builder = AstBuilder::<BN254>::new();
        let a = builder.intern_input(
            ValueType::GT,
            InputSource::Setup {
                name: "chi",
                index: Some(0),
            },
        );
        let b = builder.intern_input(
            ValueType::GT,
            InputSource::Setup {
                name: "chi",
                index: Some(1),
            },
        );
        builder.push_eq(a, b, "valid constraint");
        let graph = builder.finalize();
        assert!(graph.validate().is_ok());
    }

    #[test]
    fn test_complex_graph() {
        let mut builder = AstBuilder::<BN254>::new();

        // Inputs
        let e1 = builder.intern_input(ValueType::G1, InputSource::Proof { name: "vmv.e1" });
        let e2 = builder.intern_input(ValueType::G2, InputSource::Proof { name: "vmv.e2" });
        let h1 = builder.intern_input(
            ValueType::G1,
            InputSource::Setup {
                name: "h1",
                index: None,
            },
        );
        let h2 = builder.intern_input(
            ValueType::G2,
            InputSource::Setup {
                name: "h2",
                index: None,
            },
        );
        let chi_0 = builder.intern_input(
            ValueType::GT,
            InputSource::Setup {
                name: "chi",
                index: Some(0),
            },
        );

        // Some operations
        let d_scalar: Scalar = Scalar::from_u64(5);
        let g1_scaled = builder.push(
            ValueType::G1,
            AstOp::G1ScalarMul {
                op_id: None,
                point: h1,
                scalar: ScalarValue::named(d_scalar, "d"),
            },
        );
        let e1_mod = builder.push(
            ValueType::G1,
            AstOp::G1Add {
                op_id: None,
                a: e1,
                b: g1_scaled,
            },
        );

        let pair1 = builder.push(
            ValueType::GT,
            AstOp::Pairing {
                op_id: None,
                g1: e1_mod,
                g2: e2,
            },
        );
        let pair2 = builder.push(
            ValueType::GT,
            AstOp::Pairing {
                op_id: None,
                g1: h1,
                g2: h2,
            },
        );

        let lhs = builder.push(
            ValueType::GT,
            AstOp::GTMul {
                op_id: None,
                lhs: pair1,
                rhs: pair2,
            },
        );

        let gamma_scalar: Scalar = Scalar::from_u64(2);
        let rhs = builder.push(
            ValueType::GT,
            AstOp::GTExp {
                op_id: None,
                base: chi_0,
                scalar: ScalarValue::named(gamma_scalar, "gamma"),
            },
        );

        builder.push_eq(lhs, rhs, "final pairing check");

        let graph = builder.finalize();
        assert!(graph.validate().is_ok());
        assert_eq!(graph.constraints.len(), 1);
        assert!(!graph.is_empty());
    }

    #[test]
    fn test_wiring_pairs() {
        let mut builder = AstBuilder::<BN254>::new();

        // Create a simple graph: g1 -> scale -> add
        let g1_a = builder.intern_input(
            ValueType::G1,
            InputSource::Setup {
                name: "g1_a",
                index: None,
            },
        );
        let g1_b = builder.intern_input(
            ValueType::G1,
            InputSource::Setup {
                name: "g1_b",
                index: None,
            },
        );

        let scalar: Scalar = Scalar::from_u64(5);
        let scaled = builder.push(
            ValueType::G1,
            AstOp::G1ScalarMul {
                op_id: None,
                point: g1_a,
                scalar: ScalarValue::new(scalar),
            },
        );

        let _sum = builder.push(
            ValueType::G1,
            AstOp::G1Add {
                op_id: None,
                a: scaled,
                b: g1_b,
            },
        );

        let graph = builder.finalize();
        let pairs = graph.wiring_pairs();

        // Expected wiring:
        // - g1_a (0) -> scaled (2)
        // - scaled (2) -> sum (3)
        // - g1_b (1) -> sum (3)
        assert_eq!(pairs.len(), 3);
        assert!(pairs.contains(&(ValueId(0), ValueId(2)))); // g1_a -> scaled
        assert!(pairs.contains(&(ValueId(2), ValueId(3)))); // scaled -> sum
        assert!(pairs.contains(&(ValueId(1), ValueId(3)))); // g1_b -> sum

        // Test consumers map
        let consumers = graph.consumers();
        assert_eq!(consumers.get(&ValueId(0)), Some(&vec![ValueId(2)])); // g1_a consumed by scaled
        assert_eq!(consumers.get(&ValueId(1)), Some(&vec![ValueId(3)])); // g1_b consumed by sum
        assert_eq!(consumers.get(&ValueId(2)), Some(&vec![ValueId(3)])); // scaled consumed by sum
        assert_eq!(consumers.get(&ValueId(3)), None); // sum not consumed by anyone
    }
}
