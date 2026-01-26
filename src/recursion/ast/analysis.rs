use std::collections::HashMap;

use crate::primitives::arithmetic::{Group, PairingCurve};

use super::core::{AstGraph, ValueId, ValueType};

impl<E: PairingCurve> AstGraph<E>
where
    E::G1: Group,
{
    /// Build a reverse index: for each ValueId, who consumes it?
    ///
    /// Returns a map from `ValueId` -> `Vec<ValueId>` of consumers.
    /// This is useful for traversing the graph from outputs to inputs.
    pub fn consumers(&self) -> HashMap<ValueId, Vec<ValueId>> {
        let mut map: HashMap<ValueId, Vec<ValueId>> = HashMap::new();
        for node in &self.nodes {
            let consumer = node.out;
            for producer in node.op.input_ids() {
                map.entry(producer).or_default().push(consumer);
            }
        }
        map
    }

    /// Compute the depth level for each node in the graph.
    ///
    /// - Level 0: Input nodes (no dependencies)
    /// - Level N: Nodes whose maximum input level is N-1
    ///
    /// Nodes at the same level have no dependencies on each other and can be
    /// processed in parallel during witness generation or hint computation.
    ///
    /// # Returns
    /// A vector where `result[i]` is the level of node `ValueId(i)`.
    ///
    /// # Complexity
    /// O(V + E) where V is the number of nodes and E is the total input count.
    pub fn compute_levels(&self) -> Vec<usize> {
        let mut levels = vec![0usize; self.nodes.len()];

        for (idx, node) in self.nodes.iter().enumerate() {
            let max_input_level = node
                .op
                .input_ids()
                .iter()
                .map(|id| levels[id.0 as usize])
                .max()
                .unwrap_or(0);

            levels[idx] = if matches!(node.op, super::core::AstOp::Input { .. }) {
                0
            } else {
                max_input_level + 1
            };
        }

        levels
    }

    /// Group nodes by level for wavefront parallel processing.
    ///
    /// Returns a vector of vectors, where `result[level]` contains all `ValueId`s
    /// at that level. Nodes within the same level are independent and can be
    /// processed in parallel.
    ///
    /// # Example
    /// ```ignore
    /// let levels = graph.levels();
    /// for (level, node_ids) in levels.iter().enumerate() {
    ///     println!("Level {}: {} nodes", level, node_ids.len());
    ///     // Process node_ids in parallel with rayon
    /// }
    /// ```
    pub fn levels(&self) -> Vec<Vec<ValueId>> {
        let node_levels = self.compute_levels();
        let max_level = node_levels.iter().copied().max().unwrap_or(0);

        let mut levels: Vec<Vec<ValueId>> = vec![Vec::new(); max_level + 1];
        for (idx, &level) in node_levels.iter().enumerate() {
            levels[level].push(ValueId(idx as u32));
        }

        levels
    }

    /// Group nodes by level and value type for fine-grained parallelism.
    ///
    /// Returns a vector where each entry is a map from `ValueType` to nodes
    /// of that type at that level. This enables type-aware parallel processing
    /// where G1, G2, and GT operations can be batched separately.
    ///
    /// # Example
    /// ```ignore
    /// let levels_by_type = graph.levels_by_type();
    /// for (level, type_map) in levels_by_type.iter().enumerate() {
    ///     // Process G1 ops, G2 ops, GT ops independently
    ///     if let Some(g1_nodes) = type_map.get(&ValueType::G1) {
    ///         // Parallel process all G1 nodes at this level
    ///     }
    /// }
    /// ```
    pub fn levels_by_type(&self) -> Vec<HashMap<ValueType, Vec<ValueId>>> {
        let node_levels = self.compute_levels();
        let max_level = node_levels.iter().copied().max().unwrap_or(0);

        let mut levels: Vec<HashMap<ValueType, Vec<ValueId>>> = vec![HashMap::new(); max_level + 1];

        for (idx, node) in self.nodes.iter().enumerate() {
            let level = node_levels[idx];
            levels[level]
                .entry(node.out_ty)
                .or_default()
                .push(ValueId(idx as u32));
        }

        levels
    }

    /// Returns statistics about parallelism opportunities at each level.
    ///
    /// Useful for understanding the graph structure and potential speedup
    /// from parallel processing.
    ///
    /// # Returns
    /// A vector of `(total_nodes, g1_count, g2_count, gt_count)` for each level.
    pub fn level_stats(&self) -> Vec<(usize, usize, usize, usize)> {
        let levels_by_type = self.levels_by_type();
        levels_by_type
            .iter()
            .map(|type_map| {
                let g1 = type_map.get(&ValueType::G1).map_or(0, |v| v.len());
                let g2 = type_map.get(&ValueType::G2).map_or(0, |v| v.len());
                let gt = type_map.get(&ValueType::GT).map_or(0, |v| v.len());
                (g1 + g2 + gt, g1, g2, gt)
            })
            .collect()
    }
}
