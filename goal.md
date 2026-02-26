# Goal: ZK Feature Branch Diff Reduction

## Hard Constraints
1. The diff of `src/` + `Cargo.toml` between `main` and `feat/zk` must have **< 500 added lines** (below 300 is the stretch goal)
2. Deletions are fine and encouraged — we want less code, not more
3. **All tests must pass**: `cargo nextest run -q` and `cargo nextest run -q --features zk`
4. Do not stop until all constraints are met

## Current State
- **852 added** + 283 removed (source only)
- Biggest contributors: `reduce_and_fold.rs` (+427), `evaluation_proof.rs` (+156)

## Strategy
1. **Do not touch existing comments/docs unnecessarily** — gratuitous doc edits create diff waste
2. **Store round blinds internally in DoryProverState** — eliminate return-value tuples and blind-array parameters between functions
3. **Consolidate `commit` and `commit_zk`** — single method with optional RNG
4. **Bundle ZK proof fields** into `Option<ZkExtension>` instead of 5 separate `Option` fields
5. **Keep Mode trait lean** — use it internally, minimize generic parameter spread
6. **Move sigma proof logic to `src/zk.rs`** — keep reduce_and_fold.rs focused on the core protocol
7. **Minimize API surface changes** — fewer generic parameters on public functions

## Verification
```sh
# Added lines only (must be < 500, stretch goal < 300):
git diff main...feat/zk -- src/ Cargo.toml | grep -c '^+[^+]'

# Tests pass:
cargo nextest run --features "arkworks"
cargo nextest run --features "arkworks,zk"

# Clippy clean:
cargo clippy --features "arkworks" --message-format=short
cargo clippy --features "arkworks,zk" --message-format=short
```

## Status: IN PROGRESS
