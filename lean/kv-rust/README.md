# Rust KV extraction spike

This opt-in package checks [a small Rust crate](../../src/rust/kv-spike) against the existing [KV model](../kv/Kv/Model/Transitions.lean).
It is not linked into CCF and does not change the existing Lean specification.
The spike has one store, two maps with one key each, empty and one-byte values, and no compaction, rollback, global reads, or replication.

[`slot_read`, `slot_publish`, and `two_map_schedule`](KvRust/Correspondence.lean) compare the extracted Rust functions to the model.
The schedule varies the values, but keeps the action order fixed.
It is not a refinement theorem for all transactions.

## Reproduce

Install `rustup`, `elan`, and the [Aeneas build dependencies](https://github.com/AeneasVerif/aeneas/tree/2e3d4488280bb8a95411db81019a7854a784861f#installation--build).
From the CCF root:

```sh
mkdir -p build-kv-aeneas
git clone https://github.com/AeneasVerif/aeneas.git build-kv-aeneas/aeneas
git -C build-kv-aeneas/aeneas checkout --detach 2e3d4488280bb8a95411db81019a7854a784861f
(
  cd build-kv-aeneas/aeneas
  opam exec -- make setup-charon
  opam exec -- make
)
cargo test --locked --manifest-path src/rust/kv-spike/Cargo.toml
bash lean/kv-rust/verify.sh build-kv-aeneas/aeneas
```

The script translates the Rust with the pinned Charon and Aeneas, then builds the Lean correspondence proof with warnings treated as errors.
It rejects extraction that needs handwritten models of opaque functions or types.
Generated Lean and intermediate LLBC are not checked in.
