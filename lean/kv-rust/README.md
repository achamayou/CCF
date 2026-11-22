# Rust KV verification prototype

This opt-in package checks [a Rust prototype](../../src/rust/kv-spike) against the existing [KV model](../kv/Kv/Model/Transitions.lean).
It is not linked into CCF and does not change the existing Lean specification.

The [dynamic engine](../../src/rust/kv-spike/src/engine.rs) implements the single-store action surface with byte strings, ordered association lists, and owned, contiguous version frames.
Callers explicitly capture a snapshot before acquiring the first map, and explicitly supply the result of replication after local application.
Compaction advances the global frontier and changes which map views can be acquired; it does not yet reclaim old frames.
The prototype has no C++ adapter, multiple-store lifecycle, or persistence integration.

The [original two-map proofs](KvRust/Correspondence.lean) still exercise the scheduling and publication slice.
The [association-list proofs](KvRust/Assoc.lean) connect extracted lookup, replacement and erasure to the model's operations, given correct equality and cloning.
The [key proofs](KvRust/Keys.lean) establish the byte comparator's lexicographic order and the address equality used by the engine.
The [publication proof](KvRust/Publication.lean) discharges equality and cloning for the actual publication types and checks the full write-set fold against `Kv.Model.publish` instantiated over byte lists.
The [frame advancement proof](KvRust/Advance.lean) checks that the extracted publication produces the model's entire next frame, including the birth and revision metadata used for rollback lineage.
The [validation proofs](KvRust/Validation.lean) compare the extracted OCC read-set check to the model for both point and whole-map dependencies.
The [lineage proofs](KvRust/Lineage.lean) compose the read-set check with captured terms, map birth and revision stamps, and acquisition failures to match the model's commit eligibility test on related states.
The [local application proofs](KvRust/Apply.lean) check that rejection preserves the Rust state and that an eligible, representable application returns the model's write set and advances the history and the committing attempt.
The [dynamic history proofs](KvRust/History.lean) cover frame lookup at a cut, compaction, rollback guards and retention of the model's prefix under the indexed-history invariant.
The [acquisition proofs](KvRust/Acquire.lean) cover the `Acquire` action, including independent local and global views, rejection without mutation, and updates to the model's pinned read image.
The [point-operation proofs](KvRust/Point.lean) cover enabled `Get`, `Has`, `Previous`, and `Write` actions, including the returned observations, write overlay, and read dependencies.
The rest of the dynamic engine is extracted and exercised by native tests, but does not yet have a step-by-step simulation proof.

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

The script translates the Rust with the pinned Charon and Aeneas, builds the Lean proofs with warnings treated as errors, and rechecks the resulting modules in the Lean kernel.
It rejects extraction that needs handwritten models of opaque functions or types.
Generated Lean and intermediate LLBC are not checked in.
