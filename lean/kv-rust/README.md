# Rust KV verification

This opt-in package verifies [the Rust KV crate](../../src/rust/ccf-kv) against the existing [KV model](../kv/Kv/Model/Transitions.lean).
It is not linked into production CCF and does not change the existing Lean specification.

The [dynamic engine](../../src/rust/ccf-kv/src/engine.rs) implements the single-store action surface with byte strings, associative transaction state, a ring-buffered active branch of version frames backed by a reference-counted radix arena, and a metadata-only retained list for compacted frames still needed by live transactions.
Each frame holds a single persistent radix root ordered by packed `(map_len, map, key)` bytes, supporting prefix-scoped map scans without maintaining a second chronology index.
Callers explicitly capture a snapshot before acquiring the first map, and explicitly supply the result of replication after local application.
Compaction advances the global frontier, changes which map views can be acquired, pops compacted frames off the front of the active ring, releases their radix roots through a bounded retirement FIFO, keeps only metadata-only entries in `retained` when a live transaction snapshot or acquired view lineage still needs them, and shrinks the ring when sparse.
Rollback similarly pops discarded frames off the back of the active ring, releases their radix roots, shrinks the ring when sparse, and leaves `retained` intact.
Ending a transaction releases its pinned view roots, prunes any `retained` entries no remaining transaction needs, and drains the retirement budget.
The opt-in C++ test adapter supports ordinary ledger writes, replay, and snapshots; the production store lifecycle is not implemented.

The [association-list proofs](KvRust/Assoc.lean) connect extracted lookup, replacement and erasure to the model's operations, given correct equality and cloning.
The [key proofs](KvRust/Keys.lean) establish the byte comparator's lexicographic order and the address equality used by the engine.
The [address encoding proofs](KvRust/RadixAddress.lean) cover the packed `(map_len, map, key)` byte encoding and map prefixes.
The [radix core](KvRust/Radix.lean), [sorted batch builder](KvRust/RadixBatch.lean), [liveness](KvRust/RadixLiveness.lean), [retirement FIFO](KvRust/RetireQueue.lean), and [single-radix reclamation proofs](KvRust/RadixSingleReclaim.lean) establish exact reference-count accounting, bounded FIFO retirement, and lockstep view preservation across `put`, `remove`, sorted batch publication, root retention/release, and slot recycling.
The [address index](KvRust/KvIndex.lean) and [indexed publication proofs](KvRust/IndexedPublication.lean) check the extracted write-set fold and [sorted batch selection](KvRust/SortedPublication.lean) against `Kv.Model.publish`, releasing intermediate roots and preserving live pins under numeric bounds on packed keys, path copies, row slots, reference counts, and the retirement queue.
The [branch log](KvRust/BranchLog.lean) and [archive relation](KvRust/IndexedHistory.lean) verify the ring-buffered active branch (`slots`, `head`, `len`, grow and sparse shrink) and tie active ring frames and metadata-only `retained` entries to a ghost newest-first native history and immutable archive across compaction, rollback, and pruning.
[`StoreMetaLive`](KvRust/Relation.lean) maintains that every live transaction snapshot compacted below the active ring base is present in `retained` and every acquired map view whose stamps match any ghost active frame still matches some frame in `activeFrames ++ retained`, preserved across compaction, pruning on `End`, and rollback via branch stamp monotonicity (`RevisionFlow.stamps_between`).
The [retained-cut proof](KvRust/RetainedCuts.lean) shows that an older acquisition which remains available can read the compacted map image, or the empty placeholder, without changing its observation.
It preserves the revision invariant across the modeled apply, compact, and rollback steps.
On ordinary histories, an available acquisition below the global cut pins the compacted image without changing its local revision or observations, while compaction clears and releases superseded frame roots below the cut.
Imported and recovered histories keep the original two-cut path.
Existing handles keep their retained radix roots until `End` releases them and drains the retirement budget.
The indexed [materialization](KvRust/IndexedImage.lean) and [pin](KvRust/PinnedImage.lean) proofs relate selected maps and point reads to those views without reconstructing the whole store.
The [frame advancement proof](KvRust/Advance.lean) checks that the extracted publication produces the model's entire next frame, including the birth and revision metadata used for rollback lineage.
The [validation proofs](KvRust/Validation.lean) compare the extracted OCC read-set check to the model for both point and whole-map dependencies, including root-matched and link-by-link whole-map comparisons without cloning map images.
The [lineage proofs](KvRust/Lineage.lean) compose the read-set check with captured terms, map birth and revision stamps, and acquisition failures to match the model's commit eligibility test on related states.
The [local application proofs](KvRust/Apply.lean) check that rejection preserves the Rust state and that an eligible, representable application returns the model's write set and advances the history and the committing attempt.
The [dynamic history proofs](KvRust/History.lean) cover frame lookup at a cut, compaction, rollback guards and retention of the model's prefix under the indexed-history invariant.
The [acquisition proofs](KvRust/Acquire.lean) cover the `Acquire` action, including independent local and global views, rejection without mutation, and updates to the model's pinned read image.
The [point-operation proofs](KvRust/Point.lean) cover enabled `Get`, `Has`, `Previous`, and `Write` actions, including the returned observations, write overlay, and read dependencies.
The [map-operation proofs](KvRust/Scan.lean) cover scans, sizes, clears, and half-open ranges sorted in byte order, including direct pinned-root `Size` and filtered `Range` paths when no writes are staged.
The [lifecycle proofs](KvRust/Lifecycle.lean) cover store initialization, attempt creation and removal, term and snapshot capture, and commit initiation and completion.

[`initialized_run_matches`](KvRust/Simulation.lean) composes these results from the actual model's empty state: every in-bounds finite trace over the native single-store action surface produces matching observations and ends in related states.
Point reads, sizes, byte-sorted half-open ranges, commit decisions, rollbacks, and rejections match the model identically, while whole-map scans and applied write reports match up to list permutation.
A disabled model action maps to an unchanged native store with `Error::Disabled`; rollback below the compacted frontier is a separate observable result in both implementations.
The proof uses an injective, order-preserving encoding of native byte strings into the model's string type.
`FitsTrace` states the capacity requirements for the counters, vectors, packed addresses, radix growth, and scan work that the original, unbounded model does not have.
The proof does not cover allocation failure, a C++ adapter, or distributed execution.

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
cargo test --locked --manifest-path src/rust/ccf-kv/Cargo.toml
bash lean/kv-rust/verify.sh build-kv-aeneas/aeneas
```

The script translates the Rust with the pinned Charon and Aeneas, builds the Lean proofs with warnings treated as errors, and rechecks the resulting modules in the Lean kernel.
It rejects extraction that needs handwritten models of opaque functions or types.
Generated Lean and intermediate LLBC are not checked in.

## Run C++ unit tests against Rust

In a configured CCF development environment, enable the opt-in backend and build the test target:

```sh
cmake -S . -B build -GNinja -DBUILD_RUST_KV_TESTS=ON
cmake --build build --target kv_test kv_rust_test kv_rust_interop_test
ctest --test-dir build -R '^(kv_test|kv_rust_test|kv_rust_interop_test)$' \
  --output-on-failure --no-tests=error
```

`kv_rust_test` compiles the same contract cases as `kv_test` with Rust-backed stores and no link to the C++ KV implementation.
The shared cases cover typed and untyped map handles, OCC, range and iteration semantics, rollback, compaction, commit hooks, contention, ordinary ledger entries, and snapshots.
Rust distinguishes pre-application conflicts and stale-term writes from a replication failure after local publication.
The adapter serializes access to the Rust store and gives CCF's codecs and consensus stubs the actual Rust write set.
`kv_rust_interop_test` explicitly uses a Rust store and a C++ store to replay ordinary entries and restore snapshots in both directions.
The default `kv_test` still uses C++ and runs its full suite, including cases not enabled for Rust.

The targets share 100 contract cases, including reserved writes, signature replay, in-place snapshot restore, private map recovery, and the concurrent operation fuzzer.
The shared cases include rejection of malformed ledger entries without advancing the store and rejection of an ahead-of-target recovery source without changing either store.
The remaining C++-only cases are `Map name parsing`, nine low-level reader/writer and entry-envelope cases in `kv_serialisation.cpp` and `raw_writer.cpp`, five snapshot codec cases in `kv_snapshot.cpp`, and the rest of `Store error handling`, which includes checks of the concrete C++ `AbstractMap` API and store readiness.
Rust also tests the snapshot, rollback, and term guards through its own interface.
The shared snapshot restore tests cover historical encryption secrets and captured-public-map reuse.
The same fuzzer schedules and assertions run on both backends, but the C++ trace reporter and trace-conformance runner are not wired to the Rust adapter.

The test adapter inherits from `ccf::kv::AbstractStore`, implementing store locking, snapshot capture/serialization, replay, compaction, rollback, and flag hooks while rejecting C++-only `AbstractMap` handle methods.
It serializes commit submission and only fills reserved slots in order, and does not yet wire the Rust backend into the production CCF node lifecycle or replication loop.
The trace theorem applies to the single-store `Action` dispatcher, not the C ABI, CCF commit classification and post-commit reads, the ledger codec, the locking wrapper, or imported snapshot state.
Both the action dispatcher and the CCF adapter now stage writes in descending key order with binary search and in-place replacement; the separate recency-order path has been removed.
The [extracted staging proof](KvRust/PendingWrites.lean) checks that binary search and in-place replacement preserve exactly the same final writes, including deletions, up to permutation.
The [order-equivalence lemmas](KvRust/OrderEquivalence.lean) bridge key-ordered staging to the unchanged model through archive-wide revision consistency.
[`initialized_run_matches`](KvRust/Simulation.lean) composes these results end-to-end: exact point observations, sizes, byte-sorted half-open ranges, OCC validation decisions, and lifecycles match identically, while whole-map scans and applied write reports match up to permutation.
The extracted ordinary ledger replay proof shows that, after decoding, a successful next-version replay advances the model with exactly the supplied writes, and a rejected replay does not mutate the store.
Provisional replacement replay and snapshot import are tested, but not covered by that theorem.

## Benchmarks

The standalone Rust benchmark exercises the public Rust action dispatcher with nine timed samples after warmup, a fresh store per sample, eight-byte keys, and 64-byte values:

```sh
taskset -c 2 cargo bench --locked --offline \
  --manifest-path src/rust/ccf-kv/Cargo.toml --bench engine
```

The opt-in `kv_backend_bench` executable runs both backends through the same C++ transaction and map-handle workload with a null encryptor and no consensus:

```sh
cmake --build build --target kv_backend_bench
taskset -c 2 build/kv_backend_bench cpp
taskset -c 2 build/kv_backend_bench rust
```

For tail latency and peak process RSS under compaction and pinned-reader churn, run each backend in its own process:

```sh
/usr/bin/time -v taskset -c 2 build/kv_backend_bench cpp pinned-churn 65536
/usr/bin/time -v taskset -c 2 build/kv_backend_bench rust pinned-churn 65536
```
