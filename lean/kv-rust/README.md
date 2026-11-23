# Rust KV verification prototype

This opt-in package checks [a Rust prototype](../../src/rust/kv-spike) against the existing [KV model](../kv/Kv/Model/Transitions.lean).
It is not linked into production CCF and does not change the existing Lean specification.

The [dynamic engine](../../src/rust/kv-spike/src/engine.rs) implements the single-store action surface with byte strings, ordered association lists, and owned, contiguous version frames.
Callers explicitly capture a snapshot before acquiring the first map, and explicitly supply the result of replication after local application.
Compaction advances the global frontier and changes which map views can be acquired; it does not yet reclaim old frames.
The opt-in C++ test adapter supports ordinary ledger writes, replay, and snapshots; the production store lifecycle is not implemented.

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
The [map-operation proofs](KvRust/Scan.lean) cover scans, sizes, clears, and half-open ranges sorted in byte order.
The [lifecycle proofs](KvRust/Lifecycle.lean) cover store initialization, attempt creation and removal, term and snapshot capture, and commit initiation and completion.

[`initialized_run_matches`](KvRust/Simulation.lean) composes these results from the actual model's empty state: every in-bounds finite trace over the native single-store action surface produces the same observations and ends in related states.
A disabled model action maps to an unchanged native store with `Error::Disabled`; rollback below the compacted frontier is a separate observable result in both implementations.
The proof uses an injective, order-preserving encoding of native byte strings into the model's string type.
`FitsTrace` states the capacity requirements for the counters and vectors that the original, unbounded model does not have.
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
cargo test --locked --manifest-path src/rust/kv-spike/Cargo.toml
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

The Rust target runs 98 of the original 114 `kv_test` cases, including reserved writes, signature replay, in-place snapshot restore, private map recovery, and the concurrent operation fuzzer.
The C++-only cases are `Map name parsing`, nine low-level reader/writer and entry-envelope cases in `kv_serialisation.cpp` and `raw_writer.cpp`, five snapshot codec cases in `kv_snapshot.cpp`, and `Store error handling`, which includes tests of the concrete C++ `AbstractMap` API and store readiness.
Rust tests the snapshot, rollback, and term guards through its own interface; the C++ suite retains every original assertion.
The shared snapshot restore tests cover historical encryption secrets and captured-public-map reuse.
The same fuzzer schedules and assertions run on both backends, but the C++ trace reporter and trace-conformance runner are not wired to the Rust adapter.

The test adapter serializes commit submission and only fills reserved slots in order.
It does not implement the full CCF store interface or production replication.
The existing trace theorem applies to the single-store `Action` dispatcher, not the C ABI, CCF commit classification and post-commit reads, the ledger codec, the locking wrapper, or imported snapshot state.
The extracted ordinary ledger replay proof shows that, after decoding, a successful replay advances the model with exactly the supplied writes, and a rejected replay does not mutate the store.

## Performance

The standalone benchmark exercises the public Rust action dispatcher.
It reports the median, minimum, and maximum of nine timed samples after a warmup, with a fresh store per sample and setup outside the timer.
Each key is eight bytes and each value is 64 bytes.

```sh
taskset -c 2 cargo +1.90.0 bench --locked --offline \
  --manifest-path src/rust/kv-spike/Cargo.toml --bench engine
```

The table compares the baseline at `6e828f794` with the fresh-key insertion fast path.
The ranges are the two run medians on the same logical CPU, with the baseline and optimized binaries run in both orders on an Intel Core i7-1265U Linux x86-64 host.

| Workload                 | Baseline        | Fast path       |
| ------------------------ | --------------- | --------------- |
| Stage 512 distinct keys  | 30.4-45.7 us/op | 2.6-3.1 us/op   |
| Stage 2048 distinct keys | 112-215 us/op   | 10.6-13.0 us/op |
| Apply 512 writes         | 17.6-19.9 ms/tx | 1.67-1.68 ms/tx |
| Apply 2048 writes        | 238-278 ms/tx   | 23.4-23.6 ms/tx |

The change prepends a fresh binding in place instead of cloning the existing bindings, while retaining the original replacement path for existing keys.
Replacement and point-read measurements varied across runs and do not establish a speedup for those workloads.
These measurements compare two versions of the Rust prototype.

### Comparison with C++

The table compares the optimized Rust engine at `aefa09111` with the C++ KV engine from the same checkout.
Both used release builds (Rust 1.90.0 and Clang 21.1.8 with CCF's default snmalloc), the same pinned logical CPU on the host above, a single map, eight-byte big-endian keys, and 64-byte values.
Each value is a range of two run medians, with nine samples after warmup per run and setup and map acquisition outside the timer.
The runs were ordered C++, Rust, Rust, C++.

| Workload                  | C++               | Rust             |
| ------------------------- | ----------------- | ---------------- |
| Stage 64 distinct keys    | 1.43-1.60 us/op   | 0.39-0.56 us/op  |
| Stage 512 distinct keys   | 1.57-2.55 us/op   | 2.37-2.63 us/op  |
| Stage 2048 distinct keys  | 1.56-2.26 us/op   | 9.41-9.63 us/op  |
| Replace 64 staged keys    | 1.43-1.55 us/op   | 7.03-14.65 us/op |
| Replace 512 staged keys   | 1.57-1.58 us/op   | 50.3-51.9 us/op  |
| Replace 2048 staged keys  | 1.52-1.87 us/op   | 212-287 us/op    |
| Locally apply 64 writes   | 10.1-11.8 us/tx   | 34.4-34.9 us/tx  |
| Locally apply 512 writes  | 0.125-0.150 ms/tx | 1.50-1.54 ms/tx  |
| Locally apply 2048 writes | 0.813-1.04 ms/tx  | 23.7-30.0 ms/tx  |
| Point read, 512-key map   | 0.602-0.669 us/op | 28.5-34.9 us/op  |

The C++ comparison harness times staging and reads through an acquired map handle; Rust goes through the public action dispatcher, which currently clones the pinned view per operation.
The C++ local-apply path calls `apply_changes` with normal lock and version setup but without serialization or replication; Rust returns the full applied write set.
These are microbenchmarks of the two current implementations and interfaces, not a measurement of replicated CCF throughput.

### Matched CCF transaction interface

The opt-in `kv_backend_bench` executable runs both backends through the same C++ transaction and map-handle workload with the same null encryptor and no consensus.
Write commits include entry serialization.
The logging mix performs seven reads per write, compacts after each write, and holds an older read snapshot.
The governance mix performs a range read and updates two maps in each transaction.

```sh
cmake --build build --target kv_backend_bench
taskset -c 2 build/kv_backend_bench cpp
taskset -c 2 build/kv_backend_bench rust
```

On the host above, replacing the per-operation copy of the pinned view with a borrow reduced point reads in a 2,048-key map from 47.0-47.2 us to 3.72-4.17 us per read.
C++ took 0.61-1.01 us per read across the matched runs.
The logging mix improved from 75.4-90.3 us to 49.0-51.2 us per transaction, compared with 1.04-1.54 us in C++.
These are ranges of two run medians, not confidence intervals.
The next change replaces a single existing binding in place while retaining the original path for deduplicating repeated bindings.
Together the copy-removal changes cut a commit replacing 2,048 entries from 301-303 ms to 58.7-59.1 ms, versus 0.79-0.89 ms for C++ in the final pair of runs.
Comparing the key bytes before the map name reduced Rust bulk commits to 35-41 ms in a separate pair of runs.
The indexed batch path avoids applying the writes one at a time or cloning the input frame.
The extracted proof checks the ordered result against the original model fold, including puts, removals, and the fallback for repeated addresses or crowded buckets.
With that path, the 2,048-write commit took **1.32-1.33 ms in Rust versus 0.87-0.88 ms in C++** across two paired runs.
Rust point reads at that size took 3.91-4.86 us versus 0.63-0.64 us, and the logging mix took 49.7-57.5 us per transaction versus 1.06 us.
Sharing the already-pinned image when the local and global cuts are identical reduced the logging mix to 33.0-37.1 us in Rust versus 1.02-1.07 us in C++ in two subsequent pairs.
The unchanged extracted trace theorem covers this sharing, and acquisitions at different cuts still pin independent images.
This benchmark still does not cover replicated CCF.

### Persistent storage experiment

The benchmark-only `storage` target compares whole-map copy-on-write (`Arc<BTreeMap>`), copy-on-write leaf pages, and an append-only arena-backed radix tree.
All three use the same eight-byte keys and inline 64-byte values; the write workload retains every prior root.
It excludes transaction, FFI, serialization, and durability costs.

```sh
taskset -c 2 cargo +1.90.0 bench --locked --offline \
  --manifest-path src/rust/kv-spike/Cargo.toml --bench storage
```

At 2,048 entries, two runs measured pinned-root updates at 145-159 us for whole-map copy-on-write, 1.02-1.09 us for leaf pages, and 0.226-0.227 us for the radix arena.
Leaf pages were faster for eight-entry ranges (44-46 ns versus 112-119 ns for the radix arena).
One run of `kv_backend_bench champ` at the same size measured 206 ns for a pinned-root update and 41 ns for a point read.
Its eight-entry range takes 7.96 us because it filters a full CHAMP traversal.
These are component measurements, not a win against C++ CHAMP.
Neither candidate has been integrated or verified against the engine.
The radix prototype uses fixed-width keys and does not reclaim arena nodes, so native adoption requires an arbitrary-byte index, accounting for observed scan and write-set order, and reclamation once snapshots are released.

The `byte_radix` variant handles arbitrary byte keys, including empty keys and prefixes, and supports deletion, branching from a retained root, and reusing slots after tracing live roots.
On the same 2,048-key workload it took 73-74 ns for a point read, 230-231 ns for a pinned-root update, and 417-418 ns for an eight-entry range.
A CHAMP run took 36 ns, 180 ns, and 6.57 us respectively.
With variable-length keys, one long-lived root, and 32 recent roots, a separate churn test alternating deletes and puts used 1.52-1.75 us per mutation including collection, with 55-96 us p99 collection pauses.
The collector reused slots but did not shrink the backing vectors: at the end it held 8,624 live nodes in 9,697 slots and 4,111 live rows in 4,127 slots.
These results exclude serialization and FFI, and lexicographic index traversal does not preserve the engine's observed scan order without a separate projection.
This experiment is not used by the engine; its point performance and collection pauses do not justify integration.

The path-copied `nibble_radix` variant uses 16 byte-digit slots and a separate end-of-key slot; directories and leaf rows use separate arenas.
The revised CHAMP benchmark uses CCF's native `ByteVector` keys and hasher directly.
Run `kv_backend_bench champ` for dense 8-byte keys and `kv_backend_bench champ_scrambled` for a spread-out permutation; the Rust storage benchmark includes both distributions.
At 2,048 keys across two runs and both distributions, the higher-fanout Rust index took 9.9-10.2 ns for point reads and 139-153 ns for pinned-root updates, versus 42-48 ns and 199-262 ns for CHAMP.
Eight-entry ranges took 0.53-0.58 us versus 31-40 us for full CHAMP traversal with `ByteVector` comparisons.
In the separate churn workload the nibble index averaged 0.90-0.95 us per mutation including collection, with 29-35 us p99 collection pauses.
These are storage-component measurements, not a CCF transaction-throughput win.
`KvRust.Radix` proves the exact Rust digit selection, earliest split, and borrowed point lookup used by this benchmark.
The lookup theorem assumes that directory links partition the projected bindings and that each leaf refers to the correct live row.
With these extracted functions the two-run medians at 2,048 keys were 8.3-9.5 ns for point reads and 132-148 ns for pinned-root updates across both distributions.
The candidate is not integrated; updates must preserve those invariants and past roots, and scan-order refinement, bounded reclamation latency, and transaction qualification remain required.
