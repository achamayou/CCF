# Rust KV verification prototype

This opt-in package checks [a Rust prototype](../../src/rust/kv-spike) against the existing [KV model](../kv/Kv/Model/Transitions.lean).
It is not linked into production CCF and does not change the existing Lean specification.

The [dynamic engine](../../src/rust/kv-spike/src/engine.rs) implements the single-store action surface with byte strings, associative transaction state, and an append-only archive of version frames.
Each frame holds a pair of persistent radix roots: one for address lookup and one for the model's prepend-on-write scan order.
Callers explicitly capture a snapshot before acquiring the first map, and explicitly supply the result of replication after local application.
Compaction advances the global frontier and changes which map views can be acquired; it does not yet reclaim old frames.
The opt-in C++ test adapter supports ordinary ledger writes, replay, and snapshots; the production store lifecycle is not implemented.

The [original two-map proofs](KvRust/Correspondence.lean) still exercise the scheduling and publication slice.
The [association-list proofs](KvRust/Assoc.lean) connect extracted lookup, replacement and erasure to the model's operations, given correct equality and cloning.
The [key proofs](KvRust/Keys.lean) establish the byte comparator's lexicographic order and the address equality used by the engine.
The [indexed publication proof](KvRust/IndexedPublication.lean) checks the extracted right-to-left write-set fold against `Kv.Model.publish`, with numeric bounds on packed keys, path copies, row slots, and the stamp counter.
The [archive relation](KvRust/IndexedHistory.lean) ties every archived frame to its ordered index view, including frames no longer on the active branch after rollback.
The [retained-cut proof](KvRust/RetainedCuts.lean) shows that an older acquisition which remains available can read the compacted map image, or the empty placeholder, without changing its observation.
It preserves the revision invariant across the modeled apply, compact, and rollback steps.
On ordinary histories, an available acquisition below the global cut now pins the compacted image without changing its local revision or observations.
Imported and recovered histories keep the original two-cut path.
Existing handles keep their pins; the engine does not yet release archived roots.
The indexed [materialization](KvRust/IndexedImage.lean) and [pin](KvRust/PinnedImage.lean) proofs relate selected maps and point reads to those views without reconstructing the whole store.
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

The targets share 100 contract cases, including reserved writes, signature replay, in-place snapshot restore, private map recovery, and the concurrent operation fuzzer.
The shared cases include rejection of malformed ledger entries without advancing the store and rejection of an ahead-of-target recovery source without changing either store.
The remaining C++-only cases are `Map name parsing`, nine low-level reader/writer and entry-envelope cases in `kv_serialisation.cpp` and `raw_writer.cpp`, five snapshot codec cases in `kv_snapshot.cpp`, and the rest of `Store error handling`, which includes checks of the concrete C++ `AbstractMap` API and store readiness.
Rust also tests the snapshot, rollback, and term guards through its own interface.
The shared snapshot restore tests cover historical encryption secrets and captured-public-map reuse.
The same fuzzer schedules and assertions run on both backends, but the C++ trace reporter and trace-conformance runner are not wired to the Rust adapter.

The test adapter serializes commit submission and only fills reserved slots in order.
It does not implement the full CCF store interface or production replication.
The existing trace theorem applies to the single-store `Action` dispatcher, not the C ABI, CCF commit classification and post-commit reads, the ledger codec, the locking wrapper, or imported snapshot state.
The extracted ordinary ledger replay proof shows that, after decoding, a successful next-version replay advances the model with exactly the supplied writes, and a rejected replay does not mutate the store.
Provisional replacement replay and snapshot import are tested, but not covered by that theorem.

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
The earlier vector engine's bucketed batch path avoided applying the writes one at a time or cloning the input frame.
The extracted proof checks the ordered result against the original model fold, including puts, removals, and the fallback for repeated addresses or crowded buckets.
With that path, the 2,048-write commit took **1.32-1.33 ms in Rust versus 0.87-0.88 ms in C++** across two paired runs.
Rust point reads at that size took 3.91-4.86 us versus 0.63-0.64 us, and the logging mix took 49.7-57.5 us per transaction versus 1.06 us.
Sharing the already-pinned image when the local and global cuts are identical reduced the logging mix to 33.0-37.1 us in Rust versus 1.02-1.07 us in C++ in two subsequent pairs.
The unchanged extracted trace theorem covers this sharing, and acquisitions at different cuts still pin independent images.
Whole-map dependency validation now streams the committed rows instead of cloning an image just to compare it.
The extracted comparison checks the same ordered key, value, and version pairs, including insertions and deletions.
Two matched governance runs measured 24.7-26.0 us per Rust transaction before the change, 24.4-25.1 us after it, and 7.31-7.59 us for C++.
Removing the temporary image eliminates its allocations, but these timings do not establish a consistent transaction speedup.
Byte equality now uses the same bulk slice comparison for standalone byte keys as for full addresses.
The extracted equality theorem is unchanged; lexicographic range comparisons still use the byte-order comparator.
Matched timings did not establish a consistent gain from equality alone, and a separate single-write fast path was not retained because it did not consistently improve the logging workload.
Pinning local and global frames by stable ID avoids copying a map when a transaction acquires it.
In two paired runs, this reduced the 512-key logging mix from 28.7-31.5 us per Rust transaction to 4.40-5.31 us, versus 1.07-1.15 us for C++.
At 2,048 keys, populated point reads were 3.75-3.90 us in Rust versus 0.69-0.71 us in C++, and a batch of 2,048 replacements took 1.20-1.39 ms versus 0.87-0.89 ms.
Those measurements were for the vector-backed engine; the acquired-handle point-read benchmark excludes acquisition and therefore does not measure the cost that was removed.
This benchmark still does not cover replicated CCF.

After switching committed frames to the verified dual index, two paired runs on the same host measured:

| Workload                    | Rust               | C++                |
| --------------------------- | ------------------ | ------------------ |
| Point read, 2,048 entries   | 0.207-0.221 us     | 0.651-0.711 us     |
| Logging mix, 512 entries    | 0.962-0.973 us/tx  | 1.159-1.212 us/tx  |
| Governance mix, 64 entries  | 12.38-12.57 us/tx  | 7.45-8.22 us/tx    |
| Commit 2,048 replacements   | 2.97-3.13 ms       | 0.81-0.98 ms       |

These are ranges of run medians, not confidence intervals.
The indexed engine wins on point reads and this logging mix, but not on the governance mix or bulk commits.
These measurements do not establish p99 or retained-memory parity.

Checking address-key length and the last byte before the full comparison reduced 2,048-key staged replacements from 12.40-12.87 us/key to 8.12-8.67 us/key across four alternating Rust-to-Rust pairs.
It preserves full byte equality, including keys with the same last byte.
The commit and mixed-workload timings did not establish a comparable improvement.

For tail latency and peak process RSS under compaction, run each backend in its own process:

```sh
/usr/bin/time -v taskset -c 2 build/kv_backend_bench cpp pinned-churn 65536
/usr/bin/time -v taskset -c 2 build/kv_backend_bench rust pinned-churn 65536
```

The workload starts with 512 entries, retains one old reader, refreshes a second reader every 64 commits, and compacts after each single-key replacement.
It checks that both readers retain their captured values.
The p99 covers transaction construction, staging, commit, and compaction; peak RSS includes the process, allocator, and timing samples, not just live KV allocations.
Changing lineage validation to search newest-first reduced Rust p99 at 65,536 commits from 1.87-5.79 ms to 64.8-66.6 us across three runs per revision.
C++ p99 in the final pairs was 4.60-5.48 us.
Peak RSS was 132-161 MiB for Rust versus 11.3-11.5 MiB for C++.
The lineage improvement does not reclaim memory or establish latency parity.
Ending an attempt now moves the remaining attempt rows instead of cloning their pinned views and read dependencies.
At 65,536 commits, this reduced Rust median latency from 17.1-17.2 us to 1.42-1.46 us and p99 from 45.9-52.0 us to 6.29-6.73 us across three alternating Rust-to-Rust pairs.
Matched C++ medians were 1.94-2.21 us and p99 was 3.23-4.17 us.
Peak RSS remained 147-161 MiB for Rust versus about 11.5 MiB for C++.
In three additional matched runs, Rust logging took 0.587-0.637 us/tx versus 0.812-0.840 us/tx for C++.
Governance still took 8.38-9.41 us/tx versus 5.27-5.74 us/tx, and a 2,048-key replacement commit took 2.81-3.05 ms versus 0.79-0.97 ms.

When a range has no staged writes, it now copies only the selected cells into its sorted output and still records the entire committed map as a dependency.
Governance improved in each of four alternating Rust-to-Rust pairs, from 8.16-15.13 us/tx to 7.06-8.54 us/tx.
In three subsequent Rust/C++ pairs the host was noisier and Rust still lagged on governance and large commits, while point reads and logging remained faster.

For batches of at least 256 writes, publication now checks a bounded prefix in scan order to see whether the writes cover every committed address in the same order.
When they do, publication starts from an empty root in the existing arena, avoiding replacement of bindings that none of the new frames needs to retain.
The [extracted proof](KvRust/IndexedPublication.lean) covers puts and removals, retains existing pins, and requires complete coverage before dropping old bindings from the new root.
The 2,048-key replacement benchmark took 1.89-2.47 ms with this path versus 2.50-3.86 ms in four alternating Rust-to-Rust pairs.
Partial or reordered replacements still take the original edit path; the guard visits at most one more leaf than the batch length.

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
The extracted path rebuild now proves both preservation of old roots and the exact bindings of its result, given a prepared path with correct sibling partitions.
The changed native path copy uses a short scan in place of the benchmark's original trailing-zero intrinsic; its update measurements are now close to CHAMP, not a consistent win.
The extracted delete constructs its rebuild path and proves that it removes exactly the requested key without changing old roots, given a well-formed starting arena.
Native insertion shares the extracted implementation with the benchmark.
The insertion proof covers an empty root, replacing an existing key, and inserting a fresh key into a well-formed compressed radix.
It checks the ordered bindings at the new root and the preservation of previously live rows and directories.
The native mutation proofs also preserve the arena free lists, directory occupancy masks, live child-directory links, the minimum of two occupied slots, and the first-child caches used to choose a representative key.
The value-level refinements project arena row links to the actual values and implement the model's ordered `find`, `set`, and `erase`.
The mutation proofs establish the compressed-prefix witnesses for newly allocated directories and preserve those of retained directories, so subsequent mutations can reuse them.
For a valid compressed root, native traversal enumerates all live bindings in strict byte-key order, including empty and prefix keys.
This is the order needed by range results, not the model's prepend-on-write scan order.
With the native put and remove functions, the two-run component medians at 2,048 keys were 9.6-9.9 ns for point reads and 151-160 ns for pinned-root updates across the two key distributions.

The append-only `OrderedRadix` prototype keeps a compact vector of leaf links per root in model order.
The extracted proofs cover construction, point lookup, ordered scan length and every indexed result, insertion, and deletion, given valid arena-local handles and the stated capacity bounds.
Updates preserve the views and values of all retained roots.
The proof uses the actual inserted and replaced links returned by the native path copy rather than a second lookup or an assumed scan permutation.

Run the ordered storage benchmark separately:

```bash
taskset -c 2 cargo +1.90.0 bench --locked --offline \
  --manifest-path src/rust/kv-spike/Cargo.toml --bench storage -- ordered
```

The benchmark also tests a separate, unverified variant that assigns an increasing write stamp to each new leaf and sorts live leaves by stamp only when scanned.
A regression checks exact order across a fork and after reusing a freed row slot.
Across two paired runs and both key distributions, the 2,048-entry medians were 3.09-8.20 us per pinned-root replacement for the copied order vector versus 0.23-0.27 us for stamps.
Full ordered scans took 3.02-3.37 us with copied vectors versus 10.45-19.37 us with stamps.
At 8,192 entries the vector retains another 32 KiB of leaf links on each replacement, before directory, value, and allocator overhead.
Stamps take eight bytes per allocated row slot instead, but the cost of sorting the full scan grows with map size.
A benchmark-only dual radix keeps a second path-copied index from reverse write stamp to leaf link, avoiding both an order-vector copy on write and a sort on scan.
At 2,048 entries after 128 scattered replacements, full scans took 9.0-15.1 us with the dual index versus 35.1-48.5 us with on-demand sorting, while pinned replacements took 0.39-0.97 us versus 0.15-0.20 us.
The benchmark now calls the same native dual index as the [extracted storage proof](KvRust/RadixDual.lean), covering lookup, insertion, deletion, ordered scans, and preservation of old root pairs under the stated bounds.
In two reruns at 2,048 keys the actual native index took 0.42-0.44 us per pinned replacement, 9.3-10.3 us per full scan after scattered replacements, and 11.2-11.5 ns per point read.
The regression covers retained roots, writes to earlier branches, and deletion.
The second arena's allocation and reclamation costs are not qualified.
These are component measurements, not matched transaction results.
The [address encoding proof](KvRust/RadixAddress.lean) covers the actual Rust packing code and shows that a shared radix can distinguish arbitrary map/key pairs, including empty and prefix-related byte strings.
The extracted [`AddressIndex`](KvRust/KvIndex.lean) composes that encoding with the dual radix and relates its lookup, edits, ordered scans, and retained roots to the original address/value association lists.
Committed frames in the engine now use that same `AddressIndex`.
Both arenas and the frame archive still grow with history; the indexed trace theorem does not establish a bound on retained memory or cover slot retirement.

The `storage -- retirement` mode compares the full arena sweep with a benchmark-only reference-counted variant.
The variant counts explicit root pins and incoming directory edges, and retires at most 32 zero-reference slots per tick.
Its checks recompute the reference counts from all live edges and pins, exercise a queue larger than one budget, and confirm that retired slots are reused without changing retained roots.
With 2,048 variable-length keys, one old root, and a 32-root recent window, four alternating pairs measured 0.85-0.86 us per mutation including retirement versus 1.05-1.08 us including sweep.
The p99 of a complete mutation fell from 19.7-20.6 us to 1.63-1.89 us in those runs.
The count-based variant used 914 allocated directory slots versus 1,472, and 4,112 allocated row slots versus 4,127, excluding its count arrays and scratch storage.
The budget limits slots processed, not wall-clock latency or queue growth for all traces.
The benchmark uses the extracted `recycle_slot` primitive.
[`RadixLiveness`](KvRust/RadixLiveness.lean) proves that recycling preserves every retained root and its values when the selected slot has no incoming links or pins.
The [reclamation proofs](KvRust/RadixLiveness.lean) check the extracted retain and release arithmetic against exact owner multiplicities.
For the dual index they count every live stamp row as an owner of its value, even if the stamp row awaits retirement.
Recycling an unowned stamp row preserves pinned views and removes exactly one such reference; recycling an unowned value row preserves both views of every pinned root.
The directory and leaf recycling proofs preserve the arena invariants that subsequent inserts and deletes require, not just the current view of each pinned root.
The benchmark now uses the [extracted retirement FIFO](KvRust/RetireQueue.lean), whose reads, pushes, and pops agree with a list through wraparound and capacity growth.
The per-tick retirement budget does not bound queue growth, allocator latency, or the cost of a queue expansion.
End-to-end accounting for attaching and releasing roots and directory edges, and scheduling retirement, is still open.
Retirement is not used by the transaction backend.

The experimental history now uses [`BranchLog`](KvRust/BranchLog.lean) to separate active branch offsets from stable frame IDs.
Its extracted proofs show that rewind truncates the active sequence without invalidating old IDs and that an append at a reused offset names a new frame.
The single-store trace theorem relates the active sequence to the same model history, with an additional capacity bound for the retained frame arena.
Normal acquisitions retain frame IDs instead of copying map images, materializing an ordered image only for a whole-map operation.
The trace proof carries the validity and values of those handles across commits and rewinds.
The frame arena retains discarded frames until the log is replaced or dropped; this is not a production reclamation strategy.
