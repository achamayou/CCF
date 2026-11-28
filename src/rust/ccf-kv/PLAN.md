# Rust KV Drop-In Replacement Plan

This document tracks the remaining work required for `src/rust/ccf-kv` to be a complete, production-ready drop-in replacement for CCF's C++ KV engine.
Remove sections once completed and verified.

## 1. Full Validation and Compatibility Matrix (`USE_RUST_KV=ON`)

- Run the full e2e suite under `-DUSE_RUST_KV=ON` (including `governance_test`, `code_update_test`, `modules_test`, `reconfiguration_test_suite`, `recovery_*_snapshot_join_test`, `full_test_suite`).
- Run `partitions` (`-L partitions`) and `cft_scenario_test` under `-DUSE_RUST_KV=ON`.
- Run `lts_compatibility` (`-DLONG_TESTS=ON`) to verify ledger and snapshot interoperability with older C++ CCF releases.
- Run full-node TSAN (`-DUSE_RUST_KV=ON -DTSAN=ON`) on node unit tests and `e2e_logging`, plus an ARM64 (`aarch64`) concurrency CI run.
- Verify installed-SDK (`test_install.sh`) and RPM/offline-vendored builds under `-DUSE_RUST_KV=ON`.

## 2. Production Memory and Operational Edge Cases

- Evaluate slab shrinkage or high-water RSS behavior in `SingleRadix` (`src/rust/ccf-kv/src/radix.rs`) after large transient spikes and bulk deletes.
- Scale `RETIRE_BUDGET` (currently fixed at `16` in `src/rust/ccf-kv/src/engine.rs`) on `compact()` / `install_snapshot()` or proportional to retired-queue depth to prevent delayed RSS reclamation after bulk drops.
- Trim `RustStore::map_deltas` retention in `src/kv/rust_kv_store_impl.h` for maps without registered `global_hooks`.
- Benchmark high-thread-count deployments (>64 concurrent workers) and raise or dynamically size `NUM_HAZARD_SLOTS` if hazard-slot fallback causes contention.

## 3. Drop-In Surface Cleanup and C++ KV Retirement

- Retire C++-only `AbstractMap` virtuals (`get_map`, `get_map_unsafe`, `add_dynamic_map`) once `USE_RUST_KV=ON` becomes the default/sole KV backend.
- Flip `USE_RUST_KV` default to `ON` in `CMakeLists.txt`, remove dual `#ifdef CCF_USE_RUST_KV` branches in `src/kv/`, and retire the legacy C++ CHAMP/Map implementation.
