# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set(KV_RUST_TEST_CRATE "${CCF_DIR}/src/rust/kv-spike/cpp-test")
set(KV_RUST_TEST_CARGO_DIR "${CMAKE_CURRENT_BINARY_DIR}/cargo/kv-rust-tests")
set(
  KV_RUST_TEST_LIBRARY
  "${KV_RUST_TEST_CARGO_DIR}/release/libccf_kv_cpp_test.a"
)

add_custom_target(
  cargo-build_kv_rust_test
  BYPRODUCTS "${KV_RUST_TEST_LIBRARY}"
  COMMAND
    "${CMAKE_COMMAND}" -E env --unset=CARGO_BUILD_TARGET "${CARGO}" build
    --locked --offline --release --target-dir "${KV_RUST_TEST_CARGO_DIR}"
  WORKING_DIRECTORY "${KV_RUST_TEST_CRATE}"
  COMMENT "Building the test-only Rust KV library"
  VERBATIM
)

add_unit_test(
  kv_rust_test
  ${CCF_DIR}/src/kv/test/kv_contention.cpp
  ${CCF_DIR}/src/kv/test/kv_contract.cpp
  ${CCF_DIR}/src/kv/test/kv_fuzzer.cpp
  ${CCF_DIR}/src/kv/test/kv_ledger_contract.cpp
  ${CCF_DIR}/src/kv/test/kv_snapshot_contract.cpp
  ${CCF_DIR}/src/kv/test/kv_rust_test_main.cpp
  ${CCF_DIR}/src/kv/test/kv_trace.cpp
  ${CCF_DIR}/src/kv/test/rust_kv_commit.cpp
  ${CCF_DIR}/src/kv/test/rust_kv_replay.cpp
  ${CCF_DIR}/src/kv/test/rust_kv_snapshot.cpp
)
target_compile_definitions(kv_rust_test PRIVATE CCF_KV_RUST_TEST_BACKEND)
target_link_libraries(
  kv_rust_test
  PRIVATE "${KV_RUST_TEST_LIBRARY}" ${CMAKE_DL_LIBS} m
)
add_dependencies(kv_rust_test cargo-build_kv_rust_test)

add_unit_test(
  kv_rust_interop_test
  ${CCF_DIR}/src/kv/test/kv_rust_interop.cpp
  ${CCF_DIR}/src/kv/test/rust_kv_commit.cpp
  ${CCF_DIR}/src/kv/test/rust_kv_replay.cpp
  ${CCF_DIR}/src/kv/test/rust_kv_snapshot.cpp
)
target_link_libraries(
  kv_rust_interop_test
  PRIVATE "${KV_RUST_TEST_LIBRARY}" ${CMAKE_DL_LIBS} m ccf_kv http_parser
)
add_dependencies(kv_rust_interop_test cargo-build_kv_rust_test)
