# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

include(${CCF_DIR}/cmake/ccf_kv_rust.cmake)

add_unit_test(
  kv_rust_test
  ${CCF_DIR}/src/kv/rust_kv_backend.cpp
  ${CCF_DIR}/src/kv/test/kv_contention.cpp
  ${CCF_DIR}/src/kv/test/kv_contract.cpp
  ${CCF_DIR}/src/kv/test/kv_fuzzer.cpp
  ${CCF_DIR}/src/kv/test/kv_ledger_contract.cpp
  ${CCF_DIR}/src/kv/test/kv_snapshot_contract.cpp
  ${CCF_DIR}/src/kv/test/kv_rust_test_main.cpp
  ${CCF_DIR}/src/kv/test/kv_trace.cpp
)
if(CCF_KV_TRACING)
  target_sources(kv_rust_test PRIVATE ${CCF_DIR}/src/kv/trace.cpp)
endif()
target_compile_definitions(kv_rust_test PRIVATE CCF_KV_RUST_TEST_BACKEND)
target_link_libraries(
  kv_rust_test
  PRIVATE "${CCF_KV_RUST_LIBRARY}" ccfcrypto ${CMAKE_DL_LIBS} m
)
add_dependencies(kv_rust_test cargo-build_ccf_kv_rust)

add_unit_test(
  kv_rust_interop_test
  ${CCF_DIR}/src/kv/rust_kv_backend.cpp
  ${CCF_DIR}/src/kv/test/kv_rust_interop.cpp
)
target_link_libraries(
  kv_rust_interop_test
  PRIVATE
    "${CCF_KV_RUST_LIBRARY}"
    ccfcrypto
    ${CMAKE_DL_LIBS}
    m
    ccf_kv
    http_parser
)
add_dependencies(kv_rust_interop_test cargo-build_ccf_kv_rust)

add_test_bin(
  kv_backend_bench
  ${CCF_DIR}/src/kv/rust_kv_backend.cpp
  ${CCF_DIR}/src/kv/test/kv_backend_bench.cpp
)
target_link_libraries(
  kv_backend_bench
  PRIVATE
    "${CCF_KV_RUST_LIBRARY}"
    ccfcrypto
    ${CMAKE_DL_LIBS}
    m
    ccf_kv
    http_parser
)
add_dependencies(kv_backend_bench cargo-build_ccf_kv_rust)
