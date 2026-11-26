# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

if(NOT TARGET cargo-build_ccf_kv_rust)
  set(CCF_KV_RUST_CRATE "${CCF_DIR}/src/rust/ccf-kv/ffi")
  set(CCF_KV_RUST_CARGO_DIR "${CMAKE_CURRENT_BINARY_DIR}/cargo/ccf-kv-rust")
  set(
    CCF_KV_RUST_CARGO_LIB
    "${CCF_KV_RUST_CARGO_DIR}/release/libccf_kv_ffi.a"
  )
  set(
    CCF_KV_RUST_COMBINED_OBJECT
    "${CCF_KV_RUST_CARGO_DIR}/ccf_kv_rust_combined.o"
  )
  set(CCF_KV_RUST_LIBRARY "${CMAKE_CURRENT_BINARY_DIR}/libccf_kv_rust.a")

  add_custom_target(
    cargo-build_ccf_kv_rust
    BYPRODUCTS "${CCF_KV_RUST_LIBRARY}" "${CCF_KV_RUST_COMBINED_OBJECT}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${CCF_KV_RUST_CARGO_DIR}"
    COMMAND
      "${CMAKE_COMMAND}" -E env --unset=CARGO_BUILD_TARGET
      "RUSTFLAGS=-C relocation-model=pic" "${CARGO}" build --locked --offline
      --release --target-dir "${CCF_KV_RUST_CARGO_DIR}"
    COMMAND
      "${CMAKE_CXX_COMPILER}" -r -nostdlib -Wl,--whole-archive
      "${CCF_KV_RUST_CARGO_LIB}" -Wl,--no-whole-archive -o
      "${CCF_KV_RUST_COMBINED_OBJECT}"
    COMMAND
      "${CMAKE_OBJCOPY}" --wildcard "--keep-global-symbol=ccf_rust_kv_*"
      "${CCF_KV_RUST_COMBINED_OBJECT}"
    COMMAND "${CMAKE_COMMAND}" -E rm -f "${CCF_KV_RUST_LIBRARY}"
    COMMAND
      "${CMAKE_AR}" qc "${CCF_KV_RUST_LIBRARY}" "${CCF_KV_RUST_COMBINED_OBJECT}"
    COMMAND "${CMAKE_RANLIB}" "${CCF_KV_RUST_LIBRARY}"
    WORKING_DIRECTORY "${CCF_KV_RUST_CRATE}"
    COMMENT "Building the Rust KV FFI library"
    VERBATIM
  )
endif()
