# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

if(NOT TARGET cargo-build_ccf_kv_rust)
  set(CCF_KV_RUST_CRATE "${CCF_DIR}/src/rust/ccf-kv/ffi")
  set(CCF_KV_RUST_LIB "libccf_kv_rust.a")
  set(CCF_KV_RUST_CARGO_DIR "${CMAKE_CURRENT_BINARY_DIR}/cargo/ccf-kv-rust")
  set(
    CCF_KV_RUST_COMBINED_OBJECT
    "${CCF_KV_RUST_CARGO_DIR}/ccf_kv_rust_combined.o"
  )
  set(CCF_KV_RUST_LIBRARY "${CMAKE_CURRENT_BINARY_DIR}/${CCF_KV_RUST_LIB}")

  if(CMAKE_CONFIGURATION_TYPES)
    message(
      FATAL_ERROR
      "Multi-config generators are not supported for the Rust KV build. "
      "Use a single-config generator (e.g. -GNinja) and set CMAKE_BUILD_TYPE instead."
    )
  endif()

  if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CCF_KV_RUST_CARGO_PROFILE_FLAG "")
    set(CCF_KV_RUST_CARGO_PROFILE_DIR "debug")
    set(CCF_KV_RUST_CARGO_PROFILE_NAME "dev")
  else()
    set(CCF_KV_RUST_CARGO_PROFILE_FLAG "--release")
    set(CCF_KV_RUST_CARGO_PROFILE_DIR "release")
    set(CCF_KV_RUST_CARGO_PROFILE_NAME "release")
  endif()

  message(
    STATUS
    "Rust ccf-kv-ffi: CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -> Cargo profile '${CCF_KV_RUST_CARGO_PROFILE_NAME}'"
  )

  set(
    CCF_KV_RUST_CARGO_LIB
    "${CCF_KV_RUST_CARGO_DIR}/${CCF_KV_RUST_CARGO_PROFILE_DIR}/libccf_kv_ffi.a"
  )
  set(
    CCF_KV_RUST_RUSTFLAGS
    "-C relocation-model=pic --remap-path-prefix=${CCF_DIR}=CCF --remap-path-prefix=$ENV{HOME}/.cargo=CARGO"
  )
  if(TSAN)
    set(CCF_KV_RUST_RUSTFLAGS "${CCF_KV_RUST_RUSTFLAGS} --cfg ccf_tsan")
  endif()

  add_custom_target(
    cargo-build_ccf_kv_rust
    BYPRODUCTS "${CCF_KV_RUST_LIBRARY}" "${CCF_KV_RUST_COMBINED_OBJECT}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${CCF_KV_RUST_CARGO_DIR}"
    COMMAND
      "${CMAKE_COMMAND}" -E env --unset=CARGO_BUILD_TARGET
      "RUSTFLAGS=${CCF_KV_RUST_RUSTFLAGS}" "CARGO_BUILD_RUSTC=${RUSTC}"
      "${CARGO}" build --locked --offline ${CCF_KV_RUST_CARGO_PROFILE_FLAG}
      --target-dir "${CCF_KV_RUST_CARGO_DIR}"
    COMMAND
      "${CMAKE_CXX_COMPILER}" -r -nostdlib -Wl,--whole-archive
      "${CCF_KV_RUST_CARGO_LIB}" -Wl,--no-whole-archive -o
      "${CCF_KV_RUST_COMBINED_OBJECT}"
    COMMAND
      "${CMAKE_OBJCOPY}" --wildcard "--keep-global-symbol=ccf_rust_kv_*"
      "${CCF_KV_RUST_COMBINED_OBJECT}"
    COMMAND
      "${CMAKE_COMMAND}" "-DNM=${CMAKE_NM}"
      "-DOBJECT=${CCF_KV_RUST_COMBINED_OBJECT}" -P
      "${CCF_DIR}/cmake/verify_ccf_kv_rust_exports.cmake"
    COMMAND "${CMAKE_COMMAND}" -E rm -f "${CCF_KV_RUST_LIBRARY}"
    COMMAND
      "${CMAKE_AR}" qc "${CCF_KV_RUST_LIBRARY}" "${CCF_KV_RUST_COMBINED_OBJECT}"
    COMMAND "${CMAKE_RANLIB}" "${CCF_KV_RUST_LIBRARY}"
    WORKING_DIRECTORY "${CCF_KV_RUST_CRATE}"
    DEPENDS
      "${CCF_KV_RUST_CRATE}/Cargo.toml"
      "${CCF_KV_RUST_CRATE}/Cargo.lock"
      "${CCF_DIR}/src/rust/ccf-kv/Cargo.toml"
      "${CCF_DIR}/src/rust/ccf-kv/Cargo.lock"
    COMMENT
      "Building the Rust KV FFI library (Cargo profile: ${CCF_KV_RUST_CARGO_PROFILE_NAME})"
    VERBATIM
  )

  add_library(ccf_kv_rust INTERFACE)
  target_link_libraries(
    ccf_kv_rust
    INTERFACE
      $<BUILD_INTERFACE:${CCF_KV_RUST_LIBRARY}>
      $<INSTALL_INTERFACE:${CMAKE_INSTALL_PREFIX}/lib/${CCF_KV_RUST_LIB}>
      ${CMAKE_DL_LIBS}
      m
  )
  add_dependencies(ccf_kv_rust cargo-build_ccf_kv_rust)

  if(USE_RUST_KV)
    install(FILES "${CCF_KV_RUST_LIBRARY}" DESTINATION lib)
    install(TARGETS ccf_kv_rust EXPORT ccf)
  endif()
endif()
