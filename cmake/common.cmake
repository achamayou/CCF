# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set(CMAKE_MODULE_PATH "${CCF_DIR}/cmake;${CMAKE_MODULE_PATH}")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(Threads REQUIRED)

set(PYTHON unbuffer python3)

set(DISTRIBUTE_PERF_TESTS
    ""
    CACHE
      STRING
      "Hosts to which performance tests should be distributed, for example -n ssh://x.x.x.x -n ssh://x.x.x.x -n ssh://x.x.x.x"
)

if(DISTRIBUTE_PERF_TESTS)
  separate_arguments(NODES UNIX_COMMAND ${DISTRIBUTE_PERF_TESTS})
else()
  unset(NODES)
endif()

option(VERBOSE_LOGGING "Enable verbose logging" OFF)
set(TEST_HOST_LOGGING_LEVEL "info")
if(VERBOSE_LOGGING)
  add_compile_definitions(VERBOSE_LOGGING)
  set(TEST_HOST_LOGGING_LEVEL "debug")
endif()

option(NO_STRICT_TLS_CIPHERSUITES
       "Disable strict list of valid TLS ciphersuites" OFF
)
if(NO_STRICT_TLS_CIPHERSUITES)
  add_compile_definitions(NO_STRICT_TLS_CIPHERSUITES)
endif()

option(USE_NULL_ENCRYPTOR "Turn off encryption of ledger updates - debug only"
       OFF
)
if(USE_NULL_ENCRYPTOR)
  add_compile_definitions(USE_NULL_ENCRYPTOR)
endif()

option(SAN "Enable Address and Undefined Behavior Sanitizers" OFF)
option(DISABLE_QUOTE_VERIFICATION "Disable quote verification" OFF)
option(BUILD_END_TO_END_TESTS "Build end to end tests" ON)
option(COVERAGE "Enable coverage mapping" OFF)
option(SHUFFLE_SUITE "Shuffle end to end test suite" OFF)

option(DEBUG_CONFIG "Enable non-production options options to aid debugging"
       OFF
)
if(DEBUG_CONFIG)
  add_compile_definitions(DEBUG_CONFIG)
endif()

option(USE_NLJSON_KV_SERIALISER "Use nlohmann JSON as the KV serialiser" OFF)
if(USE_NLJSON_KV_SERIALISER)
  add_compile_definitions(USE_NLJSON_KV_SERIALISER)
endif()

enable_language(ASM)

set(CCF_GENERATED_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)
include_directories(${CCF_DIR}/src)

include_directories(SYSTEM ${CCF_DIR}/3rdparty ${CCF_DIR}/3rdparty/hacl-star)

find_package(MbedTLS REQUIRED)

set(CLIENT_MBEDTLS_INCLUDE_DIR "${MBEDTLS_INCLUDE_DIRS}")
set(CLIENT_MBEDTLS_LIBRARIES "${MBEDTLS_LIBRARIES}")

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/tools.cmake)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/cmake/tools.cmake DESTINATION cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/ccf_app.cmake)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/cmake/ccf_app.cmake DESTINATION cmake)

if(SAN AND LVI_MITIGATIONS)
  message(
    FATAL_ERROR
      "Building with both SAN and LVI mitigations is unsafe and deadlocks - choose one"
  )
endif()

# Copy and install CCF utilities
set(CCF_UTILITIES keygenerator.sh scurl.sh submit_recovery_share.sh
                  verify_quote.sh
)
foreach(UTILITY ${CCF_UTILITIES})
  configure_file(
    ${CCF_DIR}/python/utils/${UTILITY} ${CMAKE_CURRENT_BINARY_DIR} COPYONLY
  )
  install(PROGRAMS ${CCF_DIR}/python/utils/${UTILITY} DESTINATION bin)
endforeach()

# Copy utilities from tests directory
set(CCF_TEST_UTILITIES tests.sh cimetrics_env.sh upload_pico_metrics.py
                       test_install.sh test_python_cli.sh
)
foreach(UTILITY ${CCF_TEST_UTILITIES})
  configure_file(
    ${CCF_DIR}/tests/${UTILITY} ${CMAKE_CURRENT_BINARY_DIR} COPYONLY
  )
endforeach()

# Install additional utilities
install(PROGRAMS ${CCF_DIR}/tests/sgxinfo.sh DESTINATION bin)

# Install getting_started scripts for VM creation and setup
install(
  DIRECTORY ${CCF_DIR}/getting_started/
  DESTINATION getting_started
  USE_SOURCE_PERMISSIONS
)

if("sgx" IN_LIST COMPILE_TARGETS)
  if(NOT DISABLE_QUOTE_VERIFICATION)
    set(QUOTES_ENABLED ON)
  endif()

  if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(DEFAULT_ENCLAVE_TYPE debug)
  endif()
else()
  set(DEFAULT_ENCLAVE_TYPE virtual)
endif()

# Lua module
set(LUA_DIR ${CCF_DIR}/3rdparty/lua)
set(LUA_SOURCES
    ${LUA_DIR}/lapi.c
    ${LUA_DIR}/lauxlib.c
    ${LUA_DIR}/lbaselib.c
    ${LUA_DIR}/lcode.c
    ${LUA_DIR}/lcorolib.c
    ${LUA_DIR}/lctype.c
    ${LUA_DIR}/ldebug.c
    ${LUA_DIR}/ldo.c
    ${LUA_DIR}/ldump.c
    ${LUA_DIR}/lfunc.c
    ${LUA_DIR}/lgc.c
    ${LUA_DIR}/llex.c
    ${LUA_DIR}/lmathlib.c
    ${LUA_DIR}/lmem.c
    ${LUA_DIR}/lobject.c
    ${LUA_DIR}/lopcodes.c
    ${LUA_DIR}/lparser.c
    ${LUA_DIR}/lstate.c
    ${LUA_DIR}/lstring.c
    ${LUA_DIR}/lstrlib.c
    ${LUA_DIR}/ltable.c
    ${LUA_DIR}/ltablib.c
    ${LUA_DIR}/ltm.c
    ${LUA_DIR}/lundump.c
    ${LUA_DIR}/lutf8lib.c
    ${LUA_DIR}/lvm.c
    ${LUA_DIR}/lzio.c
)

set(HTTP_PARSER_SOURCES
    ${CCF_DIR}/3rdparty/llhttp/api.c ${CCF_DIR}/3rdparty/llhttp/http.c
    ${CCF_DIR}/3rdparty/llhttp/llhttp.c
)

find_library(CRYPTO_LIBRARY crypto)

include(${CCF_DIR}/cmake/crypto.cmake)
include(${CCF_DIR}/cmake/secp256k1.cmake)

list(APPEND LINK_LIBCXX -lc++ -lc++abi -lc++fs -stdlib=libc++)

# Unit test wrapper
function(add_unit_test name)
  add_executable(${name} ${CCF_DIR}/src/enclave/thread_local.cpp ${ARGN})
  target_compile_options(${name} PRIVATE -stdlib=libc++)
  target_include_directories(${name} PRIVATE src ${CCFCRYPTO_INC})
  enable_coverage(${name})
  target_link_libraries(
    ${name} PRIVATE ${LINK_LIBCXX} ccfcrypto.host openenclave::oehostverify
  )
  use_client_mbedtls(${name})
  add_san(${name})

  add_test(NAME ${name} COMMAND ${CCF_DIR}/tests/unit_test_wrapper.sh ${name})
  set_property(
    TEST ${name}
    APPEND
    PROPERTY LABELS unit_test
  )
endfunction()

# Test binary wrapper
function(add_test_bin name)
  add_executable(${name} ${CCF_DIR}/src/enclave/thread_local.cpp ${ARGN})
  target_compile_options(${name} PRIVATE -stdlib=libc++)
  target_include_directories(${name} PRIVATE src ${CCFCRYPTO_INC})
  enable_coverage(${name})
  target_link_libraries(${name} PRIVATE ${LINK_LIBCXX} ccfcrypto.host)
  use_client_mbedtls(${name})
  add_san(${name})
endfunction()

option(USE_SNMALLOC "should snmalloc be used" ON)


# Common test args for Python scripts starting up CCF networks
set(WORKER_THREADS
    0
    CACHE STRING "Number of worker threads to start on each CCF node"
)

set(CCF_NETWORK_TEST_DEFAULT_GOV ${CCF_DIR}/src/runtime_config/gov.lua)
set(CCF_NETWORK_TEST_ARGS -l ${TEST_HOST_LOGGING_LEVEL} --worker-threads
                          ${WORKER_THREADS}
)


# Picobench wrapper
function(add_picobench name)
  cmake_parse_arguments(
    PARSE_ARGV 1 PARSED_ARGS "" "" "SRCS;INCLUDE_DIRS;LINK_LIBS"
  )

  add_executable(${name} ${PARSED_ARGS_SRCS})

  #add_lvi_mitigations(${name})

  target_include_directories(${name} PRIVATE src ${PARSED_ARGS_INCLUDE_DIRS})

  target_link_libraries(
    ${name} PRIVATE ${CMAKE_THREAD_LIBS_INIT} ${PARSED_ARGS_LINK_LIBS}
  )

  # -Wall -Werror catches a number of warnings in picobench
  target_include_directories(${name} SYSTEM PRIVATE 3rdparty)

  add_test(
    NAME ${name}
    COMMAND
      bash -c
      "$<TARGET_FILE:${name}> --samples=1000 --out-fmt=csv --output=${name}.csv && cat ${name}.csv"
  )

  use_client_mbedtls(${name})

  set_property(TEST ${name} PROPERTY LABELS benchmark)
endfunction()
