# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
cmake_minimum_required(VERSION 3.11)

set(CCF_DIR ${CMAKE_CURRENT_SOURCE_DIR})
include(${CCF_DIR}/cmake/preproject.cmake)
include(${CCF_DIR}/cmake/version.cmake)

project(
  ccf
  VERSION ${CCF_RELEASE_VERSION}
  LANGUAGES C CXX
)

set(ENV{BETTER_EXCEPTIONS} 1)

message(STATUS "CCF version=${CCF_VERSION}")
message(STATUS "CCF release version=${CCF_RELEASE_VERSION}")

include(${CCF_DIR}/cmake/cpack_settings.cmake)

# Set the default install prefix for CCF. Users may override this value with the
# cmake command. For example:
#
# $ cmake -DCMAKE_INSTALL_PREFIX=/opt/myplace ..
#
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  set(CMAKE_INSTALL_PREFIX
      "/opt/${CCF_VERSION}"
      CACHE PATH "Default install prefix" FORCE
  )
endif()

message(STATUS "CMAKE_INSTALL_PREFIX is '${CMAKE_INSTALL_PREFIX}'")

install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/cmake/preproject.cmake
        DESTINATION cmake
)

include(GNUInstallDirs)

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/common.cmake)

configure_file(
  ${CCF_DIR}/src/host/version.h.in ${CCF_GENERATED_DIR}/version.h @ONLY
)
configure_file(${CCF_DIR}/python/setup.py.in ${CCF_DIR}/python/setup.py @ONLY)

set(CONSENSUSES cft bft)

option(BUILD_TESTS "Build tests" ON)
option(BUILD_UNIT_TESTS "Build unit tests" ON)
option(TLS_TEST "TLS Test using https://github.com/drwetter/testssl.sh" OFF)
option(BUILD_SMALLBANK "Build SmallBank sample app and clients" ON)

add_picobench(hash_bench SRCS src/ds/test/hash_bench.cpp)
add_picobench(
  digest_bench
  SRCS src/crypto/test/digest_bench.cpp
  LINK_LIBS ccfcrypto.host evercrypt.host secp256k1.host
  INCLUDE_DIRS ${EVERCRYPT_INC}
)