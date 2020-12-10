# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

add_library(secp256k1.host STATIC ${CCF_DIR}/3rdparty/secp256k1/src/secp256k1.c)
# Can't add_san to this library, doing so causes a compile error on
# field_*_asm_impl.h: inline assembly requires more registers than available
target_include_directories(
  secp256k1.host PUBLIC $<BUILD_INTERFACE:${CCF_DIR}/3rdparty/secp256k1>
                        $<INSTALL_INTERFACE:include/3rdparty/secp256k1>
)
target_compile_options(secp256k1.host PRIVATE -fvisibility=hidden)
target_compile_definitions(secp256k1.host PRIVATE HAVE_CONFIG_H SECP256K1_BUILD)
set_property(TARGET secp256k1.host PROPERTY POSITION_INDEPENDENT_CODE ON)
install(
  TARGETS secp256k1.host
  EXPORT ccf
  DESTINATION lib
)
