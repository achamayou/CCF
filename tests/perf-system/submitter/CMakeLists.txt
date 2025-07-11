set(SUBMITTER_DIR ${CCF_DIR}/tests/perf-system/submitter)

add_executable(
  submit ${SUBMITTER_DIR}/submit.cpp ${SUBMITTER_DIR}/handle_arguments.h
         ${SUBMITTER_DIR}/parquet_data.h
)
target_compile_definitions(submit PRIVATE CCF_LOGGER_NO_DEPRECATE)

add_library(stdcxxhttp_parser "${HTTP_PARSER_SOURCES}")
target_compile_definitions(stdcxxhttp_parser PRIVATE CCF_LOGGER_NO_DEPRECATE)

set(CCFCRYPTO_SRC
    ${CCF_DIR}/src/crypto/base64.cpp
    ${CCF_DIR}/src/crypto/entropy.cpp
    ${CCF_DIR}/src/crypto/hash.cpp
    ${CCF_DIR}/src/crypto/sha256_hash.cpp
    ${CCF_DIR}/src/crypto/symmetric_key.cpp
    ${CCF_DIR}/src/crypto/key_pair.cpp
    ${CCF_DIR}/src/crypto/rsa_key_pair.cpp
    ${CCF_DIR}/src/crypto/verifier.cpp
    ${CCF_DIR}/src/crypto/key_wrap.cpp
    ${CCF_DIR}/src/crypto/hmac.cpp
    ${CCF_DIR}/src/crypto/pem.cpp
    ${CCF_DIR}/src/crypto/cose.cpp
    ${CCF_DIR}/src/crypto/openssl/symmetric_key.cpp
    ${CCF_DIR}/src/crypto/openssl/public_key.cpp
    ${CCF_DIR}/src/crypto/openssl/key_pair.cpp
    ${CCF_DIR}/src/crypto/openssl/hash.cpp
    ${CCF_DIR}/src/crypto/openssl/rsa_public_key.cpp
    ${CCF_DIR}/src/crypto/openssl/rsa_key_pair.cpp
    ${CCF_DIR}/src/crypto/openssl/verifier.cpp
    ${CCF_DIR}/src/crypto/sharing.cpp
)

add_library(stdcxxccfcrypto STATIC "${CCFCRYPTO_SRC}")
target_link_libraries(stdcxxccfcrypto PUBLIC crypto)
target_link_libraries(stdcxxccfcrypto PUBLIC ssl)
target_link_libraries(stdcxxccfcrypto PUBLIC qcbor)
target_compile_definitions(stdcxxccfcrypto PRIVATE CCF_LOGGER_NO_DEPRECATE)

target_link_libraries(
  submit PRIVATE stdcxxhttp_parser stdcxxccfcrypto arrow parquet
)

install(TARGETS submit DESTINATION bin)
