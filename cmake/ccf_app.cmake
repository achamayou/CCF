# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set(ALLOWED_TARGETS "sgx;virtual")

set(COMPILE_TARGETS
    "sgx;virtual"
    CACHE
      STRING
      "List of target compilation platforms. Choose from: ${ALLOWED_TARGETS}"
)

set(IS_VALID_TARGET "FALSE")
foreach(REQUESTED_TARGET ${COMPILE_TARGETS})
  if(${REQUESTED_TARGET} IN_LIST ALLOWED_TARGETS)
    set(IS_VALID_TARGET "TRUE")
  else()
    message(
      FATAL_ERROR
        "${REQUESTED_TARGET} is not a valid target. Choose from: ${ALLOWED_TARGETS}"
    )
  endif()
endforeach()

if((NOT ${IS_VALID_TARGET}))
  message(
    FATAL_ERROR
      "Variable list 'COMPILE_TARGETS' must include at least one supported target. Choose from: ${ALLOWED_TARGETS}"
  )
endif()

function(use_client_mbedtls name)
  target_include_directories(${name} PRIVATE ${CLIENT_MBEDTLS_INCLUDE_DIR})
  target_link_libraries(${name} PRIVATE ${CLIENT_MBEDTLS_LIBRARIES})
endfunction()