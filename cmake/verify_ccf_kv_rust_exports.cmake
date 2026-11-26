# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

if(NOT DEFINED NM OR NOT DEFINED OBJECT)
  message(FATAL_ERROR "NM and OBJECT are required")
endif()

execute_process(
  COMMAND "${NM}" --defined-only --extern-only "${OBJECT}"
  RESULT_VARIABLE NM_RESULT
  OUTPUT_VARIABLE NM_OUTPUT
  ERROR_VARIABLE NM_ERROR
)
if(NOT NM_RESULT EQUAL 0)
  message(FATAL_ERROR "Failed to inspect ${OBJECT}: ${NM_ERROR}")
endif()

set(HAS_KV_EXPORT FALSE)
string(REPLACE "\n" ";" NM_LINES "${NM_OUTPUT}")
foreach(LINE IN LISTS NM_LINES)
  string(STRIP "${LINE}" LINE)
  if(LINE STREQUAL "")
    continue()
  endif()

  if(NOT LINE MATCHES "[ \t]([^ \t]+)$")
    message(FATAL_ERROR "Unexpected nm output for ${OBJECT}: ${LINE}")
  endif()

  set(SYMBOL "${CMAKE_MATCH_1}")
  if(SYMBOL STREQUAL "ccf_rust_kv_new")
    set(HAS_KV_EXPORT TRUE)
  elseif(NOT SYMBOL MATCHES "^ccf_rust_kv_")
    message(FATAL_ERROR "Unexpected global symbol in ${OBJECT}: ${SYMBOL}")
  endif()
endforeach()

if(NOT HAS_KV_EXPORT)
  message(
    FATAL_ERROR
    "Expected ccf-kv-ffi C ABI exports are missing from ${OBJECT}"
  )
endif()
