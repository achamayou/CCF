// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "endian.h"
#define HAVE_OPENSSL
#define HAVE_MBEDTLS
// merklecpp traces are off by default, even when CCF tracing is enabled
// #include "merklecpp_trace.h"
#include <merklecpp/merklecpp.h>

namespace ccf
{
  using HistoryTree = merkle::TreeT<32, merkle::sha256_openssl>;
}