// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cstdint>

namespace ccf::kv
{
  enum class StoreReadiness : uint8_t
  {
    Unavailable,
    InstallingSnapshot,
    Ready,
    Failed
  };
}
