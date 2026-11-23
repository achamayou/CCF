// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "kv/null_encryptor.h"
#include "kv/store.h"
#include "kv/test/stub_consensus.h"

#include <atomic>
#include <doctest/doctest.h>
#include <exception>
#include <thread>
#include <vector>

struct MapTypes
{
  using StringString = ccf::kv::Map<std::string, std::string>;
  using NumNum = ccf::kv::Map<size_t, size_t>;
  using NumString = ccf::kv::Map<size_t, std::string>;
  using StringNum = ccf::kv::Map<std::string, size_t>;
};
