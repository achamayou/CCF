// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/null_encryptor.h"

#ifdef CCF_KV_RUST_TEST_BACKEND
#  include "kv/test/rust_kv_diff.h"
#  include "kv/test/rust_kv_typed.h"
#else
#  include "kv/store.h"
#endif

namespace ccf::kv::test
{
#ifdef CCF_KV_RUST_TEST_BACKEND
  using TestStoreBase = rust_test::Store;
#else
  using TestStoreBase = Store;
#endif

  struct TestStore : public TestStoreBase
  {
    TestStore()
    {
      set_encryptor(std::make_shared<NullTxEncryptor>());
    }
  };

  inline bool has_map_at(
    TestStoreBase& store, Version version, const std::string& name)
  {
#ifdef CCF_KV_RUST_TEST_BACKEND
    return store.has_map_at(version, name);
#else
    return store.get_map(version, name) != nullptr;
#endif
  }

  inline std::unique_ptr<AbstractStore::AbstractSnapshot> take_snapshot(
    TestStoreBase& store, Version version)
  {
#ifdef CCF_KV_RUST_TEST_BACKEND
    return store.snapshot_maps(version);
#else
    ScopedStoreMapsLock lock(&store);
    return store.snapshot_unsafe_maps(version);
#endif
  }
}
