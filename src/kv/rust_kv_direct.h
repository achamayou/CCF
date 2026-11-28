// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/kv/tx.h"

#include <cstdint>

namespace ccf::kv
{
#ifdef CCF_USE_RUST_KV
  // Lazily prepares a BaseTx for direct Rust-to-Rust KV access from ccf-app,
  // returning the raw ConcurrentStore and NativeTx pointers. Returns false when
  // direct access is unavailable (e.g. KV tracing active or reserved/subclass
  // store), in which case callers fall back to the standard C++ MapHandle path.
  bool prepare_rust_direct_tx(
    BaseTx& tx,
    bool read_only,
    const void*& out_store,
    void*& out_tx,
    uint8_t& out_has_snap);

  // Propagates the snapshot version/view captured during direct Rust KV access
  // back onto BaseTx so commit and receipt metadata match the C++ path.
  void finish_rust_direct_tx(
    BaseTx& tx, uint64_t snap_version, uint64_t commit_view, uint8_t has_snap);
#endif
}
