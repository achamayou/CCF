// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/kv/tx.h"
#ifdef CCF_USE_RUST_KV
#  include "kv/rust_kv_ffi.h"
#endif
#include "kv/trace.h"

namespace ccf::kv
{
  class Store;

  struct BaseTx::PrivateImpl
  {
    AbstractStore* store = nullptr;
#ifdef CCF_KV_TRACING
    trace::Attempt trace_attempt;
#endif
#ifdef CCF_USE_RUST_KV
    Store* rust_store = nullptr;
    uint64_t rust_attempt_id = 0;
    rust_ffi::NativeTx* rust_tx = nullptr;
    bool rust_read_only = false;
    std::optional<TxID> rust_reserved = std::nullopt;
    size_t rust_reserve_epoch = 0;
    bool rust_explicit_read_txid = false;
    bool rust_committing = false;
    bool rust_committed = false;
    bool rust_aborted = false;
    ~PrivateImpl();
#endif

    // NB: This exists only to maintain the old API, where this Tx stores
    // MapHandles and returns raw pointers to them. It could be removed entirely
    // with a near-identical API if we return `shared_ptr`s, and assuming that
    // we don't actually care about returning exactly the same Handle instance
    // if `rw` is called multiple times
    using PossibleHandles = std::list<std::unique_ptr<AbstractHandle>>;
    std::map<std::string, PossibleHandles> all_handles;

    // Note: read_txid version is set to NoVersion for the first transaction in
    // the service, before anything has been applied to the KV.
    std::optional<TxID> read_txid = std::nullopt;
    ccf::View commit_view = ccf::VIEW_UNKNOWN;

    std::map<std::string, std::shared_ptr<AbstractMap>> created_maps;
  };
}