// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/kv/tx.h"

#include "ds/ccf_assert.h"
#include "kv/compacted_version_conflict.h"
#include "kv/kv_types.h"
#ifdef CCF_USE_RUST_KV
#  include "kv/store.h"
#endif
#include "kv/tx_pimpl.h"
#include "kv/untyped_map.h"

#include <format>
#include <typeinfo>

namespace ccf::kv
{
#ifdef CCF_USE_RUST_KV
  BaseTx::PrivateImpl::~PrivateImpl()
  {
    if (rust_store != nullptr)
    {
      rust_store->release_tx_resources(
        rust_hazard_slot, rust_registered, rust_tx);
      rust_hazard_slot = -1;
      rust_tx = nullptr;
    }
    else if (rust_tx != nullptr)
    {
      rust_ffi::ccf_rust_kv_tx_delete(nullptr, rust_tx);
      rust_tx = nullptr;
    }
  }
#endif

  MapChanges::MapChanges(
    const std::shared_ptr<AbstractMap>& m,
    std::unique_ptr<untyped::ChangeSet>&& cs) :
    map(m),
    changeset(std::move(cs))
  {}

  // Use default destructor, but instantiate here where untyped::ChangeSet is
  // not incomplete
  MapChanges::~MapChanges() = default;

  void BaseTx::retain_change_set(
    const std::string& map_name,
    std::unique_ptr<untyped::ChangeSet>&& change_set,
    const std::shared_ptr<AbstractMap>& abstract_map)
  {
    const auto it = all_changes.find(map_name);
    if (it != all_changes.end())
    {
      throw std::logic_error(
        std::format("Re-creating change set for map {}", map_name));
    }
    all_changes.emplace_hint(
      it,
      std::piecewise_construct,
      std::forward_as_tuple(map_name),
      std::forward_as_tuple(abstract_map, std::move(change_set)));
  }

  void BaseTx::retain_handle(
    const std::string& map_name, std::unique_ptr<AbstractHandle>&& handle)
  {
    pimpl->all_handles[map_name].emplace_back(std::move(handle));
  }

  MapChanges BaseTx::get_map_and_change_set_by_name(
    const std::string& map_name, bool track_deletes_on_missing_keys)
  {
#ifdef CCF_USE_RUST_KV
    using namespace rust_ffi;
    using namespace rust_detail;
    auto& s = *pimpl;
    if (s.rust_store == nullptr)
    {
      throw std::logic_error("Transaction is not bound to a Rust KV Store");
    }
    auto& store = *s.rust_store;
    if (s.rust_committing)
    {
      throw std::logic_error("Cannot acquire a new handle after commit");
    }
    parse_map_name(map_name);

    if (track_deletes_on_missing_keys)
    {
      if (!s.read_txid.has_value())
      {
        auto p = s.store->current_txid_and_commit_term();
        s.read_txid = p.first;
        s.commit_view = p.second;
      }
      auto writes = store.diff_entries_for(s.read_txid->seqno, map_name);
      return {nullptr, std::make_unique<untyped::ChangeSet>(std::move(writes))};
    }

    const bool is_read_only = (dynamic_cast<const Tx*>(this) == nullptr);
    s.rust_read_only = is_read_only;

    if (s.rust_tx == nullptr)
    {
      s.rust_attempt_id = store.allocate_attempt_id();
      s.rust_tx = ccf_rust_kv_tx_new(s.rust_attempt_id);
    }

    // If a test subclass overrides current_txid_and_commit_term() (e.g.
    // CompactingOnReadStore), honour its hook by capturing read_txid
    // explicitly.
    const bool subclass_store = (typeid(*s.store) != typeid(Store));
    if (subclass_store && !s.read_txid.has_value() && !s.rust_reserved)
    {
      auto p = s.store->current_txid_and_commit_term();
      s.read_txid = p.first;
      s.commit_view = p.second;
      s.rust_explicit_read_txid = true;
    }

    if (!store.acquire_map_for_tx(
          s.rust_tx,
          map_name,
          s.rust_registered,
          s.rust_hazard_slot,
          s.rust_reserved,
          s.rust_explicit_read_txid,
          s.read_txid,
          s.commit_view))
    {
      return {nullptr, nullptr};
    }

    return {
      nullptr,
      std::make_unique<untyped::ChangeSet>(
        &store, s.rust_tx, &s.rust_committed, is_read_only)};
#else
    auto& read_txid = pimpl->read_txid;
#  ifdef CCF_KV_TRACING
    trace::Context trace_context(pimpl->trace_attempt.id);
#  endif

    if (!read_txid.has_value())
    {
      // Grab opacity version that all Maps should be queried at.
      // Note: It is by design that we delay acquiring a read version to now
      // rather than earlier, at Tx construction. This is to minimise the
      // window during which concurrent transactions can write to the same map
      // and cause this transaction to conflict on commit.
      auto p = pimpl->store->current_txid_and_commit_term();
      read_txid = p.first;
      pimpl->commit_view = p.second;
    }

    auto abstract_map = pimpl->store->get_map(read_txid->seqno, map_name);
    if (abstract_map == nullptr)
    {
      // Store doesn't know this map yet - create it dynamically
      {
        const auto map_it = pimpl->created_maps.find(map_name);
        if (map_it != pimpl->created_maps.end())
        {
          throw std::logic_error("Created map without creating handle over it");
        }
      }

      // NB: The created maps are always untyped. Only the handles over them
      // are typed
      auto new_map =
        std::make_shared<ccf::kv::untyped::Map>(pimpl->store, map_name);
      pimpl->created_maps[map_name] = new_map;

      abstract_map = new_map;
    }

    auto untyped_map =
      std::dynamic_pointer_cast<ccf::kv::untyped::Map>(abstract_map);
    if (untyped_map == nullptr)
    {
      throw std::logic_error(
        std::format("Map {} has unexpected type", map_name));
    }

    return {
      abstract_map,
      untyped_map->create_change_set(
        read_txid->seqno, track_deletes_on_missing_keys)};
#endif
  }

  std::list<AbstractHandle*> BaseTx::get_possible_handles(
    const std::string& map_name)
  {
    std::list<AbstractHandle*> handles;
    auto it = pimpl->all_handles.find(map_name);
    if (it != pimpl->all_handles.end())
    {
      for (auto& handle : it->second)
      {
        handles.push_back(handle.get());
      }
    }
    return handles;
  }

  void BaseTx::compacted_version_conflict(const std::string& map_name)
  {
    auto& read_txid = pimpl->read_txid;
    if (!read_txid.has_value())
    {
      throw std::logic_error(
        std::format("read_txid should have already been set"));
    }
    throw CompactedVersionConflict(std::format(
      "Unable to retrieve state over map {} at {}",
      map_name,
      read_txid->seqno));
  }

  BaseTx::BaseTx(AbstractStore* store_)
  {
    pimpl = std::make_unique<PrivateImpl>();
    pimpl->store = store_;
#ifdef CCF_USE_RUST_KV
    pimpl->rust_store = dynamic_cast<Store*>(store_);
#endif
    KV_TRACE(pimpl->trace_attempt.bind(store_));
  }

  // Use default destructor, but instantiate here where PrivateImpl is not
  // incomplete
  BaseTx::~BaseTx() = default;
}
