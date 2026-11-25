// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/kv/serialisers/serialised_entry.h"
#include "ccf/tx_id.h"
#include "kv/claims.h"
#include "kv/committable_tx.h"
#include "kv/compacted_version_conflict.h"
#include "kv/kv_serialiser.h"
#include "kv/kv_types.h"
#include "kv/ledger_chunker_interface.h"
#include "kv/test/rust_kv_ffi.h"
#include "kv/version_v.h"

#include <atomic>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <typeindex>
#include <unordered_map>
#include <utility>

namespace ccf::kv::untyped
{
  class Map;
}

namespace ccf::kv::rust_test
{
  using Bytes = serialisers::SerialisedEntry;

  inline ByteView bytes(std::string_view s)
  {
    static constexpr uint8_t EMPTY = 0;
    return {
      s.empty() ? &EMPTY : reinterpret_cast<const uint8_t*>(s.data()),
      s.size()};
  }

  inline ByteView bytes(const Bytes& b)
  {
    return {b.data(), b.size()};
  }

  inline Bytes copy(ByteView b)
  {
    if (b.data == nullptr)
    {
      throw std::logic_error("Rust KV reply is missing bytes");
    }
    if (b.size == 0)
    {
      return {};
    }
    return Bytes(b.data, b.data + b.size);
  }

  struct Response
  {
    Status status;
    uint64_t number;
    uint64_t detail;
    size_t size;
    std::unique_ptr<ReplyData, decltype(&ccf_rust_kv_reply_delete)> data;

    void require(Status expected = Status::OK) const
    {
      if (status != expected)
      {
        throw std::logic_error(
          "Unexpected Rust KV status " +
          std::to_string(static_cast<unsigned>(status)));
      }
    }

    Entry entry(size_t i) const
    {
      return ccf_rust_kv_reply_entry(data.get(), i);
    }
  };

  using MapWrites = std::map<std::string, untyped::Write, std::less<>>;

  inline MapWrites collect_writes(const Response& r)
  {
    MapWrites writes;
    auto current = writes.end();
    // Pending writes arrive sorted in descending (map, key) order; iterating
    // backwards inserts each map and key at end() in amortized O(1).
    for (size_t i = r.size; i > 0; --i)
    {
      const auto row = r.entry(i - 1);
      if (row.map.data == nullptr)
      {
        throw std::logic_error("Rust KV reply is missing map name");
      }
      const std::string_view name(
        reinterpret_cast<const char*>(row.map.data), row.map.size);
      if (current == writes.end() || current->first != name)
      {
        current = writes.lower_bound(name);
        if (current == writes.end() || current->first != name)
        {
          current =
            writes.emplace_hint(current, std::string(name), untyped::Write{});
        }
      }
      current->second.emplace_hint(
        current->second.end(),
        copy(row.key),
        row.value.data != nullptr ? std::make_optional(copy(row.value)) :
                                    std::nullopt);
    }
    return writes;
  }

  inline void serialise_writes(KvStoreSerialiser& s, const MapWrites& writes)
  {
    for (const auto domain : {SecurityDomain::PUBLIC, SecurityDomain::PRIVATE})
    {
      for (const auto& [name, rows] : writes)
      {
        if (parse_map_name(name).first == domain)
        {
          serialise_map_writes(s, name, domain, rows);
        }
      }
    }
  }

  class Tx;
  class TxDiff;
  class ReadOnlyTx;
  class ReplayEntry;

  // Concurrent Rust KV adapter. Each Tx owns its detached Rust Tx state so
  // staged writes are lock-free and reads share the Rust RwLock concurrently.
  // Lock hierarchy (strictly non-recursive, always acquired in this order):
  //   1. commit_lock     - pending_txs reorder buffer & consensus replication
  //   2. compaction_lock - compact() ordering & global hook delivery
  //   3. maps_lock       - store-wide structural barriers (lock_maps/apply/
  //                        compact/rollback/replay/snapshot)
  //   4. state_lock      - C++ metadata fields (versions, hooks, pending_txs)
  //   5. Rust RwLock     - innermost lock inside NativeStore
  class Store : public AbstractStore
  {
  public:
    class SnapshotPublicMaps
    {
      struct CapturedMap
      {
        Version revision;
        ccf::crypto::Sha256Hash digest;
        std::vector<std::pair<Bytes, VersionV<Bytes>>> rows;
      };

      friend class Store;
      Version version = NoVersion;
      std::map<std::string, CapturedMap> maps;
      SnapshotPublicMaps() = default;

    public:
      SnapshotPublicMaps(SnapshotPublicMaps&&) noexcept = default;
      SnapshotPublicMaps& operator=(SnapshotPublicMaps&&) noexcept = default;
    };

  private:
    friend class Tx;
    friend class MapAccess;
    friend class ReplayEntry;

    std::mutex commit_lock;
    std::mutex compaction_lock;
    std::mutex maps_lock;
    mutable std::mutex state_lock;
    std::unique_ptr<NativeStore, decltype(&ccf_rust_kv_delete)> native{
      ccf_rust_kv_new(0), &ccf_rust_kv_delete};
    std::atomic<uint64_t> next_attempt{0};
    Version head = 0;
    std::set<Version> open_reservations;
    Version last_replicated = 0;
    Version global = 0;
    View term = 0;
    View last_view = 0;
    size_t rollback_count = 0;
    Version last_committable = NoVersion;
    EncryptorPtr encryptor;
    std::shared_ptr<Consensus> consensus;
    std::shared_ptr<TxHistory> history;
    size_t max_entry_size = max_serialised_entry_size;
    std::atomic<bool> snapshot_requested{false};
    std::shared_ptr<ILedgerChunker> chunker;
    SnapshotterPtr snapshotter;
    std::unordered_map<Version, std::tuple<std::unique_ptr<PendingTx>, bool>>
      pending_txs;
    std::map<std::string, untyped::MapHook> local_hooks;
    std::map<std::string, untyped::CommitHook> global_hooks;

    struct MapDelta
    {
      untyped::Write writes;
      bool delivered = false;
    };

    std::map<std::string, std::map<Version, MapDelta>> map_deltas;

    static Response wrap_reply(Reply reply)
    {
      return {
        reply.status,
        reply.number,
        reply.detail,
        reply.size,
        {reply.data, &ccf_rust_kv_reply_delete}};
    }

    Response dispatch(Request request) const
    {
      return wrap_reply(ccf_rust_kv_execute(native.get(), request));
    }

    std::optional<Version> map_revision_at(
      Version version, const std::string& name) const
    {
      auto r = dispatch(
        {.op = Opcode::MAP_REVISION, .number = version, .map = bytes(name)});
      if (r.status == Status::MISSING)
      {
        return std::nullopt;
      }
      r.require();
      return r.number;
    }

    // Called under state_lock immediately after APPLY. Records map_deltas
    // atomically with version publication and returns matching local hooks so
    // callers can invoke them outside locks if needed.
    ConsensusHookPtrs record_commit_locked(
      Version version, const MapWrites& maps)
    {
      ConsensusHookPtrs hooks;
      for (const auto& [name, writes] : maps)
      {
        if (auto it = local_hooks.find(name);
            it != local_hooks.end() && it->second)
        {
          if (auto hook = it->second(version, writes); hook != nullptr)
          {
            hooks.push_back(std::move(hook));
          }
        }
        // Any put advances the map revision to `version`; only an all-delete
        // batch on missing keys can publish without bumping the revision.
        bool has_put = false;
        for (const auto& [_, value] : writes)
        {
          if (value.has_value())
          {
            has_put = true;
            break;
          }
        }
        if (has_put || map_revision_at(version, name) == version)
        {
          map_deltas[name].emplace(version, MapDelta{writes});
        }
      }
      return hooks;
    }

    ApplyResult deserialise_snapshot_internal(
      const uint8_t* data,
      size_t size,
      uint8_t* writable,
      ConsensusHookPtrs& hooks,
      std::vector<Version>* view_history,
      bool public_only,
      std::optional<SnapshotPublicMaps>* capture,
      const SnapshotPublicMaps* reuse);

    bool should_create_ledger_chunk_locked(Version version)
    {
      const bool chunk = chunker && chunker->is_chunk_end_requested(version);
      const bool snapshot = snapshotter ?
        snapshotter->record_committable(version) :
        snapshot_requested.load(std::memory_order_acquire);
      return chunk || snapshot;
    }

    bool mark_reserved_chunk_locked(Version version)
    {
      const auto mark = should_create_ledger_chunk_locked(version);
      if (mark && chunker)
      {
        chunker->produced_chunk_at(version);
      }
      return mark;
    }

    void apply_tx_flags_locked(Version version, bool force_chunk, bool snapshot)
    {
      if (force_chunk && chunker)
      {
        chunker->force_end_of_chunk(version);
      }
      if (snapshot)
      {
        snapshot_requested.store(true, std::memory_order_release);
      }
    }

  public:
    Store() = default;
    Store(const Store&) = delete;
    Store& operator=(const Store&) = delete;

    Tx create_tx();
    Tx create_reserved_tx(const TxID& version);
    CommitResult commit(
      const TxID& id,
      std::unique_ptr<PendingTx> entry,
      bool committable) override;
    TxDiff create_tx_diff();
    ReadOnlyTx create_read_only_tx();
    std::unique_ptr<AbstractExecutionWrapper> deserialize(
      const std::vector<uint8_t>& data,
      bool public_only = false,
      const std::optional<TxID>& expected_txid = std::nullopt) override;
    std::unique_ptr<AbstractStore::AbstractSnapshot> snapshot_unsafe_maps(
      Version version) override;
    std::unique_ptr<AbstractStore::AbstractSnapshot> snapshot_maps(
      Version version);
    void swap_private_maps(Store& source);
    std::vector<uint8_t> serialise_snapshot(
      std::unique_ptr<AbstractStore::AbstractSnapshot> snapshot) override;
    ApplyResult deserialise_snapshot(
      const uint8_t* data,
      size_t size,
      ConsensusHookPtrs& hooks,
      std::vector<Version>* view_history = nullptr,
      bool public_only = false) override;
    ApplyResult deserialise_snapshot_in_place(
      std::span<uint8_t> data,
      ConsensusHookPtrs& hooks,
      std::vector<Version>* view_history = nullptr,
      const SnapshotPublicMaps* public_maps = nullptr);
    ApplyResult deserialise_public_snapshot_capturing(
      const uint8_t* data,
      size_t size,
      ConsensusHookPtrs& hooks,
      std::vector<Version>* view_history,
      std::optional<SnapshotPublicMaps>& captured);

    void lock_map_set() override
    {
      maps_lock.lock();
    }

    void unlock_map_set() override
    {
      maps_lock.unlock();
    }

    void lock_maps() override
    {
      maps_lock.lock();
    }

    void unlock_maps() override
    {
      maps_lock.unlock();
    }

    std::shared_ptr<AbstractMap> get_map(
      Version /*v*/, const std::string& /*map_name*/) override
    {
      throw std::logic_error(
        "Rust KV store does not expose C++ AbstractMap handles");
    }

    std::shared_ptr<AbstractMap> get_map_unsafe(
      Version /*v*/, const std::string& /*map_name*/) override
    {
      throw std::logic_error(
        "Rust KV store does not expose C++ AbstractMap handles");
    }

    void add_dynamic_map(
      Version /*v*/, const std::shared_ptr<AbstractMap>& /*map*/) override
    {
      throw std::logic_error(
        "Rust KV store does not expose C++ AbstractMap handles");
    }

    std::shared_ptr<Consensus> get_consensus() override
    {
      std::lock_guard lock(state_lock);
      return consensus;
    }

    std::shared_ptr<TxHistory> get_history() override
    {
      std::lock_guard lock(state_lock);
      return history;
    }

    std::shared_ptr<ILedgerChunker> get_chunker() override
    {
      std::lock_guard lock(state_lock);
      return chunker;
    }

    EncryptorPtr get_encryptor() override
    {
      std::lock_guard lock(state_lock);
      return encryptor;
    }

    Version current_version() override
    {
      std::lock_guard lock(state_lock);
      return head;
    }

    Version compacted_version() override
    {
      std::lock_guard lock(state_lock);
      return global;
    }

    View commit_view() override
    {
      std::lock_guard lock(state_lock);
      return term;
    }

    TxID current_txid() override
    {
      std::lock_guard lock(state_lock);
      return {last_view, head};
    }

    std::pair<TxID, Term> current_txid_and_commit_term() override
    {
      std::lock_guard lock(state_lock);
      return {{last_view, head}, term};
    }

    std::optional<std::tuple<Version, Version>> next_version(
      Term expected_commit_term) override
    {
      std::scoped_lock lock(maps_lock, state_lock);
      if (term != expected_commit_term)
      {
        return std::nullopt;
      }
      auto r = wrap_reply(ccf_rust_kv_reserve_version(native.get()));
      if (r.status == Status::EXHAUSTED)
      {
        throw std::overflow_error("Rust KV test version counter exhausted");
      }
      r.require();
      head = r.number;
      last_view = term;
      open_reservations.insert(head);
      return std::make_tuple(head, rollback_count);
    }

    void initialise_term(View view) override
    {
      std::lock_guard lock(state_lock);
      if (term != 0)
      {
        throw std::logic_error("Commit term is already initialised");
      }
      dispatch({.op = Opcode::SET_TERM, .number = view}).require();
      term = view;
      if (history)
      {
        history->set_term(view);
      }
    }

    void set_encryptor(const EncryptorPtr& e)
    {
      std::lock_guard lock(state_lock);
      encryptor = e;
    }

    void set_consensus(const std::shared_ptr<Consensus>& c)
    {
      std::lock_guard lock(state_lock);
      consensus = c;
    }

    void set_history(const std::shared_ptr<TxHistory>& h)
    {
      std::lock_guard lock(state_lock);
      history = h;
    }

    void set_chunker(const std::shared_ptr<ILedgerChunker>& c)
    {
      std::lock_guard lock(state_lock);
      chunker = c;
    }

    void set_snapshotter(const SnapshotterPtr& s)
    {
      std::lock_guard lock(state_lock);
      snapshotter = s;
    }

    bool flag_enabled(AbstractStore::StoreFlag flag) override
    {
      return flag_enabled_unsafe(flag);
    }

    bool flag_enabled_unsafe(AbstractStore::StoreFlag flag) const override
    {
      return flag == AbstractStore::StoreFlag::SNAPSHOT_AT_NEXT_SIGNATURE &&
        snapshot_requested.load(std::memory_order_acquire);
    }

    void set_flag(AbstractStore::StoreFlag flag) override
    {
      set_flag_unsafe(flag);
    }

    void set_flag_unsafe(AbstractStore::StoreFlag flag) override
    {
      if (flag == AbstractStore::StoreFlag::SNAPSHOT_AT_NEXT_SIGNATURE)
      {
        snapshot_requested.store(true, std::memory_order_release);
      }
    }

    void unset_flag_unsafe(AbstractStore::StoreFlag flag) override
    {
      if (flag == AbstractStore::StoreFlag::SNAPSHOT_AT_NEXT_SIGNATURE)
      {
        snapshot_requested.store(false, std::memory_order_release);
      }
    }

    bool apply_tx_flags(
      Version version,
      View expected_term,
      Version expected_rollback_count,
      bool force_chunk,
      bool snapshot) override
    {
      std::lock_guard lock(state_lock);
      if (term != expected_term || rollback_count != expected_rollback_count)
      {
        return false;
      }
      apply_tx_flags_locked(version, force_chunk, snapshot);
      return true;
    }

    std::optional<bool> should_create_ledger_chunk_for_reserved_tx(
      Version version,
      View expected_term,
      Version expected_rollback_count) override
    {
      std::lock_guard lock(state_lock);
      if (term != expected_term || rollback_count != expected_rollback_count)
      {
        return std::nullopt;
      }
      return mark_reserved_chunk_locked(version);
    }

    bool should_create_ledger_chunk(Version version) override
    {
      std::lock_guard lock(state_lock);
      return should_create_ledger_chunk_locked(version);
    }

    bool should_create_ledger_chunk_unsafe(Version version) override
    {
      return should_create_ledger_chunk_locked(version);
    }

    TxID next_txid() override
    {
      std::scoped_lock lock(maps_lock, state_lock);
      auto r = wrap_reply(ccf_rust_kv_reserve_version(native.get()));
      if (r.status == Status::EXHAUSTED)
      {
        throw std::overflow_error("Rust KV test version counter exhausted");
      }
      r.require();
      head = r.number;
      last_view = term;
      open_reservations.insert(head);
      return {term, head};
    }

    void set_max_transaction_size(size_t limit)
    {
      if (
        limit >
        std::min(max_serialised_entry_size, std::vector<uint8_t>().max_size()))
      {
        throw std::logic_error("Maximum transaction size is not representable");
      }
      std::lock_guard lock(state_lock);
      max_entry_size = limit;
    }

    size_t get_max_transaction_size() const override
    {
      std::lock_guard lock(state_lock);
      return max_entry_size;
    }

    bool has_map_at(Version version, const std::string& name)
    {
      return map_revision_at(version, name).has_value();
    }

    bool check_rollback_count(Version expected) override
    {
      std::lock_guard lock(state_lock);
      return rollback_count == expected;
    }

    size_t committable_gap() override
    {
      std::lock_guard lock(state_lock);
      return head - last_committable;
    }

    void clear()
    {
      std::scoped_lock lock(
        commit_lock, compaction_lock, maps_lock, state_lock);
      dispatch({.op = Opcode::CLEAR_STORE}).require();
      head = NoVersion;
      global = NoVersion;
      open_reservations.clear();
      last_replicated = NoVersion;
      last_committable = NoVersion;
      term = 0;
      last_view = 0;
      ++rollback_count;
      snapshot_requested.store(false, std::memory_order_release);
      pending_txs.clear();
      map_deltas.clear();
    }

    void set_map_hook(const std::string& name, untyped::MapHook hook)
    {
      std::lock_guard lock(state_lock);
      local_hooks.insert_or_assign(name, std::move(hook));
    }

    void unset_map_hook(const std::string& name)
    {
      std::lock_guard lock(state_lock);
      local_hooks.erase(name);
    }

    void set_global_hook(const std::string& name, untyped::CommitHook hook)
    {
      std::lock_guard lock(state_lock);
      global_hooks.insert_or_assign(name, std::move(hook));
    }

    void unset_global_hook(const std::string& name)
    {
      std::lock_guard lock(state_lock);
      global_hooks.erase(name);
    }

    void compact(Version v) override
    {
      std::lock_guard ordered(compaction_lock);
      std::vector<std::tuple<untyped::CommitHook, Version, untyped::Write>>
        callbacks;
      {
        std::scoped_lock lock(maps_lock, state_lock);
        if (chunker)
        {
          chunker->compacted_to(v);
        }
        if (snapshotter)
        {
          snapshotter->commit(v, consensus && consensus->is_primary());
        }
        const auto compact_target = open_reservations.empty() ?
          v :
          std::min(v, *open_reservations.begin() - 1);
        auto r = dispatch({.op = Opcode::COMPACT, .number = compact_target});
        r.require();
        global = r.number;
        if (compact_target > head || compact_target < global)
        {
          return;
        }
        if (history)
        {
          history->compact(global);
        }
        for (auto& [name, changes] : map_deltas)
        {
          auto end = changes.upper_bound(global);
          if (end == changes.begin())
          {
            continue;
          }
          const auto hook = global_hooks.find(name);
          if (hook != global_hooks.end() && hook->second)
          {
            for (auto it = changes.begin(); it != end; ++it)
            {
              if (!it->second.delivered)
              {
                callbacks.emplace_back(
                  hook->second, it->first, it->second.writes);
                it->second.delivered = true;
                std::erase_if(it->second.writes, [](const auto& row) {
                  return !row.second.has_value();
                });
              }
            }
          }
          changes.erase(changes.begin(), std::prev(end));
        }
      }
      for (const auto& [hook, version, writes] : callbacks)
      {
        hook(version, writes);
      }
    }

    void rollback(const TxID& txid, View new_term) override
    {
      std::scoped_lock lock(maps_lock, state_lock);
      auto r = dispatch(
        {.op = Opcode::ROLLBACK, .attempt = new_term, .number = txid.seqno});
      if (r.status == Status::ROLLBACK_REJECTED)
      {
        throw std::logic_error("Cannot roll back compacted Rust KV history");
      }
      r.require();
      const auto old_head = head;
      head = r.number;
      open_reservations.erase(
        open_reservations.upper_bound(head), open_reservations.end());
      term = new_term;
      last_view = txid.view;
      if (history)
      {
        history->rollback(txid, new_term);
      }
      if (head < old_head)
      {
        ++rollback_count;
        last_replicated = head;
        last_committable = std::min(last_committable, head);
        snapshot_requested.store(false, std::memory_order_release);
        if (encryptor != nullptr)
        {
          encryptor->rollback(head);
        }
        pending_txs.clear();
      }
      if (chunker)
      {
        chunker->rolled_back_to(std::min(txid.seqno, old_head));
      }
      if (snapshotter)
      {
        snapshotter->rollback(txid.seqno);
      }
      for (auto& [_, changes] : map_deltas)
      {
        changes.erase(changes.upper_bound(head), changes.end());
      }
    }
  };

  template <typename M>
  struct MapTypes
  {
    using Key = typename M::Key;
    using Value = typename M::Value;
    using Keys = typename M::KeySerialiser;
    using Values = typename M::ValueSerialiser;
  };

  template <>
  struct MapTypes<untyped::Map>
  {
    struct Identity
    {
      static const Bytes& to_serialised(const Bytes& b)
      {
        return b;
      }

      static const Bytes& from_serialised(const Bytes& b)
      {
        return b;
      }
    };

    using Key = Bytes;
    using Value = Bytes;
    using Keys = Identity;
    using Values = Identity;
  };

  struct HandleBase
  {
    virtual ~HandleBase() = default;
  };

  class MapAccess : public HandleBase
  {
    Store& store;
    NativeTx* native_tx;
    std::string name;
    const bool& committed;

  public:
    MapAccess(
      Store& store_,
      NativeTx* native_tx_,
      const std::string& name_,
      const bool& committed_) :
      store(store_),
      native_tx(native_tx_),
      name(name_),
      committed(committed_)
    {}

    void write(ByteView key, ByteView value = {})
    {
      if (committed)
      {
        throw std::logic_error("Unexpected Rust KV status 1");
      }
      const auto status =
        ccf_rust_kv_tx_write(native_tx, bytes(name), key, value);
      if (status != Status::OK)
      {
        throw std::logic_error(
          "Unexpected Rust KV status " +
          std::to_string(static_cast<unsigned>(status)));
      }
    }

    Response operate(
      Opcode op, ByteView key = {}, ByteView value = {}, bool global = false)
    {
      return Store::wrap_reply(ccf_rust_kv_tx_operate(
        store.native.get(),
        native_tx,
        {.op = op,
         .inspect_finished = committed,
         .attempt = 0,
         .number = global,
         .map = bytes(name),
         .key = key,
         .value = value}));
    }
  };

  template <typename M>
  class ReadHandle
  {
    using Key = typename MapTypes<M>::Key;
    using Value = typename MapTypes<M>::Value;
    using Keys = typename MapTypes<M>::Keys;
    using Values = typename MapTypes<M>::Values;

    MapAccess& access;

    std::optional<Value> get_at(const Key& key, bool global)
    {
      auto r = access.operate(
        Opcode::GET, bytes(Keys::to_serialised(key)), {}, global);
      if (r.status == Status::MISSING)
      {
        return std::nullopt;
      }
      r.require();
      return Values::from_serialised(copy(r.entry(0).value));
    }

    bool has_at(const Key& key, bool global)
    {
      auto r = access.operate(
        Opcode::HAS, bytes(Keys::to_serialised(key)), {}, global);
      r.require();
      return r.number != 0;
    }

  public:
    explicit ReadHandle(MapAccess& access_) : access(access_) {}

    std::optional<Value> get(const Key& key)
    {
      return get_at(key, false);
    }

    std::optional<Value> get_globally_committed(const Key& key)
    {
      return get_at(key, true);
    }

    bool has(const Key& key)
    {
      return has_at(key, false);
    }

    bool has_globally_committed(const Key& key)
    {
      return has_at(key, true);
    }

    std::optional<Version> get_version_of_previous_write(const Key& key)
    {
      auto r =
        access.operate(Opcode::PREVIOUS, bytes(Keys::to_serialised(key)));
      if (r.status == Status::MISSING)
      {
        return std::nullopt;
      }
      r.require();
      return r.number;
    }

    size_t size()
    {
      auto r = access.operate(Opcode::SIZE);
      r.require();
      return r.size;
    }

    template <typename F>
    void foreach_raw(F&& f)
    {
      auto r = access.operate(Opcode::SCAN);
      r.require();
      // The Rust reply owns the scan image, even if f modifies this map.
      for (size_t i = 0; i < r.size; ++i)
      {
        const auto row = r.entry(i);
        if (!f(row))
        {
          break;
        }
      }
    }

    template <typename F>
    void foreach(F&& f)
    {
      foreach_raw([&](const Entry& row) {
        return f(
          Keys::from_serialised(copy(row.key)),
          Values::from_serialised(copy(row.value)));
      });
    }

    template <typename F>
    void foreach_key(F&& f)
    {
      foreach_raw([&](const Entry& row) {
        return f(Keys::from_serialised(copy(row.key)));
      });
    }

    template <typename F>
    void foreach_value(F&& f)
    {
      foreach_raw([&](const Entry& row) {
        return f(Values::from_serialised(copy(row.value)));
      });
    }

    template <typename F>
    void range(
      F&& f, const std::optional<Key>& lower, const std::optional<Key>& upper)
    {
      auto run = [&](ByteView from, ByteView to) {
        auto r = access.operate(Opcode::RANGE, from, to);
        r.require();
        for (size_t i = 0; i < r.size; ++i)
        {
          const auto row = r.entry(i);
          f(Keys::from_serialised(copy(row.key)),
            Values::from_serialised(copy(row.value)));
        }
      };
      if (lower && upper)
      {
        const auto& from = Keys::to_serialised(*lower);
        const auto& to = Keys::to_serialised(*upper);
        run(bytes(from), bytes(to));
      }
      else if (lower)
      {
        const auto& from = Keys::to_serialised(*lower);
        run(bytes(from), ByteView{});
      }
      else if (upper)
      {
        const auto& to = Keys::to_serialised(*upper);
        run(ByteView{}, bytes(to));
      }
      else
      {
        run(ByteView{}, ByteView{});
      }
    }
  };

  template <typename M>
  class WriteHandle
  {
    using Key = typename MapTypes<M>::Key;
    using Value = typename MapTypes<M>::Value;
    using Keys = typename MapTypes<M>::Keys;
    using Values = typename MapTypes<M>::Values;

    MapAccess& access;

  public:
    explicit WriteHandle(MapAccess& access_) : access(access_) {}

    void put(const Key& key, const Value& value)
    {
      access.write(
        bytes(Keys::to_serialised(key)), bytes(Values::to_serialised(value)));
    }

    void remove(const Key& key)
    {
      access.write(bytes(Keys::to_serialised(key)));
    }

    void clear()
    {
      access.operate(Opcode::CLEAR).require();
    }
  };

  template <typename M>
  class Handle : public MapAccess, public ReadHandle<M>, public WriteHandle<M>
  {
  public:
    Handle(
      Store& store,
      NativeTx* native_tx,
      const std::string& name,
      const bool& committed) :
      MapAccess(store, native_tx, name, committed),
      ReadHandle<M>(static_cast<MapAccess&>(*this)),
      WriteHandle<M>(static_cast<MapAccess&>(*this))
    {}
  };

  template <typename M>
  struct HandleFamily
  {
    using Full = Handle<M>;
    using Read = ReadHandle<M>;
    using Write = WriteHandle<M>;
  };

  class Tx
  {
    friend class Store;

    struct HandleSlot
    {
      std::string name;
      std::type_index type;
      std::unique_ptr<HandleBase> handle;
    };

    struct State
    {
      Store& store;
      uint64_t id;
      NativeTx* native_tx;
      std::vector<HandleSlot> handles;
      std::optional<View> captured_term;
      std::optional<TxID> read_txid;
      std::optional<TxID> reserved;
      size_t reserve_epoch = 0;
      bool committing = false;
      bool committed = false;
      bool aborted = false;
      std::optional<Version> version;
      CommittableTx::TxFlags flags = 0;

      State(Store& store_, uint64_t id_) :
        store(store_),
        id(id_),
        native_tx(ccf_rust_kv_tx_new(id_))
      {}

      ~State()
      {
        ccf_rust_kv_tx_delete(store.native.get(), native_tx);
      }
    };

    std::unique_ptr<State> state;

    PendingTxInfo commit_impl(
      const ClaimsDigest& claims,
      const CommittableTx::WriteSetObserver& observer,
      bool reserved);

  public:
    Tx(Store& store, uint64_t id) : state(std::make_unique<State>(store, id)) {}

    template <typename M>
    typename HandleFamily<M>::Full* rw(const std::string& name)
    {
      auto& s = *state;
      using Full = typename HandleFamily<M>::Full;
      const auto type = std::type_index(typeid(Full));
      bool map_acquired = false;
      for (const auto& slot : s.handles)
      {
        if (slot.name == name)
        {
          map_acquired = true;
          if (slot.type == type)
          {
            if (s.committing && !s.committed)
            {
              throw std::logic_error("Transaction did not commit successfully");
            }
            return static_cast<Full*>(slot.handle.get());
          }
        }
      }
      if (s.committing)
      {
        throw std::logic_error("Cannot acquire a new handle after commit");
      }
      parse_map_name(name);
      // Typed and untyped handles share the single native acquisition.
      if (!map_acquired)
      {
        std::lock_guard lock(s.store.state_lock);
        auto r = Store::wrap_reply(ccf_rust_kv_tx_snapshot_and_acquire(
          s.store.native.get(),
          s.native_tx,
          bytes(name),
          s.reserved.has_value(),
          s.reserved ? s.reserved->seqno - 1 : 0));
        if (r.status == Status::UNAVAILABLE)
        {
          throw CompactedVersionConflict(
            "Cannot acquire a compacted Rust KV map: " + name);
        }
        r.require();
        if (!s.captured_term.has_value())
        {
          s.captured_term = r.detail;
          s.read_txid = TxID{s.store.last_view, r.number};
        }
      }
      auto handle =
        std::make_unique<Full>(s.store, s.native_tx, name, s.committed);
      auto* raw = handle.get();
      s.handles.push_back({name, type, std::move(handle)});
      return raw;
    }

    template <typename M>
    typename HandleFamily<M>::Full* rw(const M& map)
    {
      return rw<M>(map.get_name());
    }

    template <typename M>
    typename HandleFamily<M>::Read* ro(const M& map)
    {
      return rw(map);
    }

    template <typename M>
    typename HandleFamily<M>::Read* ro(const std::string& name)
    {
      return rw<M>(name);
    }

    template <typename M>
    typename HandleFamily<M>::Write* wo(const M& map)
    {
      return rw(map);
    }

    template <typename M>
    typename HandleFamily<M>::Write* wo(const std::string& name)
    {
      return rw<M>(name);
    }

    CommitResult commit(
      const ClaimsDigest& claims = empty_claims(),
      const CommittableTx::WriteSetObserver& observer = nullptr);
    PendingTxInfo commit_reserved();

    void set_tx_flag(CommittableTx::TxFlag flag)
    {
      state->flags |= static_cast<CommittableTx::TxFlags>(flag);
    }

    void unset_tx_flag(CommittableTx::TxFlag flag)
    {
      state->flags &= ~static_cast<CommittableTx::TxFlags>(flag);
    }

    bool tx_flag_enabled(CommittableTx::TxFlag flag) const
    {
      return (state->flags & static_cast<CommittableTx::TxFlags>(flag)) != 0;
    }

    Version commit_version() const
    {
      if (!state->version.has_value())
      {
        throw std::logic_error("Transaction not yet committed");
      }
      if (state->aborted)
      {
        throw std::logic_error("Transaction aborted");
      }
      return *state->version;
    }

    View commit_term() const
    {
      static_cast<void>(commit_version());
      return state->captured_term.value_or(0);
    }

    std::optional<TxID> get_txid() const
    {
      const auto version = commit_version();
      if (version == NoVersion || !state->read_txid.has_value())
      {
        return state->read_txid;
      }
      return TxID{state->captured_term.value(), version};
    }
  };

  class ReadOnlyTx
  {
    Tx tx;

  public:
    explicit ReadOnlyTx(Tx&& tx_) : tx(std::move(tx_)) {}

    template <typename M>
    typename HandleFamily<M>::Read* ro(const M& map)
    {
      return tx.ro(map);
    }

    template <typename M>
    typename HandleFamily<M>::Read* ro(const std::string& name)
    {
      return tx.ro<M>(name);
    }
  };

  inline Tx Store::create_tx()
  {
    const auto previous = next_attempt.fetch_add(1, std::memory_order_relaxed);
    if (previous == std::numeric_limits<uint64_t>::max())
    {
      throw std::overflow_error("Rust KV test attempt counter exhausted");
    }
    return Tx(*this, previous + 1);
  }

  inline ReadOnlyTx Store::create_read_only_tx()
  {
    return ReadOnlyTx(create_tx());
  }
}
