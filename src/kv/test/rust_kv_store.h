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

#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <typeindex>
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
    untyped::Write::iterator hint;
    for (size_t i = 0; i < r.size; ++i)
    {
      const auto row = r.entry(i);
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
        hint = current->second.end();
      }
      hint = current->second.emplace_hint(
        hint,
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

  // The test facade serializes access to the Rust store. Each Tx and its
  // handles must still be used by a single thread.
  class Store
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
    friend class ReplayEntry;

    mutable std::mutex mutex;
    std::mutex commit_order;
    std::mutex compaction_order;
    std::unique_ptr<NativeStore, decltype(&ccf_rust_kv_delete)> native{
      ccf_rust_kv_new(0), &ccf_rust_kv_delete};
    uint64_t next_attempt = 0;
    Version head = 0;
    Version reserved_through = 0;
    Version global = 0;
    View term = 0;
    View last_view = 0;
    size_t rollback_count = 0;
    Version last_committable = NoVersion;
    EncryptorPtr encryptor;
    std::shared_ptr<Consensus> consensus;
    std::shared_ptr<TxHistory> history;
    size_t max_entry_size = max_serialised_entry_size;
    bool snapshot_requested = false;
    std::shared_ptr<ILedgerChunker> chunker;
    SnapshotterPtr snapshotter;
    std::map<Version, std::pair<View, size_t>> reserved_entries;
    std::map<std::string, untyped::MapHook> local_hooks;
    std::map<std::string, untyped::CommitHook> global_hooks;

    struct MapDelta
    {
      untyped::Write writes;
      bool delivered = false;
    };

    std::map<std::string, std::map<Version, MapDelta>> map_deltas;

    Response dispatch(Request request)
    {
      const auto reply = ccf_rust_kv_execute(native.get(), request);
      return {
        reply.status,
        reply.number,
        reply.detail,
        reply.size,
        {reply.data, &ccf_rust_kv_reply_delete}};
    }

    std::optional<Version> map_revision_at(
      Version version, const std::string& name)
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

    ConsensusHookPtrs record_commit(Version version, const MapWrites& maps)
    {
      ConsensusHookPtrs hooks;
      for (const auto& [name, writes] : maps)
      {
        // A deletion of a missing key can publish without a map revision.
        if (map_revision_at(version, name) == version)
        {
          map_deltas[name].emplace(version, MapDelta{writes});
        }
        if (auto it = local_hooks.find(name);
            it != local_hooks.end() && it->second)
        {
          if (auto hook = it->second(version, writes); hook != nullptr)
          {
            hooks.push_back(std::move(hook));
          }
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
        snapshot_requested;
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
        snapshot_requested = true;
      }
    }

  public:
    Store() = default;
    Store(const Store&) = delete;
    Store& operator=(const Store&) = delete;

    Tx create_tx();
    Tx create_reserved_tx(const TxID& version);
    CommitResult commit(
      const TxID& id, std::unique_ptr<PendingTx> entry, bool committable);
    TxDiff create_tx_diff();
    ReadOnlyTx create_read_only_tx();
    std::unique_ptr<AbstractExecutionWrapper> deserialize(
      const std::vector<uint8_t>& data,
      bool public_only = false,
      const std::optional<TxID>& expected_txid = std::nullopt);
    std::unique_ptr<AbstractStore::AbstractSnapshot> snapshot_maps(
      Version version);
    void swap_private_maps(Store& source);
    std::vector<uint8_t> serialise_snapshot(
      std::unique_ptr<AbstractStore::AbstractSnapshot> snapshot);
    ApplyResult deserialise_snapshot(
      const uint8_t* data,
      size_t size,
      ConsensusHookPtrs& hooks,
      std::vector<Version>* view_history = nullptr,
      bool public_only = false);
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

    Version current_version() const
    {
      std::lock_guard lock(mutex);
      return std::max(head, reserved_through);
    }

    Version compacted_version() const
    {
      std::lock_guard lock(mutex);
      return global;
    }

    View commit_view() const
    {
      std::lock_guard lock(mutex);
      return term;
    }

    TxID current_txid() const
    {
      std::lock_guard lock(mutex);
      return {last_view, std::max(head, reserved_through)};
    }

    void initialise_term(View view)
    {
      std::lock_guard lock(mutex);
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
      std::lock_guard lock(mutex);
      encryptor = e;
    }

    void set_consensus(const std::shared_ptr<Consensus>& c)
    {
      std::lock_guard lock(mutex);
      consensus = c;
    }

    void set_history(const std::shared_ptr<TxHistory>& h)
    {
      std::lock_guard lock(mutex);
      history = h;
    }

    void set_chunker(const std::shared_ptr<ILedgerChunker>& c)
    {
      std::lock_guard lock(mutex);
      chunker = c;
    }

    void set_snapshotter(const SnapshotterPtr& s)
    {
      std::lock_guard lock(mutex);
      snapshotter = s;
    }

    bool flag_enabled(AbstractStore::StoreFlag flag) const
    {
      std::lock_guard lock(mutex);
      return flag == AbstractStore::StoreFlag::SNAPSHOT_AT_NEXT_SIGNATURE &&
        snapshot_requested;
    }

    void set_flag(AbstractStore::StoreFlag flag)
    {
      std::lock_guard lock(mutex);
      if (flag == AbstractStore::StoreFlag::SNAPSHOT_AT_NEXT_SIGNATURE)
      {
        snapshot_requested = true;
      }
    }

    bool apply_tx_flags(
      Version version,
      View expected_term,
      Version expected_rollback_count,
      bool force_chunk,
      bool snapshot)
    {
      std::lock_guard lock(mutex);
      if (term != expected_term || rollback_count != expected_rollback_count)
      {
        return false;
      }
      apply_tx_flags_locked(version, force_chunk, snapshot);
      return true;
    }

    std::optional<bool> should_create_ledger_chunk_for_reserved_tx(
      Version version, View expected_term, Version expected_rollback_count)
    {
      std::lock_guard lock(mutex);
      if (term != expected_term || rollback_count != expected_rollback_count)
      {
        return std::nullopt;
      }
      return mark_reserved_chunk_locked(version);
    }

    bool should_create_ledger_chunk(Version version)
    {
      std::lock_guard lock(mutex);
      return should_create_ledger_chunk_locked(version);
    }

    TxID next_txid()
    {
      std::lock_guard lock(mutex);
      const auto current = std::max(head, reserved_through);
      if (current == std::numeric_limits<Version>::max())
      {
        throw std::overflow_error("Rust KV test version counter exhausted");
      }
      reserved_through = current + 1;
      last_view = term;
      return {term, reserved_through};
    }

    void set_max_transaction_size(size_t limit)
    {
      if (
        limit >
        std::min(max_serialised_entry_size, std::vector<uint8_t>().max_size()))
      {
        throw std::logic_error("Maximum transaction size is not representable");
      }
      std::lock_guard lock(mutex);
      max_entry_size = limit;
    }

    size_t get_max_transaction_size() const
    {
      std::lock_guard lock(mutex);
      return max_entry_size;
    }

    bool has_map_at(Version version, const std::string& name)
    {
      std::lock_guard lock(mutex);
      return map_revision_at(version, name).has_value();
    }

    bool check_rollback_count(size_t expected) const
    {
      std::lock_guard lock(mutex);
      return rollback_count == expected;
    }

    Version committable_gap() const
    {
      std::lock_guard lock(mutex);
      return std::max(head, reserved_through) - last_committable;
    }

    void clear()
    {
      std::lock_guard ordered(commit_order);
      std::lock_guard lock(mutex);
      dispatch({.op = Opcode::CLEAR_STORE}).require();
      head = NoVersion;
      global = NoVersion;
      reserved_through = NoVersion;
      last_committable = NoVersion;
      term = 0;
      last_view = 0;
      ++rollback_count;
      snapshot_requested = false;
      reserved_entries.clear();
      map_deltas.clear();
    }

    void set_map_hook(const std::string& name, untyped::MapHook hook)
    {
      std::lock_guard lock(mutex);
      local_hooks.insert_or_assign(name, std::move(hook));
    }

    void unset_map_hook(const std::string& name)
    {
      std::lock_guard lock(mutex);
      local_hooks.erase(name);
    }

    void set_global_hook(const std::string& name, untyped::CommitHook hook)
    {
      std::lock_guard lock(mutex);
      global_hooks.insert_or_assign(name, std::move(hook));
    }

    void unset_global_hook(const std::string& name)
    {
      std::lock_guard lock(mutex);
      global_hooks.erase(name);
    }

    void compact(Version v)
    {
      std::lock_guard ordered(compaction_order);
      std::unique_lock lock(mutex);
      if (chunker)
      {
        chunker->compacted_to(v);
      }
      if (snapshotter)
      {
        snapshotter->commit(v, consensus && consensus->is_primary());
      }
      auto r = dispatch({.op = Opcode::COMPACT, .number = v});
      r.require();
      global = r.number;
      if (v > head || v < global)
      {
        return;
      }
      if (history)
      {
        history->compact(global);
      }
      std::vector<std::tuple<untyped::CommitHook, Version, untyped::Write>>
        callbacks;
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
      lock.unlock();
      for (const auto& [hook, version, writes] : callbacks)
      {
        hook(version, writes);
      }
    }

    void rollback(TxID txid, View new_term)
    {
      std::lock_guard lock(mutex);
      auto r = dispatch(
        {.op = Opcode::ROLLBACK, .attempt = new_term, .number = txid.seqno});
      if (r.status == Status::ROLLBACK_REJECTED)
      {
        throw std::logic_error("Cannot roll back compacted Rust KV history");
      }
      r.require();
      const auto old_head = std::max(head, reserved_through);
      head = r.number;
      reserved_through = std::min(reserved_through, txid.seqno);
      term = new_term;
      last_view = txid.view;
      if (history)
      {
        history->rollback(txid, new_term);
      }
      if (std::max(head, reserved_through) < old_head)
      {
        ++rollback_count;
        last_committable = std::min(last_committable, head);
        snapshot_requested = false;
        if (encryptor != nullptr)
        {
          encryptor->rollback(head);
        }
        reserved_entries.erase(
          reserved_entries.upper_bound(head), reserved_entries.end());
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

    Response execute(Request request)
    {
      std::lock_guard lock(mutex);
      return dispatch(request);
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
    uint64_t attempt;
    std::string name;
    const bool& committed;

  public:
    MapAccess(
      Store& store_,
      uint64_t attempt_,
      const std::string& name_,
      const bool& committed_) :
      store(store_),
      attempt(attempt_),
      name(name_),
      committed(committed_)
    {}

    Response operate(
      Opcode op, ByteView key = {}, ByteView value = {}, bool global = false)
    {
      return store.execute(
        {.op = op,
         .inspect_finished = committed,
         .attempt = attempt,
         .number = global,
         .map = bytes(name),
         .key = key,
         .value = value});
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
      const auto from = lower ? Keys::to_serialised(*lower) : Bytes{};
      const auto to = upper ? Keys::to_serialised(*upper) : Bytes{};
      auto r = access.operate(
        Opcode::RANGE,
        lower ? bytes(from) : ByteView{},
        upper ? bytes(to) : ByteView{});
      r.require();
      for (size_t i = 0; i < r.size; ++i)
      {
        const auto row = r.entry(i);
        f(Keys::from_serialised(copy(row.key)),
          Values::from_serialised(copy(row.value)));
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
      access
        .operate(
          Opcode::WRITE,
          bytes(Keys::to_serialised(key)),
          bytes(Values::to_serialised(value)))
        .require();
    }

    void remove(const Key& key)
    {
      access.operate(Opcode::WRITE, bytes(Keys::to_serialised(key))).require();
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
      uint64_t id,
      const std::string& name,
      const bool& committed) :
      MapAccess(store, id, name, committed),
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

    struct State
    {
      Store& store;
      uint64_t id;
      std::
        map<std::string, std::map<std::type_index, std::unique_ptr<HandleBase>>>
          handles;
      std::optional<View> captured_term;
      std::optional<TxID> read_txid;
      std::optional<TxID> reserved;
      size_t reserve_epoch = 0;
      bool committing = false;
      bool committed = false;
      bool aborted = false;
      std::optional<Version> version;
      CommittableTx::TxFlags flags = 0;

      State(Store& store_, uint64_t id_) : store(store_), id(id_)
      {
        store.execute({.op = Opcode::BEGIN, .attempt = id}).require();
      }

      ~State()
      {
        // END is enabled for every existing attempt, even after commit.
        store.execute({.op = Opcode::END, .attempt = id}).require();
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
      auto& handles = s.handles[name];
      using Full = typename HandleFamily<M>::Full;
      const auto type = std::type_index(typeid(Full));
      if (auto it = handles.find(type); it != handles.end())
      {
        if (s.committing && !s.committed)
        {
          throw std::logic_error("Transaction did not commit successfully");
        }
        return static_cast<Full*>(it->second.get());
      }
      if (s.committing)
      {
        throw std::logic_error("Cannot acquire a new handle after commit");
      }
      parse_map_name(name);
      std::lock_guard lock(s.store.mutex);
      if (!s.captured_term.has_value())
      {
        auto snapshot = s.reserved ?
          s.store.dispatch(
            {.op = Opcode::SNAPSHOT_AT,
             .attempt = s.id,
             .number = s.reserved->seqno - 1}) :
          s.store.dispatch({.op = Opcode::SNAPSHOT, .attempt = s.id});
        snapshot.require();
        s.captured_term = snapshot.detail;
        s.read_txid = TxID{s.store.last_view, snapshot.number};
      }
      // Typed and untyped handles share the single native acquisition.
      if (handles.empty())
      {
        auto r = s.store.dispatch(
          {.op = Opcode::ACQUIRE, .attempt = s.id, .map = bytes(name)});
        if (r.status == Status::UNAVAILABLE)
        {
          throw CompactedVersionConflict(
            "Cannot acquire a compacted Rust KV map: " + name);
        }
        r.require();
      }
      auto handle = std::make_unique<Full>(s.store, s.id, name, s.committed);
      auto* raw = handle.get();
      handles.emplace(type, std::move(handle));
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
    uint64_t attempt = 0;
    {
      std::lock_guard lock(mutex);
      if (next_attempt == std::numeric_limits<uint64_t>::max())
      {
        throw std::overflow_error("Rust KV test attempt counter exhausted");
      }
      attempt = ++next_attempt;
    }
    return Tx(*this, attempt);
  }

  inline ReadOnlyTx Store::create_read_only_tx()
  {
    return ReadOnlyTx(create_tx());
  }
}
