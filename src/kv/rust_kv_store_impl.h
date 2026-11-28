// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/sha256_hash.h"
#include "ccf/kv/read_only_store.h"
#include "ccf/kv/serialisers/serialised_entry.h"
#include "ccf/tx_id.h"
#include "ds/internal_logger.h"
#include "kv/claims.h"
#include "kv/committable_tx.h"
#include "kv/compacted_version_conflict.h"
#include "kv/kv_serialiser.h"
#include "kv/kv_types.h"
#include "kv/ledger_chunker_interface.h"
#include "kv/rust_kv_ffi.h"
#include "kv/snapshot.h"
#include "kv/store_readiness.h"
#include "kv/trace.h"
#include "kv/untyped_map.h"
#include "kv/version_v.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstring>
#include <deque>
#include <format>
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
#include <thread>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

namespace ccf::kv
{
  namespace rust_detail
  {
    using Bytes = serialisers::SerialisedEntry;
    using MapWrites = std::map<std::string, untyped::Write>;

    inline rust_ffi::ByteView bytes(std::string_view s)
    {
      static constexpr uint8_t EMPTY = 0;
      return {
        s.empty() ? &EMPTY : reinterpret_cast<const uint8_t*>(s.data()),
        s.size()};
    }

    inline rust_ffi::ByteView bytes(const Bytes& b)
    {
      static constexpr uint8_t EMPTY = 0;
      return {b.empty() ? &EMPTY : b.data(), b.size()};
    }

    inline Bytes copy(rust_ffi::ByteView v)
    {
      return v.data == nullptr ? Bytes{} : Bytes(v.data, v.data + v.size);
    }

    struct Response
    {
      rust_ffi::Status status;
      uint64_t number;
      uint64_t detail;
      size_t size;
      std::unique_ptr<
        rust_ffi::ReplyData,
        decltype(&rust_ffi::ccf_rust_kv_reply_delete)>
        data;

      void require() const
      {
        if (status != rust_ffi::Status::OK)
        {
          throw std::logic_error(
            "Unexpected Rust KV status " +
            std::to_string(static_cast<unsigned>(status)));
        }
      }

      rust_ffi::Entry entry(size_t index) const
      {
        return rust_ffi::ccf_rust_kv_reply_entry(data.get(), index);
      }
    };

    inline Response wrap_reply(rust_ffi::Reply reply)
    {
      return {
        reply.status,
        reply.number,
        reply.detail,
        reply.size,
        {reply.data, &rust_ffi::ccf_rust_kv_reply_delete}};
    }

    struct FlatMapWrite
    {
      static constexpr size_t REMOVED = std::numeric_limits<size_t>::max();

      struct EntrySpan
      {
        size_t key_off = 0;
        size_t key_len = 0;
        size_t val_off = 0;
        size_t val_len = REMOVED;
      };

      std::vector<uint8_t> blob;
      std::vector<EntrySpan> entries;
      size_t puts = 0;
      size_t removes = 0;

      [[nodiscard]] bool empty() const
      {
        return entries.empty();
      }

      [[nodiscard]] std::span<const uint8_t> key_span(const EntrySpan& e) const
      {
        return {blob.data() + e.key_off, e.key_len};
      }

      [[nodiscard]] std::span<const uint8_t> val_span(const EntrySpan& e) const
      {
        return {blob.data() + e.val_off, e.val_len};
      }

      static int compare_spans(
        std::span<const uint8_t> a, std::span<const uint8_t> b)
      {
        const size_t min_len = std::min(a.size(), b.size());
        if (min_len != 0)
        {
          const int cmp = std::memcmp(a.data(), b.data(), min_len);
          if (cmp != 0)
          {
            return cmp;
          }
        }
        return a.size() < b.size() ? -1 : (a.size() > b.size() ? 1 : 0);
      }

      void append(
        std::span<const uint8_t> key, const std::span<const uint8_t>* val)
      {
        const size_t k_off = blob.size();
        blob.insert(blob.end(), key.begin(), key.end());
        size_t v_off = 0;
        size_t v_len = REMOVED;
        if (val != nullptr)
        {
          v_off = blob.size();
          v_len = val->size();
          blob.insert(blob.end(), val->begin(), val->end());
          ++puts;
        }
        else
        {
          ++removes;
        }
        entries.push_back({k_off, key.size(), v_off, v_len});
      }

      // Sort entries by ascending key order. Returns false if a duplicate key
      // exists, setting duplicate_is_remove when the duplicate is a removal.
      bool sort_and_check_unique(bool& duplicate_is_remove)
      {
        if (entries.size() <= 1)
        {
          return true;
        }
        bool sorted = true;
        for (size_t i = 1; i < entries.size(); ++i)
        {
          const int cmp =
            compare_spans(key_span(entries[i - 1]), key_span(entries[i]));
          if (cmp == 0)
          {
            duplicate_is_remove = (entries[i].val_len == REMOVED);
            return false;
          }
          if (cmp > 0)
          {
            sorted = false;
            break;
          }
        }
        if (sorted)
        {
          return true;
        }
        std::stable_sort(
          entries.begin(),
          entries.end(),
          [this](const EntrySpan& a, const EntrySpan& b) {
            return compare_spans(key_span(a), key_span(b)) < 0;
          });
        for (size_t i = 1; i < entries.size(); ++i)
        {
          if (
            compare_spans(key_span(entries[i - 1]), key_span(entries[i])) == 0)
          {
            duplicate_is_remove = (entries[i].val_len == REMOVED);
            return false;
          }
        }
        return true;
      }

      [[nodiscard]] untyped::Write materialize() const
      {
        untyped::Write out;
        for (const auto& e : entries)
        {
          const auto ks = key_span(e);
          Bytes k(ks.begin(), ks.end());
          if (e.val_len == REMOVED)
          {
            out.emplace(std::move(k), std::nullopt);
          }
          else
          {
            const auto vs = val_span(e);
            out.emplace(std::move(k), Bytes(vs.begin(), vs.end()));
          }
        }
        return out;
      }

      [[nodiscard]] std::shared_ptr<const FlatMapWrite> without_removes() const
      {
        auto out = std::make_shared<FlatMapWrite>();
        out->entries.reserve(puts);
        out->blob.reserve(blob.size());
        for (const auto& e : entries)
        {
          if (e.val_len != REMOVED)
          {
            const auto vs = val_span(e);
            out->append(key_span(e), &vs);
          }
        }
        return out;
      }
    };

    using FlatMapWrites =
      std::vector<std::pair<std::string, std::shared_ptr<const FlatMapWrite>>>;

    inline FlatMapWrites collect_flat_writes(const Response& reply)
    {
      std::map<std::string, std::shared_ptr<FlatMapWrite>> by_map;
      for (size_t i = 0; i < reply.size; ++i)
      {
        const auto row = reply.entry(i);
        std::string name(
          reinterpret_cast<const char*>(row.map.data), row.map.size);
        auto& ptr = by_map[std::move(name)];
        if (!ptr)
        {
          ptr = std::make_shared<FlatMapWrite>();
        }
        const std::span<const uint8_t> ks(row.key.data, row.key.size);
        if (row.value.data == nullptr)
        {
          ptr->append(ks, nullptr);
        }
        else
        {
          const std::span<const uint8_t> vs(row.value.data, row.value.size);
          ptr->append(ks, &vs);
        }
      }
      FlatMapWrites out;
      out.reserve(by_map.size());
      for (auto& [name, ptr] : by_map)
      {
        bool unused = false;
        ptr->sort_and_check_unique(unused);
        out.emplace_back(name, std::move(ptr));
      }
      return out;
    }

    template <typename Serialiser>
    inline void serialise_flat_writes(
      Serialiser& serialiser, const FlatMapWrites& maps)
    {
      for (const auto domain :
           {SecurityDomain::PUBLIC, SecurityDomain::PRIVATE})
      {
        for (const auto& [name, writes_ptr] : maps)
        {
          const auto& writes = *writes_ptr;
          if (writes.empty() || get_security_domain(name) != domain)
          {
            continue;
          }
          serialiser.start_map(name, domain);
          serialiser.serialise_entry_version(NoVersion);
          serialiser.serialise_count_header(0);
          serialiser.serialise_count_header(writes.puts);
          for (const auto& e : writes.entries)
          {
            if (e.val_len != FlatMapWrite::REMOVED)
            {
              serialiser.serialise_write_span(
                writes.key_span(e), writes.val_span(e));
            }
          }
          serialiser.serialise_count_header(writes.removes);
          for (const auto& e : writes.entries)
          {
            if (e.val_len == FlatMapWrite::REMOVED)
            {
              serialiser.serialise_remove_span(writes.key_span(e));
            }
          }
        }
      }
    }
  }

  // Lock ordering (always acquired in strictly ascending order; never re-enter
  // a lower-numbered lock while holding a higher-numbered lock):
  //   1. commit_lock     - serialises consensus replication and pending_txs
  //   2. compaction_lock - serialises compact() and global-hook delivery
  //   3. maps_lock       - store-wide structural barriers (lock_maps/apply/
  //                        compact/rollback/replay/snapshot)
  //   4. state_lock      - C++ metadata fields (versions, hooks, pending_txs)
  //   5. Rust NativeStore internal ShardedRwLock + HazardTable (never calls
  //      back into locks 1-4)
  class RustStore : public AbstractStore
  {
  public:
    struct TxCommitParams
    {
      rust_ffi::NativeTx* rust_tx = nullptr;
      const std::optional<TxID>& reserved;
      size_t reserve_epoch = 0;
      const ccf::ClaimsDigest& claims;
      const CommittableTx::WriteSetObserver& observer;
      bool is_reserved = false;
      bool has_any_changes = true;
      bool has_snapshot = false;
      bool& committing;
      bool& committed;
      bool& success;
      bool& aborted;
      Version& version;
      View& commit_view;
      CommittableTx::TxFlags& flags;
#ifdef CCF_KV_TRACING
      trace::Identity trace_id{};
#endif
    };

    class alignas(64) AdaptiveMutex
    {
      static constexpr uint32_t SPIN_LIMIT = 2048;
      std::mutex m;
      std::atomic<bool> held{false};

      static inline void cpu_relax()
      {
#if defined(__x86_64__) || defined(_M_X64)
        __builtin_ia32_pause();
#elif defined(__aarch64__)
        asm volatile("yield" ::: "memory");
#endif
      }

    public:
      AdaptiveMutex() = default;

      void lock()
      {
        if (!held.load(std::memory_order_relaxed) && m.try_lock())
        {
          held.store(true, std::memory_order_relaxed);
          return;
        }
        for (uint32_t i = 0; i < SPIN_LIMIT; ++i)
        {
          if (!held.load(std::memory_order_relaxed) && m.try_lock())
          {
            held.store(true, std::memory_order_relaxed);
            return;
          }
          cpu_relax();
        }
        m.lock();
        held.store(true, std::memory_order_relaxed);
      }

      bool try_lock()
      {
        if (!held.load(std::memory_order_relaxed) && m.try_lock())
        {
          held.store(true, std::memory_order_relaxed);
          return true;
        }
        return false;
      }

      void unlock()
      {
        held.store(false, std::memory_order_relaxed);
        m.unlock();
      }

      AdaptiveMutex(const AdaptiveMutex&) = delete;
      AdaptiveMutex& operator=(const AdaptiveMutex&) = delete;
    };

    class SnapshotPublicMaps
    {
      struct CapturedMap
      {
        Version revision;
        ccf::crypto::Sha256Hash digest;
        std::vector<std::pair<rust_detail::Bytes, untyped::VersionV>> rows;
      };

      friend class RustStore;
      Version version = NoVersion;
      std::map<std::string, CapturedMap> maps;
      SnapshotPublicMaps() = default;

    public:
      SnapshotPublicMaps(const SnapshotPublicMaps&) = delete;
      SnapshotPublicMaps& operator=(const SnapshotPublicMaps&) = delete;
      SnapshotPublicMaps(SnapshotPublicMaps&&) noexcept = default;
      SnapshotPublicMaps& operator=(SnapshotPublicMaps&&) noexcept = default;
      ~SnapshotPublicMaps() = default;
    };

  protected:
    friend class BaseTx;
    friend class CommittableTx;
    friend class ReservedTx;
    friend class untyped::MapHandle;
    friend class untyped::MapDiff;
    friend class RustReplayEntry;

    AdaptiveMutex commit_lock;
    std::mutex compaction_lock;
    AdaptiveMutex maps_lock;
    mutable AdaptiveMutex state_lock;
    std::
      unique_ptr<rust_ffi::NativeStore, decltype(&rust_ffi::ccf_rust_kv_delete)>
        native{rust_ffi::ccf_rust_kv_new(0), &rust_ffi::ccf_rust_kv_delete};
    const uint64_t store_instance_id = next_store_instance_id();
    std::atomic<uint64_t> next_attempt{0};
    Version head = 0;
    std::set<Version> open_reservations;
    Version last_replicated = 0;
    Version global = 0;
    View term = 0;
    std::atomic<View> last_view{0};
    size_t rollback_count = 0;
    Version last_committable = NoVersion;
    const bool is_historical = false;
    EncryptorPtr encryptor;
    std::shared_ptr<Consensus> consensus;
    std::shared_ptr<TxHistory> history;
    size_t max_entry_size = max_serialised_entry_size;
    std::atomic<bool> snapshot_requested{false};
    std::atomic<StoreReadiness> readiness{StoreReadiness::Ready};
    std::shared_ptr<ILedgerChunker> chunker;
    SnapshotterPtr snapshotter;
    std::unordered_map<Version, std::tuple<std::unique_ptr<PendingTx>, bool>>
      pending_txs;
    std::map<std::string, untyped::MapHook> local_hooks;
    std::map<std::string, untyped::CommitHook> global_hooks;

    struct MapDelta
    {
      std::shared_ptr<const rust_detail::FlatMapWrite> writes;
      bool delivered = false;
    };

    using MapDeltaLog = std::deque<std::pair<Version, MapDelta>>;
    std::map<std::string, MapDeltaLog> map_deltas;

    static void insert_map_delta(
      MapDeltaLog& log, Version version, MapDelta delta)
    {
      if (log.empty() || log.back().first < version)
      {
        log.emplace_back(version, std::move(delta));
        return;
      }
      auto it = std::lower_bound(
        log.begin(), log.end(), version, [](const auto& entry, Version v) {
          return entry.first < v;
        });
      if (it == log.end() || it->first != version)
      {
        log.emplace(it, version, std::move(delta));
      }
    }

    static MapDeltaLog::iterator upper_bound_delta(
      MapDeltaLog& log, Version version)
    {
      return std::upper_bound(
        log.begin(), log.end(), version, [](Version v, const auto& entry) {
          return v < entry.first;
        });
    }

    static MapDeltaLog::const_iterator upper_bound_delta(
      const MapDeltaLog& log, Version version)
    {
      return std::upper_bound(
        log.begin(), log.end(), version, [](Version v, const auto& entry) {
          return v < entry.first;
        });
    }

    static uint64_t next_store_instance_id()
    {
      static std::atomic<uint64_t> counter{0};
      return counter.fetch_add(1, std::memory_order_relaxed) + 1;
    }

    uint64_t allocate_attempt_id()
    {
      static constexpr uint64_t BATCH = 1024;

      struct LocalAttemptRange
      {
        uint64_t store_id = 0;
        uint64_t next = 0;
        uint64_t end = 0;
      };

      thread_local LocalAttemptRange local;
      if (local.store_id != store_instance_id || local.next == local.end)
      {
        const auto base =
          next_attempt.fetch_add(BATCH, std::memory_order_relaxed);
        if (base >= std::numeric_limits<uint64_t>::max() - BATCH)
        {
          throw std::overflow_error("Rust KV attempt counter exhausted");
        }
        local.store_id = store_instance_id;
        local.next = base + 1;
        local.end = base + BATCH + 1;
      }
      return local.next++;
    }

    rust_detail::Response dispatch_read(rust_ffi::Request request) const
    {
      return rust_detail::wrap_reply(
        rust_ffi::ccf_rust_kv_execute_read(native.get(), request));
    }

    rust_detail::Response dispatch_write(
      rust_ffi::Request request,
      void* trace_ctx = nullptr,
      rust_ffi::ReplyTraceFn trace_cb = nullptr)
    {
      return rust_detail::wrap_reply(rust_ffi::ccf_rust_kv_execute(
        native.get(), request, trace_ctx, trace_cb));
    }

    std::optional<Version> map_revision_at(
      Version version, const std::string& name) const
    {
      auto r = dispatch_read(
        {.op = rust_ffi::Opcode::MAP_REVISION,
         .number = version,
         .map = rust_detail::bytes(name)});
      if (r.status == rust_ffi::Status::MISSING)
      {
        return std::nullopt;
      }
      r.require();
      return r.number;
    }

    ConsensusHookPtrs record_commit_flat_locked(
      Version version, const rust_detail::FlatMapWrites& maps)
    {
      ConsensusHookPtrs hooks;
      for (const auto& [name, writes_ptr] : maps)
      {
        if (auto it = local_hooks.find(name);
            it != local_hooks.end() && it->second)
        {
          const auto materialized = writes_ptr->materialize();
          if (auto hook = it->second(version, materialized); hook != nullptr)
          {
            hooks.push_back(std::move(hook));
          }
        }
        if (writes_ptr->puts > 0 || map_revision_at(version, name) == version)
        {
          insert_map_delta(map_deltas[name], version, MapDelta{writes_ptr});
        }
      }
      return hooks;
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

    std::shared_ptr<const rust_detail::FlatMapWrite> diff_entries_for(
      Version version, const std::string& name)
    {
      std::lock_guard lock(state_lock);
      const auto it = map_deltas.find(name);
      if (it == map_deltas.end() || it->second.empty())
      {
        return nullptr;
      }
      const auto upper = upper_bound_delta(it->second, version);
      if (upper == it->second.begin())
      {
        return nullptr;
      }
      return std::prev(upper)->second.writes;
    }

    CommitResult commit_internal(
      const TxID& id,
      std::unique_ptr<PendingTx> entry,
      bool committable,
      std::optional<size_t> expected_rollback_count);

    ApplyResult deserialise_snapshot_internal(
      const uint8_t* data,
      size_t size,
      uint8_t* writable,
      ConsensusHookPtrs& hooks,
      std::vector<Version>* view_history,
      bool public_only,
      std::optional<SnapshotPublicMaps>* capture,
      const SnapshotPublicMaps* reuse);

  public:
    explicit RustStore(bool is_historical_ = false) :
      is_historical(is_historical_)
    {
      KV_TRACE(trace::store_create(this));
    }

    bool has_map_at(Version version, const std::string& name)
    {
      return map_revision_at(version, name).has_value();
    }

    rust_detail::MapWrites latest_map_deltas()
    {
      std::lock_guard lock(state_lock);
      rust_detail::MapWrites writes;
      for (const auto& [name, changes] : map_deltas)
      {
        if (!changes.empty())
        {
          writes.emplace(name, changes.back().second.writes->materialize());
        }
      }
      return writes;
    }

    bool acquire_map_for_tx(
      rust_ffi::NativeTx* tx,
      const std::string& map_name,
      const std::optional<TxID>& reserved,
      bool explicit_read_txid,
      std::optional<TxID>& read_txid,
      View& commit_view
#ifdef CCF_KV_TRACING
      ,
      trace::Identity trace_id = {}
#endif
    );

    PendingTxInfo commit_tx_impl(TxCommitParams& params);

    void release_tx_resources(rust_ffi::NativeTx* tx)
    {
      if (tx != nullptr)
      {
        rust_ffi::ccf_rust_kv_tx_delete(native.get(), tx);
      }
    }

    rust_detail::Response operate_tx_read(
      rust_ffi::NativeTx* tx, rust_ffi::Request request) const
    {
      return rust_detail::wrap_reply(
        rust_ffi::ccf_rust_kv_tx_operate(native.get(), tx, request));
    }

    ~RustStore() override
    {
      KV_TRACE(trace::store_end(this));
    }

    RustStore(const RustStore&) = delete;
    RustStore& operator=(const RustStore&) = delete;

    void set_readiness(StoreReadiness readiness_)
    {
      readiness.store(readiness_, std::memory_order_release);
    }

    [[nodiscard]] StoreReadiness get_readiness() const
    {
      return readiness.load(std::memory_order_acquire);
    }

    [[nodiscard]] bool is_ready() const
    {
      return get_readiness() == StoreReadiness::Ready;
    }

    std::shared_ptr<Consensus> get_consensus() override
    {
      std::lock_guard lock(state_lock);
      return consensus;
    }

    void set_consensus(const std::shared_ptr<Consensus>& c)
    {
      std::lock_guard lock(state_lock);
      consensus = c;
    }

    std::shared_ptr<TxHistory> get_history() override
    {
      std::lock_guard lock(state_lock);
      return history;
    }

    void set_history(const std::shared_ptr<TxHistory>& h)
    {
      KV_TRACE(
        if (h) { trace::unsupported(this, "transaction history machinery"); });
      std::lock_guard lock(state_lock);
      history = h;
    }

    std::shared_ptr<ILedgerChunker> get_chunker() override
    {
      std::lock_guard lock(state_lock);
      return chunker;
    }

    void set_chunker(const std::shared_ptr<ILedgerChunker>& c)
    {
      KV_TRACE(if (c) { trace::unsupported(this, "ledger chunk machinery"); });
      std::lock_guard lock(state_lock);
      chunker = c;
    }

    void set_encryptor(const EncryptorPtr& e)
    {
      std::lock_guard lock(state_lock);
      encryptor = e;
    }

    EncryptorPtr get_encryptor() override
    {
      std::lock_guard lock(state_lock);
      return encryptor;
    }

    void set_snapshotter(const SnapshotterPtr& s)
    {
      KV_TRACE(if (s) { trace::unsupported(this, "snapshot machinery"); });
      std::lock_guard lock(state_lock);
      snapshotter = s;
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

    std::shared_ptr<AbstractMap> get_map(Version, const std::string&) override
    {
      throw std::logic_error(
        "Rust KV backend does not expose C++ AbstractMap handles");
    }

    std::shared_ptr<AbstractMap> get_map_unsafe(
      Version, const std::string&) override
    {
      throw std::logic_error(
        "Rust KV backend does not expose C++ AbstractMap handles");
    }

    void add_dynamic_map(Version, const std::shared_ptr<AbstractMap>&) override
    {
      throw std::logic_error(
        "Rust KV backend does not expose C++ AbstractMap handles");
    }

    void lock_maps() override
    {
      maps_lock.lock();
    }

    void unlock_maps() override
    {
      maps_lock.unlock();
    }

    void lock_map_set() override
    {
      maps_lock.lock();
    }

    void unlock_map_set() override
    {
      maps_lock.unlock();
    }

    Version current_version() override
    {
      std::lock_guard lock(state_lock);
      return head;
    }

    TxID current_txid() override
    {
      std::lock_guard lock(state_lock);
      return {last_view.load(std::memory_order_acquire), head};
    }

    std::pair<TxID, Term> current_txid_and_commit_term() override
    {
      std::lock_guard lock(state_lock);
      KV_TRACE(trace::snapshot(this, head, term));
      return {{last_view.load(std::memory_order_acquire), head}, term};
    }

    Version compacted_version() override
    {
      std::lock_guard lock(state_lock);
      return global;
    }

    Term commit_view() override
    {
      std::lock_guard lock(state_lock);
      return term;
    }

    void initialise_term(View view) override
    {
      std::lock_guard lock(state_lock);
      if (term != 0)
      {
        throw std::logic_error("term_of_next_version is already initialised");
      }
      dispatch_write({.op = rust_ffi::Opcode::SET_TERM, .number = view})
        .require();
      term = view;
      KV_TRACE(trace::initialise_term(this));
      if (history)
      {
        history->set_term(view);
      }
    }

    std::optional<std::tuple<Version, Version>> next_version(
      Term expected_commit_term) override
    {
      KV_TRACE(trace::unsupported(this, "reserved transaction ID"));
      std::scoped_lock lock(maps_lock, state_lock);
      if (term != expected_commit_term)
      {
        return std::nullopt;
      }
      auto r = rust_detail::wrap_reply(
        rust_ffi::ccf_rust_kv_reserve_version(native.get()));
      if (r.status == rust_ffi::Status::EXHAUSTED)
      {
        throw std::overflow_error("Rust KV version counter exhausted");
      }
      r.require();
      head = r.number;
      last_view.store(term, std::memory_order_release);
      open_reservations.insert(head);
      return std::make_tuple(head, rollback_count);
    }

    TxID next_txid() override
    {
      KV_TRACE(trace::unsupported(this, "reserved transaction ID"));
      std::scoped_lock lock(maps_lock, state_lock);
      auto r = rust_detail::wrap_reply(
        rust_ffi::ccf_rust_kv_reserve_version(native.get()));
      if (r.status == rust_ffi::Status::EXHAUSTED)
      {
        throw std::overflow_error("Rust KV version counter exhausted");
      }
      r.require();
      head = r.number;
      last_view.store(term, std::memory_order_release);
      open_reservations.insert(head);
      return {term, head};
    }

    bool should_schedule_snapshot()
    {
      std::lock_guard lock(state_lock);
      if (snapshotter != nullptr)
      {
        return snapshotter->should_schedule_snapshot(last_committable);
      }
      return false;
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
      KV_TRACE(trace::unsupported(nullptr, "store clear"));
      std::scoped_lock lock(
        commit_lock, compaction_lock, maps_lock, state_lock);
      dispatch_write({.op = rust_ffi::Opcode::CLEAR_STORE}).require();
      head = NoVersion;
      global = NoVersion;
      open_reservations.clear();
      last_replicated = NoVersion;
      last_committable = NoVersion;
      term = 0;
      last_view.store(0, std::memory_order_release);
      ++rollback_count;
      snapshot_requested.store(false, std::memory_order_release);
      pending_txs.clear();
      map_deltas.clear();
    }

    void set_map_hook(
      const std::string& name, const ccf::kv::untyped::Map::MapHook& hook)
    {
      KV_TRACE(if (hook) { trace::unsupported(this, "local hook"); });
      std::lock_guard lock(state_lock);
      local_hooks.insert_or_assign(name, hook);
    }

    void unset_map_hook(const std::string& name)
    {
      std::lock_guard lock(state_lock);
      local_hooks.erase(name);
    }

    void set_global_hook(
      const std::string& name, const ccf::kv::untyped::Map::CommitHook& hook)
    {
      KV_TRACE(if (hook) { trace::unsupported(this, "global hook"); });
      std::lock_guard lock(state_lock);
      global_hooks.insert_or_assign(name, hook);
    }

    void unset_global_hook(const std::string& name)
    {
      std::lock_guard lock(state_lock);
      global_hooks.erase(name);
    }

    void compact(Version v) override
    {
      std::lock_guard ordered(compaction_lock);
#ifdef CCF_KV_TRACING
      trace::Environment trace_environment;
#endif
      SnapshotterPtr snap;
      std::shared_ptr<Consensus> cons;
      std::shared_ptr<ILedgerChunker> ch;
      {
        std::lock_guard lock(state_lock);
        snap = snapshotter;
        cons = consensus;
        ch = chunker;
      }
      if (snap)
      {
        snap->commit(v, cons && cons->is_primary());
      }
      if (ch)
      {
        ch->compacted_to(v);
      }
      std::vector<std::tuple<untyped::CommitHook, Version, untyped::Write>>
        callbacks;
      std::vector<std::shared_ptr<const rust_detail::FlatMapWrite>> to_drop;
      {
        std::scoped_lock lock(maps_lock, state_lock);
        const auto compact_target = open_reservations.empty() ?
          v :
          std::min(v, *open_reservations.begin() - 1);
#ifdef CCF_KV_TRACING
        struct CompactTraceCtx
        {
          RustStore* store;
          Version requested;
        };

        CompactTraceCtx trace_ctx{this, v};
        auto r = dispatch_write(
          {.op = rust_ffi::Opcode::COMPACT, .number = compact_target},
          &trace_ctx,
          trace::enabled() ?
            +[](void* ctx, rust_ffi::Reply res) {
              auto* c = static_cast<CompactTraceCtx*>(ctx);
              if (res.status == rust_ffi::Status::OK)
              {
                trace::compact(c->store, res.number, c->requested);
              }
            } :
            nullptr);
#else
        auto r = dispatch_write(
          {.op = rust_ffi::Opcode::COMPACT, .number = compact_target});
#endif
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
          auto end = upper_bound_delta(changes, global);
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
                  hook->second, it->first, it->second.writes->materialize());
                it->second.delivered = true;
                if (it->second.writes->removes > 0)
                {
                  to_drop.push_back(std::move(it->second.writes));
                  it->second.writes = to_drop.back()->without_removes();
                }
              }
            }
          }
          const auto drop_count =
            static_cast<size_t>(std::distance(changes.begin(), std::prev(end)));
          for (size_t i = 0; i < drop_count; ++i)
          {
            to_drop.push_back(std::move(changes.front().second.writes));
            changes.pop_front();
          }
        }
      }
      to_drop.clear();
      for (const auto& [hook, version, writes] : callbacks)
      {
        hook(version, writes);
      }
    }

    void rollback(const TxID& txid, View new_term) override
    {
      std::scoped_lock lock(maps_lock, state_lock);
#ifdef CCF_KV_TRACING
      trace::Environment trace_environment;
      trace::Rollback trace_rollback(this);

      struct RollbackTraceCtx
      {
        trace::Rollback* trace;
        Version seqno;
        View term;
      };

      RollbackTraceCtx trace_ctx{&trace_rollback, txid.seqno, new_term};
      auto r = dispatch_write(
        {.op = rust_ffi::Opcode::ROLLBACK,
         .attempt = new_term,
         .number = txid.seqno},
        &trace_ctx,
        trace::enabled() ?
          +[](void* ctx, rust_ffi::Reply res) {
            auto* c = static_cast<RollbackTraceCtx*>(ctx);
            if (res.status == rust_ffi::Status::ROLLBACK_REJECTED)
            {
              c->trace->rejected(c->seqno, c->term);
            }
            else if (res.status == rust_ffi::Status::OK)
            {
              c->trace->result(res.number, c->seqno, c->term);
            }
          } :
          nullptr);
#else
      auto r = dispatch_write(
        {.op = rust_ffi::Opcode::ROLLBACK,
         .attempt = new_term,
         .number = txid.seqno});
#endif
      if (r.status == rust_ffi::Status::ROLLBACK_REJECTED)
      {
        throw std::logic_error(std::format(
          "Attempting rollback to {}, earlier than commit version {}",
          txid.seqno,
          global));
      }
      r.require();
      const auto old_head = head;
      head = r.number;
      open_reservations.erase(
        open_reservations.upper_bound(head), open_reservations.end());
      term = new_term;
      last_view.store(txid.view, std::memory_order_release);
      if (history)
      {
        history->rollback(txid, new_term);
      }
      if (txid.seqno >= old_head)
      {
        if (snapshotter)
        {
          snapshotter->rollback(txid.seqno);
        }
        if (chunker)
        {
          chunker->rolled_back_to(std::min(txid.seqno, old_head));
        }
        return;
      }
      last_replicated = head;
      last_committable = std::min(last_committable, head);
      ++rollback_count;
      snapshot_requested.store(false, std::memory_order_release);
      pending_txs.clear();
      if (chunker)
      {
        chunker->rolled_back_to(head);
      }
      if (snapshotter)
      {
        snapshotter->rollback(txid.seqno);
      }
      if (encryptor)
      {
        encryptor->rollback(head);
      }
      for (auto& [_, changes] : map_deltas)
      {
        while (!changes.empty() && changes.back().first > head)
        {
          changes.pop_back();
        }
      }
    }

    CommitResult commit(
      const TxID& id,
      std::unique_ptr<PendingTx> entry,
      bool committable) override;

    std::unique_ptr<AbstractSnapshot> snapshot_unsafe_maps(
      Version version) override;
    std::unique_ptr<AbstractSnapshot> snapshot_maps(Version version);
    std::vector<uint8_t> serialise_snapshot(
      std::unique_ptr<AbstractSnapshot> snapshot) override;
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
    void swap_private_maps(RustStore& source);

    std::unique_ptr<AbstractExecutionWrapper> deserialize(
      const std::vector<uint8_t>& data,
      bool public_only = false,
      const std::optional<TxID>& expected_txid = std::nullopt) override;
  };
}
