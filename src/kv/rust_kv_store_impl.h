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
#include "kv/untyped_map.h"
#include "kv/version_v.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <bit>
#include <format>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <pthread.h>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
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

    inline MapWrites collect_writes(const Response& reply)
    {
      MapWrites maps;
      for (size_t i = 0; i < reply.size; ++i)
      {
        const auto row = reply.entry(i);
        std::string name(
          reinterpret_cast<const char*>(row.map.data), row.map.size);
        maps[std::move(name)].insert_or_assign(
          copy(row.key),
          row.value.data == nullptr ? std::nullopt :
                                      std::optional<Bytes>(copy(row.value)));
      }
      return maps;
    }

    inline void serialise_writes(
      KvStoreSerialiser& serialiser, const MapWrites& maps)
    {
      for (const auto domain :
           {SecurityDomain::PUBLIC, SecurityDomain::PRIVATE})
      {
        for (const auto& [name, writes] : maps)
        {
          if (writes.empty() || get_security_domain(name) != domain)
          {
            continue;
          }
          serialiser.start_map(name, domain);
          serialiser.serialise_entry_version(NoVersion);
          serialiser.serialise_count_header(0);

          uint64_t puts = 0;
          uint64_t removes = 0;
          for (const auto& [_, value] : writes)
          {
            ++(value.has_value() ? puts : removes);
          }
          serialiser.serialise_count_header(puts);
          for (const auto& [key, value] : writes)
          {
            if (value.has_value())
            {
              serialiser.serialise_write(key, *value);
            }
          }
          serialiser.serialise_count_header(removes);
          for (const auto& [key, value] : writes)
          {
            if (!value.has_value())
            {
              serialiser.serialise_remove(key);
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
  //   5. native_lock     - sharded rwlock guarding NativeStore
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
    };

    class ShardedRwLock
    {
      static constexpr size_t NUM_STRIPES = 8;

      struct alignas(64) Stripe
      {
        mutable pthread_rwlock_t rwlock;

        Stripe()
        {
          pthread_rwlockattr_t attr;
          pthread_rwlockattr_init(&attr);
#ifdef PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP
          pthread_rwlockattr_setkind_np(
            &attr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
#endif
          pthread_rwlock_init(&rwlock, &attr);
          pthread_rwlockattr_destroy(&attr);
        }

        ~Stripe()
        {
          pthread_rwlock_destroy(&rwlock);
        }

        Stripe(const Stripe&) = delete;
        Stripe& operator=(const Stripe&) = delete;
      };

      mutable std::mutex write_gate;
      std::array<Stripe, NUM_STRIPES> stripes;

      static size_t thread_stripe()
      {
        static std::atomic<size_t> next_stripe{0};
        thread_local const size_t idx =
          next_stripe.fetch_add(1, std::memory_order_relaxed) &
          (NUM_STRIPES - 1);
        return idx;
      }

    public:
      class ReadGuard
      {
        pthread_rwlock_t& rwlock;

      public:
        explicit ReadGuard(const ShardedRwLock& lock) :
          rwlock(lock.stripes[thread_stripe()].rwlock)
        {
          pthread_rwlock_rdlock(&rwlock);
        }

        ~ReadGuard()
        {
          pthread_rwlock_unlock(&rwlock);
        }

        ReadGuard(const ReadGuard&) = delete;
        ReadGuard& operator=(const ReadGuard&) = delete;
      };

      class WriteGuard
      {
        const ShardedRwLock& lock;

      public:
        explicit WriteGuard(const ShardedRwLock& lock_) : lock(lock_)
        {
          lock.write_gate.lock();
          for (size_t i = 0; i < NUM_STRIPES; ++i)
          {
            pthread_rwlock_wrlock(&lock.stripes[i].rwlock);
          }
        }

        ~WriteGuard()
        {
          for (size_t i = NUM_STRIPES; i > 0; --i)
          {
            pthread_rwlock_unlock(&lock.stripes[i - 1].rwlock);
          }
          lock.write_gate.unlock();
        }

        WriteGuard(const WriteGuard&) = delete;
        WriteGuard& operator=(const WriteGuard&) = delete;
      };

      static size_t current_thread_stripe()
      {
        return thread_stripe();
      }
    };

    static constexpr size_t NUM_HAZARD_SLOTS = 64;
    static constexpr size_t ROOTS_PER_HAZARD = 12;

    struct alignas(64) HazardSlot
    {
      std::atomic<bool> claimed{false};
      std::atomic<uint64_t> snap_plus_one{0};
      std::array<std::atomic<uint32_t>, ROOTS_PER_HAZARD> roots{};
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

    std::mutex commit_lock;
    std::mutex compaction_lock;
    std::mutex maps_lock;
    mutable std::mutex state_lock;
    mutable ShardedRwLock native_lock;
    std::
      unique_ptr<rust_ffi::NativeStore, decltype(&rust_ffi::ccf_rust_kv_delete)>
        native{rust_ffi::ccf_rust_kv_new(0), &rust_ffi::ccf_rust_kv_delete};
    std::array<HazardSlot, NUM_HAZARD_SLOTS> hazard_slots;
    std::atomic<uint64_t> hazard_active_mask{0};
    std::vector<uint32_t> hazard_retained_roots;
    std::vector<std::pair<Version, uint64_t>> hazard_pinned_snaps;
    uint64_t next_hazard_pin_id = (uint64_t(1) << 63);
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
      untyped::Write writes;
      bool delivered = false;
    };

    std::map<std::string, std::map<Version, MapDelta>> map_deltas;

    uint64_t allocate_attempt_id()
    {
      const auto previous =
        next_attempt.fetch_add(1, std::memory_order_relaxed);
      if (previous == std::numeric_limits<uint64_t>::max())
      {
        throw std::overflow_error("Rust KV attempt counter exhausted");
      }
      return previous + 1;
    }

    int try_claim_hazard_slot()
    {
      const size_t start =
        (ShardedRwLock::current_thread_stripe() * 8) % NUM_HAZARD_SLOTS;
      for (size_t i = 0; i < NUM_HAZARD_SLOTS; ++i)
      {
        const size_t idx = (start + i) % NUM_HAZARD_SLOTS;
        bool expected = false;
        if (hazard_slots[idx].claimed.compare_exchange_strong(
              expected, true, std::memory_order_acq_rel))
        {
          hazard_active_mask.fetch_or(
            uint64_t(1) << idx, std::memory_order_release);
          return static_cast<int>(idx);
        }
      }
      return -1;
    }

    void release_hazard_slot(int slot)
    {
      const auto idx = static_cast<size_t>(slot);
      auto& h = hazard_slots[idx];
      for (auto& r : h.roots)
      {
        r.store(0, std::memory_order_release);
      }
      h.snap_plus_one.store(0, std::memory_order_release);
      hazard_active_mask.fetch_and(
        ~(uint64_t(1) << idx), std::memory_order_release);
      h.claimed.store(false, std::memory_order_release);
    }

    void sync_hazards_locked()
    {
      uint64_t mask = hazard_active_mask.load(std::memory_order_acquire);
      if (
        mask == 0 && hazard_retained_roots.empty() &&
        hazard_pinned_snaps.empty())
      {
        return;
      }
      std::array<uint32_t, NUM_HAZARD_SLOTS * ROOTS_PER_HAZARD> active_roots{};
      size_t active_root_count = 0;
      std::array<Version, NUM_HAZARD_SLOTS> active_snaps{};
      size_t active_snap_count = 0;

      auto contains_root = [&](uint32_t v) {
        for (size_t i = 0; i < active_root_count; ++i)
        {
          if (active_roots[i] == v)
          {
            return true;
          }
        }
        return false;
      };
      auto contains_snap = [&](Version v) {
        for (size_t i = 0; i < active_snap_count; ++i)
        {
          if (active_snaps[i] == v)
          {
            return true;
          }
        }
        return false;
      };

      while (mask != 0)
      {
        const auto idx = static_cast<size_t>(std::countr_zero(mask));
        mask &= (mask - 1);
        const auto& slot = hazard_slots[idx];
        const auto sp = slot.snap_plus_one.load(std::memory_order_acquire);
        if (sp != 0 && !contains_snap(sp - 1))
        {
          active_snaps[active_snap_count++] = sp - 1;
        }
        for (const auto& r : slot.roots)
        {
          const auto root = r.load(std::memory_order_acquire);
          if (root != 0 && !contains_root(root))
          {
            active_roots[active_root_count++] = root;
          }
        }
      }

      for (size_t i = 0; i < active_root_count; ++i)
      {
        const auto root = active_roots[i];
        bool already = false;
        for (const auto existing : hazard_retained_roots)
        {
          if (existing == root)
          {
            already = true;
            break;
          }
        }
        if (!already)
        {
          rust_ffi::ccf_rust_kv_retain_root(native.get(), root);
          hazard_retained_roots.push_back(root);
        }
      }
      for (size_t i = 0; i < hazard_retained_roots.size();)
      {
        if (!contains_root(hazard_retained_roots[i]))
        {
          rust_ffi::ccf_rust_kv_release_root(
            native.get(), hazard_retained_roots[i]);
          hazard_retained_roots[i] = hazard_retained_roots.back();
          hazard_retained_roots.pop_back();
        }
        else
        {
          ++i;
        }
      }
      for (size_t i = 0; i < active_snap_count; ++i)
      {
        const auto ver = active_snaps[i];
        bool already = false;
        for (const auto& [existing_ver, _] : hazard_pinned_snaps)
        {
          if (existing_ver == ver)
          {
            already = true;
            break;
          }
        }
        if (!already)
        {
          const auto pin_id = next_hazard_pin_id++;
          rust_ffi::ccf_rust_kv_pin_snapshot(native.get(), pin_id, ver);
          hazard_pinned_snaps.emplace_back(ver, pin_id);
        }
      }
      for (size_t i = 0; i < hazard_pinned_snaps.size();)
      {
        if (!contains_snap(hazard_pinned_snaps[i].first))
        {
          rust_ffi::ccf_rust_kv_unpin_snapshot(
            native.get(), hazard_pinned_snaps[i].second);
          hazard_pinned_snaps[i] = hazard_pinned_snaps.back();
          hazard_pinned_snaps.pop_back();
        }
        else
        {
          ++i;
        }
      }
    }

    rust_detail::Response dispatch_read_locked(rust_ffi::Request request) const
    {
      return rust_detail::wrap_reply(
        rust_ffi::ccf_rust_kv_execute_read(native.get(), request));
    }

    rust_detail::Response dispatch_read(rust_ffi::Request request) const
    {
      ShardedRwLock::ReadGuard guard(native_lock);
      return dispatch_read_locked(request);
    }

    rust_detail::Response dispatch_write_locked(rust_ffi::Request request)
    {
      return rust_detail::wrap_reply(
        rust_ffi::ccf_rust_kv_execute(native.get(), request));
    }

    rust_detail::Response dispatch_write(rust_ffi::Request request)
    {
      ShardedRwLock::WriteGuard guard(native_lock);
      return dispatch_write_locked(request);
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

    ConsensusHookPtrs record_commit_locked(
      Version version, const rust_detail::MapWrites& maps)
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

    untyped::Write diff_entries_for(Version version, const std::string& name)
    {
      std::lock_guard lock(state_lock);
      const auto it = map_deltas.find(name);
      if (it == map_deltas.end() || it->second.empty())
      {
        return {};
      }
      const auto upper = it->second.upper_bound(version);
      if (upper == it->second.begin())
      {
        return {};
      }
      return std::prev(upper)->second.writes;
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

  public:
    explicit RustStore(bool is_historical_ = false) :
      is_historical(is_historical_)
    {}

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
          writes.emplace(name, changes.rbegin()->second.writes);
        }
      }
      return writes;
    }

    bool acquire_map_for_tx(
      rust_ffi::NativeTx* tx,
      const std::string& map_name,
      bool& registered,
      int& hazard_slot,
      const std::optional<TxID>& reserved,
      bool explicit_read_txid,
      std::optional<TxID>& read_txid,
      View& commit_view);

    PendingTxInfo commit_tx_impl(TxCommitParams& params);

    void release_tx_resources(
      int hazard_slot, bool registered, rust_ffi::NativeTx* tx)
    {
      if (hazard_slot >= 0)
      {
        release_hazard_slot(hazard_slot);
      }
      if (tx != nullptr)
      {
        if (registered)
        {
          ShardedRwLock::WriteGuard guard(native_lock);
          rust_ffi::ccf_rust_kv_tx_delete(native.get(), tx);
        }
        else
        {
          rust_ffi::ccf_rust_kv_tx_delete(nullptr, tx);
        }
      }
    }

    rust_detail::Response operate_tx_read(
      rust_ffi::NativeTx* tx, rust_ffi::Request request) const
    {
      ShardedRwLock::ReadGuard guard(native_lock);
      return rust_detail::wrap_reply(
        rust_ffi::ccf_rust_kv_tx_operate(native.get(), tx, request));
    }

    ~RustStore() override = default;
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
        throw std::logic_error("Commit term is already initialised");
      }
      dispatch_write({.op = rust_ffi::Opcode::SET_TERM, .number = view})
        .require();
      term = view;
      if (history)
      {
        history->set_term(view);
      }
    }

    std::optional<std::tuple<Version, Version>> next_version(
      Term expected_commit_term) override
    {
      std::scoped_lock lock(maps_lock, state_lock);
      if (term != expected_commit_term)
      {
        return std::nullopt;
      }
      auto r = [&]() {
        ShardedRwLock::WriteGuard native_guard(native_lock);
        return rust_detail::wrap_reply(
          rust_ffi::ccf_rust_kv_reserve_version(native.get()));
      }();
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
      std::scoped_lock lock(maps_lock, state_lock);
      auto r = [&]() {
        ShardedRwLock::WriteGuard native_guard(native_lock);
        return rust_detail::wrap_reply(
          rust_ffi::ccf_rust_kv_reserve_version(native.get()));
      }();
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
      std::scoped_lock lock(
        commit_lock, compaction_lock, maps_lock, state_lock);
      {
        ShardedRwLock::WriteGuard native_guard(native_lock);
        sync_hazards_locked();
        dispatch_write_locked({.op = rust_ffi::Opcode::CLEAR_STORE}).require();
        hazard_retained_roots.clear();
        hazard_pinned_snaps.clear();
      }
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
      {
        std::scoped_lock lock(maps_lock, state_lock);
        const auto compact_target = open_reservations.empty() ?
          v :
          std::min(v, *open_reservations.begin() - 1);
        auto r = [&]() {
          ShardedRwLock::WriteGuard native_guard(native_lock);
          sync_hazards_locked();
          auto res = dispatch_write_locked(
            {.op = rust_ffi::Opcode::COMPACT, .number = compact_target});
          sync_hazards_locked();
          return res;
        }();
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
      auto r = [&]() {
        ShardedRwLock::WriteGuard native_guard(native_lock);
        sync_hazards_locked();
        auto res = dispatch_write_locked(
          {.op = rust_ffi::Opcode::ROLLBACK,
           .attempt = new_term,
           .number = txid.seqno});
        sync_hazards_locked();
        return res;
      }();
      if (r.status == rust_ffi::Status::ROLLBACK_REJECTED)
      {
        throw std::logic_error("Cannot roll back compacted Rust KV history");
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
        changes.erase(changes.upper_bound(head), changes.end());
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
