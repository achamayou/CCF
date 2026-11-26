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

    class ShardedRwLock
    {
      static constexpr size_t NUM_STRIPES = 8;
      static constexpr uint32_t WRITER_BIT = 0x80000000u;
      static constexpr uint32_t READER_MASK = 0x7fffffffu;
      static constexpr uint32_t SPIN_LIMIT = 512;

      static inline void cpu_relax()
      {
#if defined(__x86_64__) || defined(_M_X64)
        __builtin_ia32_pause();
#elif defined(__aarch64__)
        asm volatile("yield" ::: "memory");
#endif
      }

      struct alignas(64) Stripe
      {
        mutable std::atomic<uint32_t> state{0};

        Stripe() = default;
        Stripe(const Stripe&) = delete;
        Stripe& operator=(const Stripe&) = delete;
      };

      alignas(64) mutable std::atomic<bool> write_gate{false};
      std::array<Stripe, NUM_STRIPES> stripes;

      void lock_write_gate() const
      {
        uint32_t spins = 0;
        for (;;)
        {
          if (
            !write_gate.load(std::memory_order_relaxed) &&
            !write_gate.exchange(true, std::memory_order_acquire))
          {
            return;
          }
          if (++spins < SPIN_LIMIT)
          {
            cpu_relax();
          }
          else
          {
            std::this_thread::yield();
          }
        }
      }

      void unlock_write_gate() const
      {
        write_gate.store(false, std::memory_order_release);
      }

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
        std::atomic<uint32_t>& state;

      public:
        explicit ReadGuard(const ShardedRwLock& lock) :
          state(lock.stripes[thread_stripe()].state)
        {
          uint32_t spins = 0;
          for (;;)
          {
            if ((state.load(std::memory_order_relaxed) & WRITER_BIT) == 0)
            {
              const uint32_t prev =
                state.fetch_add(1, std::memory_order_acq_rel);
              if ((prev & WRITER_BIT) == 0)
              {
                return;
              }
              state.fetch_sub(1, std::memory_order_release);
            }
            if (++spins < SPIN_LIMIT)
            {
              cpu_relax();
            }
            else
            {
              std::this_thread::yield();
            }
          }
        }

        ~ReadGuard()
        {
          state.fetch_sub(1, std::memory_order_release);
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
          lock.lock_write_gate();
          // Set WRITER_BIT across all stripes first so readers stop entering
          // and drain in parallel across every stripe.
          for (size_t i = 0; i < NUM_STRIPES; ++i)
          {
            lock.stripes[i].state.fetch_or(
              WRITER_BIT, std::memory_order_acq_rel);
          }
          for (size_t i = 0; i < NUM_STRIPES; ++i)
          {
            uint32_t spins = 0;
            while ((lock.stripes[i].state.load(std::memory_order_acquire) &
                    READER_MASK) != 0)
            {
              if (++spins < SPIN_LIMIT)
              {
                cpu_relax();
              }
              else
              {
                std::this_thread::yield();
              }
            }
          }
        }

        ~WriteGuard()
        {
          for (size_t i = NUM_STRIPES; i > 0; --i)
          {
            lock.stripes[i - 1].state.fetch_and(
              ~WRITER_BIT, std::memory_order_release);
          }
          lock.unlock_write_gate();
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

    AdaptiveMutex commit_lock;
    std::mutex compaction_lock;
    AdaptiveMutex maps_lock;
    mutable AdaptiveMutex state_lock;
    mutable ShardedRwLock native_lock;
    std::
      unique_ptr<rust_ffi::NativeStore, decltype(&rust_ffi::ccf_rust_kv_delete)>
        native{rust_ffi::ccf_rust_kv_new(0), &rust_ffi::ccf_rust_kv_delete};
    std::array<HazardSlot, NUM_HAZARD_SLOTS> hazard_slots;
    std::vector<uint32_t> hazard_retained_roots;
    std::vector<std::pair<Version, uint64_t>> hazard_pinned_snaps;
    uint64_t next_hazard_pin_id = (uint64_t(1) << 63);
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
        if (r.load(std::memory_order_relaxed) != 0)
        {
          r.store(0, std::memory_order_release);
        }
      }
      if (h.snap_plus_one.load(std::memory_order_relaxed) != 0)
      {
        h.snap_plus_one.store(0, std::memory_order_release);
      }
      h.claimed.store(false, std::memory_order_release);
    }

    void sync_hazards_locked()
    {
      bool any_claimed = false;
      for (const auto& slot : hazard_slots)
      {
        if (slot.claimed.load(std::memory_order_acquire))
        {
          any_claimed = true;
          break;
        }
      }
      if (
        !any_claimed && hazard_retained_roots.empty() &&
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

      for (const auto& slot : hazard_slots)
      {
        if (!slot.claimed.load(std::memory_order_acquire))
        {
          continue;
        }
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
      bool& registered,
      int& hazard_slot,
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
      KV_TRACE(trace::unsupported(this, "reserved transaction ID"));
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
      KV_TRACE(trace::unsupported(nullptr, "store clear"));
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
        auto r = [&]() {
          ShardedRwLock::WriteGuard native_guard(native_lock);
          sync_hazards_locked();
          auto res = dispatch_write_locked(
            {.op = rust_ffi::Opcode::COMPACT, .number = compact_target});
          sync_hazards_locked();
          if (res.status == rust_ffi::Status::OK)
          {
            KV_TRACE(trace::compact(this, res.number, v));
          }
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
#endif
      auto r = [&]() {
        ShardedRwLock::WriteGuard native_guard(native_lock);
        sync_hazards_locked();
        auto res = dispatch_write_locked(
          {.op = rust_ffi::Opcode::ROLLBACK,
           .attempt = new_term,
           .number = txid.seqno});
        sync_hazards_locked();
        if (res.status == rust_ffi::Status::ROLLBACK_REJECTED)
        {
          KV_TRACE(trace_rollback.rejected(txid.seqno, new_term));
        }
        else if (res.status == rust_ffi::Status::OK)
        {
          KV_TRACE(trace_rollback.result(res.number, txid.seqno, new_term));
        }
        return res;
      }();
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
