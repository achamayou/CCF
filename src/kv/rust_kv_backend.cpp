// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ds/internal_logger.h"
#include "kv/committable_tx.h"
#include "kv/internal_table_names.h"
#include "kv/rust_kv_store_impl.h"
#include "kv/snapshot.h"
#ifdef CCF_USE_RUST_KV
#  include "kv/store.h"
#  include "kv/tx_pimpl.h"
#  include "kv/untyped_change_set.h"
#endif

#include <bit>
#include <format>
#include <limits>
#include <stdexcept>

namespace ccf::kv
{
  using namespace rust_ffi;
  using namespace rust_detail;

  namespace
  {
    using Rows = std::vector<std::pair<Bytes, untyped::VersionV>>;

    class RustMapSnapshot : public AbstractMap::Snapshot
    {
      const std::string name;
      const SecurityDomain domain;
      const Version revision;
      const Rows rows;

    public:
      RustMapSnapshot(std::string name_, Version revision_, Rows rows_) :
        name(std::move(name_)),
        domain(ccf::kv::get_security_domain(name)),
        revision(revision_),
        rows(std::move(rows_))
      {}

      SecurityDomain get_security_domain() const override
      {
        return domain;
      }

      void serialise(KvStoreSerialiser& s) override
      {
        size_t size = 0;
        for (const auto& [key, val] : rows)
        {
          size += ::map::get_serialized_size_with_padding(key);
          size += ::map::get_serialized_size_with_padding(val);
        }
        s.start_map(name, domain);
        s.serialise_entry_version(revision);
        s.serialise_raw_in_place(size, [&](std::span<uint8_t> dest) {
          auto* p = dest.data();
          auto remaining = dest.size();
          for (const auto& [key, val] : rows)
          {
            const auto ksize = ::map::serialize(key, p, remaining);
            ::map::add_padding(ksize, p, remaining);
            const auto vsize = ::map::serialize(val, p, remaining);
            ::map::add_padding(vsize, p, remaining);
          }
        });
      }
    };

    Rows decode_snapshot_rows(std::span<const uint8_t> raw)
    {
      Rows rows;
      const auto* data = raw.data();
      auto size = raw.size();
      while (size != 0)
      {
        auto payload = [&](size_t minimum) {
          const auto length = serialized::read<uint64_t>(data, size);
          if (length < minimum || length > size)
          {
            throw std::logic_error("Invalid snapshot map payload size");
          }
          auto span = std::span(data, static_cast<size_t>(length));
          serialized::skip(data, size, length);
          serialized::skip(
            data, size, ::map::get_padding(sizeof(uint64_t) + length));
          return span;
        };
        auto key = payload(0);
        auto value = payload(sizeof(Version));
        const auto* p = value.data();
        auto remaining = value.size();
        const auto version = serialized::read<Version>(p, remaining);
        // Legacy snapshots encoded tombstones as negative write versions.
        if (std::bit_cast<int64_t>(version) >= 0)
        {
          rows.emplace_back(
            Bytes(key.begin(), key.end()),
            untyped::VersionV{version, Bytes(p, p + remaining)});
        }
      }
      return rows;
    }
  }

  class RustReplayEntry : public AbstractExecutionWrapper
  {
    RustStore& store;
    const std::vector<uint8_t> data;
    const bool public_only;
    const std::optional<TxID> expected_txid;
    TxID applied;
    ConsensusHookPtrs hooks;
    ClaimsDigest claims = no_claims();
    std::optional<ccf::crypto::Sha256Hash> evidence;

  public:
    RustReplayEntry(
      RustStore& store_,
      const std::vector<uint8_t>& data_,
      bool public_only_,
      const std::optional<TxID>& expected_txid_) :
      store(store_),
      data(data_),
      public_only(public_only_),
      expected_txid(expected_txid_)
    {}

    ApplyResult apply(bool track_deletes_on_missing_keys) override
    {
      std::scoped_lock lock(store.maps_lock, store.state_lock);
      RawKvStoreDeserialiser decoder(
        store.encryptor,
        public_only ? std::make_optional(SecurityDomain::PUBLIC) :
                      std::nullopt);
      Term term = 0;
      EntryFlags flags{};
      const auto version = decoder.init(
        data.data(), data.size(), term, flags, store.is_historical);
      if (!version.has_value())
      {
        LOG_FAIL_FMT("Rust KV replay could not decode the ledger entry");
        return ApplyResult::FAIL;
      }
      if (
        decoder.get_entry_type() == EntryType::Snapshot ||
        decoder.get_entry_type() > EntryType::MAX ||
        (flags &
         ~(EntryFlags::FORCE_LEDGER_CHUNK_BEFORE |
           EntryFlags::FORCE_LEDGER_CHUNK_AFTER)) != 0)
      {
        LOG_FAIL_FMT("Rust KV replay only accepts ordinary ledger entries");
        return ApplyResult::FAIL;
      }
      const TxID id{term, *version};
      if (expected_txid.has_value() && id != *expected_txid)
      {
        LOG_FAIL_FMT("Rust KV replay TxID does not match the expected entry");
        return ApplyResult::FAIL;
      }

      MapWrites writes;
      for (auto name = decoder.start_map(); name; name = decoder.start_map())
      {
        if (!writes.try_emplace(*name).second)
        {
          LOG_FAIL_FMT("Rust KV replay received a duplicate map");
          return ApplyResult::FAIL;
        }
        const auto domain = parse_map_name(*name).first;
        if (public_only && domain != SecurityDomain::PUBLIC)
        {
          LOG_FAIL_FMT("Rust KV replay received a private map in public data");
          return ApplyResult::FAIL;
        }
        auto& rows = writes.at(*name);
        if (
          decoder.deserialise_entry_version() != NoVersion ||
          decoder.deserialise_read_header() != 0)
        {
          LOG_FAIL_FMT("Rust KV replay does not support legacy read sets");
          return ApplyResult::FAIL;
        }
        for (auto n = decoder.deserialise_write_header(); n != 0; --n)
        {
          auto [k, v] = decoder.deserialise_write();
          if (!rows.try_emplace(std::move(k), std::move(v)).second)
          {
            LOG_FAIL_FMT("Rust KV replay received a duplicate key");
            return ApplyResult::FAIL;
          }
        }
        for (auto n = decoder.deserialise_remove_header(); n != 0; --n)
        {
          if (!rows.try_emplace(decoder.deserialise_remove(), std::nullopt)
                 .second)
          {
            LOG_FAIL_FMT("Rust KV replay received a duplicate removal");
            return ApplyResult::FAIL;
          }
        }
      }

      const bool classical = writes.contains(Tables::SIGNATURES);
      const bool cose = writes.contains(Tables::COSE_SIGNATURES);
      const bool signature = classical || cose;
      if (
        signature &&
        (!writes.contains(Tables::SERIALISED_MERKLE_TREE) ||
         writes.size() !=
           1 + static_cast<size_t>(classical) + static_cast<size_t>(cose)))
      {
        LOG_FAIL_FMT("Rust KV replay received an invalid signature entry");
        return ApplyResult::FAIL;
      }
      std::vector<Entry> entries;
      for (const auto& [name, rows] : writes)
      {
        for (const auto& [key, value] : rows)
        {
          entries.push_back(
            {bytes(name), bytes(key), value ? bytes(*value) : ByteView{}});
        }
      }
      const bool replace = id.seqno <= store.head;
      Status status;
      {
        RustStore::ShardedRwLock::WriteGuard native_guard(store.native_lock);
        store.sync_hazards_locked();
        status = ccf_rust_kv_replay(
          store.native.get(),
          id.seqno,
          entries.data(),
          entries.size(),
          track_deletes_on_missing_keys);
        store.sync_hazards_locked();
      }
      if (status != Status::OK)
      {
        LOG_FAIL_FMT(
          "Rust KV did not apply ledger entry {} (status {})",
          id.to_str(),
          static_cast<unsigned>(status));
        return ApplyResult::FAIL;
      }
      applied = id;
      if (store.head == 0 && id.seqno > 1)
      {
        store.global = id.seqno - 1;
      }
      store.head = id.seqno;
      store.last_view.store(id.view, std::memory_order_release);
      store.open_reservations.erase(
        store.open_reservations.lower_bound(id.seqno),
        store.open_reservations.end());
      store.last_replicated = id.seqno;
      if (replace)
      {
        ++store.rollback_count;
        store.last_committable = std::min(store.last_committable, id.seqno - 1);
        store.snapshot_requested.store(false, std::memory_order_release);
        store.pending_txs.clear();
        for (auto& [_, deltas] : store.map_deltas)
        {
          deltas.erase(deltas.lower_bound(id.seqno), deltas.end());
        }
        if (store.history)
        {
          store.history->rollback({id.view, id.seqno - 1}, store.term);
        }
        if (store.chunker)
        {
          store.chunker->rolled_back_to(id.seqno - 1);
        }
      }
      hooks = store.record_commit_locked(id.seqno, writes);
      claims = decoder.consume_claims_digest();
      evidence = decoder.consume_commit_evidence_digest();
      if (signature)
      {
        store.last_committable = id.seqno;
        if (store.history && !store.history->verify_root_signatures(id.seqno))
        {
          LOG_FAIL_FMT("Rust KV signature verification failed at {}", id.seqno);
          return ApplyResult::FAIL;
        }
      }
      if (store.history)
      {
        store.history->append_entry(ccf::entry_leaf(data, evidence, claims));
      }
      if (store.chunker)
      {
        store.chunker->append_entry_size(data.size());
        if ((flags & EntryFlags::FORCE_LEDGER_CHUNK_BEFORE) != 0)
        {
          store.chunker->produced_chunk_at(id.seqno - 1);
        }
        if ((flags & EntryFlags::FORCE_LEDGER_CHUNK_AFTER) != 0)
        {
          store.chunker->produced_chunk_at(id.seqno);
        }
      }
      if (writes.contains(Tables::ENCRYPTED_PAST_LEDGER_SECRET))
      {
        return ApplyResult::PASS_ENCRYPTED_PAST_LEDGER_SECRET;
      }
      return signature ? ApplyResult::PASS_SIGNATURE : ApplyResult::PASS;
    }

    ConsensusHookPtrs& get_hooks() override
    {
      return hooks;
    }

    const std::vector<uint8_t>& get_entry() override
    {
      return data;
    }

    Term get_term() override
    {
      return applied.view;
    }

    Version get_index() override
    {
      return applied.seqno;
    }

    ClaimsDigest&& consume_claims_digest() override
    {
      return std::move(claims);
    }

    std::optional<ccf::crypto::Sha256Hash>&& consume_commit_evidence_digest()
      override
    {
      return std::move(evidence);
    }
  };

  std::unique_ptr<AbstractExecutionWrapper> RustStore::deserialize(
    const std::vector<uint8_t>& data,
    bool public_only,
    const std::optional<TxID>& expected_txid)
  {
    KV_TRACE(trace::unsupported(this, "deserialisation"));
    return std::make_unique<RustReplayEntry>(
      *this, data, public_only, expected_txid);
  }

  CommitResult RustStore::commit(
    const TxID& id, std::unique_ptr<PendingTx> entry, bool committable)
  {
    std::lock_guard ordered(commit_lock);

    std::vector<std::tuple<std::unique_ptr<PendingTx>, bool>>
      contiguous_pending_txs;
    Version previous_last_replicated = 0;
    Version next_last_replicated = 0;
    size_t previous_rollback_count = 0;
    View replication_view = 0;
    std::shared_ptr<Consensus> c;
    std::shared_ptr<TxHistory> h;
    std::shared_ptr<ILedgerChunker> ch;

    {
      std::lock_guard lock(state_lock);
      if (term != id.view)
      {
        return CommitResult::FAIL_NO_REPLICATE;
      }

      if (committable && id.seqno > last_committable)
      {
        last_committable = id.seqno;
      }

      if (pending_txs.empty() && id.seqno == last_replicated + 1)
      {
        contiguous_pending_txs.emplace_back(std::move(entry), committable);
      }
      else
      {
        pending_txs.insert(
          {id.seqno, std::make_tuple(std::move(entry), committable)});

        for (Version offset = 1;; ++offset)
        {
          auto search = pending_txs.find(last_replicated + offset);
          if (search == pending_txs.end())
          {
            break;
          }
          contiguous_pending_txs.emplace_back(std::move(search->second));
          pending_txs.erase(search);
        }
      }

      previous_rollback_count = rollback_count;
      previous_last_replicated = last_replicated;
      next_last_replicated = last_replicated + contiguous_pending_txs.size();
      replication_view = term;
      c = consensus;
      h = history;
      ch = chunker;
    }

    if (contiguous_pending_txs.empty())
    {
      return CommitResult::SUCCESS;
    }

    BatchVector batch;
    if (c)
    {
      batch.reserve(contiguous_pending_txs.size());
    }

    size_t offset = 1;
    for (auto& [pending_tx, entry_committable] : contiguous_pending_txs)
    {
      auto info = pending_tx->call();
      if (info.success != CommitResult::SUCCESS)
      {
        return info.success;
      }

      if (c)
      {
        auto data_shared =
          std::make_shared<std::vector<uint8_t>>(std::move(info.data));
        auto hooks_shared =
          std::make_shared<ConsensusHookPtrs>(std::move(info.hooks));

        if (h)
        {
          h->append_entry(
            ccf::entry_leaf(
              *data_shared, info.commit_evidence_digest, info.claims_digest),
            replication_view);
        }

        if (ch)
        {
          std::lock_guard lock(state_lock);
          if (
            previous_rollback_count == rollback_count &&
            replication_view == term)
          {
            ch->append_entry_size(data_shared->size());
          }
        }

        batch.emplace_back(
          previous_last_replicated + offset,
          std::move(data_shared),
          entry_committable,
          std::move(hooks_shared));
      }

      ++offset;
    }

    if (c)
    {
      {
        std::lock_guard lock(state_lock);
        if (
          previous_rollback_count != rollback_count || replication_view != term)
        {
          return CommitResult::FAIL_NO_REPLICATE;
        }
      }
      if (!c->replicate(batch, replication_view))
      {
        return CommitResult::FAIL_NO_REPLICATE;
      }
    }

    {
      std::lock_guard lock(state_lock);
      if (
        last_replicated == previous_last_replicated &&
        previous_rollback_count == rollback_count)
      {
        last_replicated = next_last_replicated;
      }
    }

    return CommitResult::SUCCESS;
  }

  std::unique_ptr<AbstractStore::AbstractSnapshot> RustStore::
    snapshot_unsafe_maps(Version version)
  {
    std::shared_ptr<TxHistory> h;
    std::shared_ptr<Consensus> c;
    {
      std::lock_guard lock(state_lock);
      if (version < global)
      {
        throw std::logic_error(std::format(
          "Cannot snapshot at version {} which is earlier than last "
          "compacted version {} ",
          version,
          global));
      }
      if (version > head)
      {
        throw std::logic_error(std::format(
          "Cannot snapshot at version {} which is later than current "
          "version {} ",
          version,
          head));
      }
      h = history;
      c = consensus;
    }
    auto r = dispatch_read({.op = Opcode::SNAPSHOT_MAPS, .number = version});
    r.require();
    auto snapshot = std::make_unique<StoreSnapshot>(version);
    if (h)
    {
      snapshot->add_hash_at_snapshot(h->get_raw_leaf(version));
    }
    if (c)
    {
      snapshot->add_view_history(c->get_view_history(version));
    }
    for (size_t i = 0; i < r.size; ++i)
    {
      const auto map = ccf_rust_kv_snapshot_map(r.data.get(), i);
      const auto name = copy(map.name);
      Rows rows;
      rows.reserve(map.size);
      for (size_t j = 0; j < map.size; ++j)
      {
        const auto row = ccf_rust_kv_snapshot_cell(r.data.get(), i, j);
        rows.emplace_back(
          copy(row.key), untyped::VersionV{row.version, copy(row.value)});
      }
      snapshot->add_map_snapshot(std::make_unique<RustMapSnapshot>(
        std::string(name.begin(), name.end()), map.revision, std::move(rows)));
    }
    return snapshot;
  }

  std::unique_ptr<AbstractStore::AbstractSnapshot> RustStore::snapshot_maps(
    Version version)
  {
    std::lock_guard lock(maps_lock);
    return snapshot_unsafe_maps(version);
  }

  std::vector<uint8_t> RustStore::serialise_snapshot(
    std::unique_ptr<AbstractStore::AbstractSnapshot> snapshot)
  {
    EncryptorPtr e;
    {
      std::lock_guard lock(state_lock);
      e = encryptor;
    }
    return snapshot->serialise(e);
  }

  void RustStore::swap_private_maps(RustStore& source)
  {
    KV_TRACE(trace::unsupported(this, "swap private maps"));
    KV_TRACE(trace::unsupported(&source, "swap private maps"));
    if (this == &source)
    {
      throw std::logic_error("Cannot swap a Rust KV store with itself");
    }
    std::scoped_lock maps_guard(maps_lock, source.maps_lock);
    std::scoped_lock state_guard(state_lock, source.state_lock);
    if (source.head > head)
    {
      throw std::runtime_error(std::format(
        "Invalid call to swap_private_maps. Source is at version {} while "
        "target is at {}",
        source.head,
        head));
    }
    if (!open_reservations.empty() || !source.open_reservations.empty())
    {
      throw std::logic_error("Cannot swap maps with outstanding reservations");
    }
    auto* first = this < &source ? this : &source;
    auto* second = this < &source ? &source : this;
    ShardedRwLock::WriteGuard first_guard(first->native_lock);
    ShardedRwLock::WriteGuard second_guard(second->native_lock);
    sync_hazards_locked();
    source.sync_hazards_locked();
    auto response = source.dispatch_read_locked(
      {.op = Opcode::SNAPSHOT_MAPS, .number = source.head});
    response.require();
    std::vector<std::string> names;
    for (size_t i = 0; i < response.size; ++i)
    {
      const auto raw =
        copy(ccf_rust_kv_snapshot_map(response.data.get(), i).name);
      std::string name(raw.begin(), raw.end());
      if (get_security_domain(name) == SecurityDomain::PRIVATE)
      {
        names.push_back(std::move(name));
      }
    }
    std::vector<ByteView> views;
    for (const auto& name : names)
    {
      views.push_back(bytes(name));
    }
    const auto status = ccf_rust_kv_swap_recovery_maps(
      native.get(), source.native.get(), views.data(), views.size());
    if (status != Status::OK)
    {
      throw std::logic_error(std::format(
        "Rust KV could not swap private maps (status {})",
        static_cast<unsigned>(status)));
    }
    for (const auto& name : names)
    {
      map_deltas.erase(name);
      source.map_deltas.erase(name);
    }
  }

  ApplyResult RustStore::deserialise_snapshot(
    const uint8_t* data,
    size_t size,
    ConsensusHookPtrs& hooks,
    std::vector<Version>* view_history,
    bool public_only)
  {
    return deserialise_snapshot_internal(
      data, size, nullptr, hooks, view_history, public_only, nullptr, nullptr);
  }

  ApplyResult RustStore::deserialise_snapshot_in_place(
    std::span<uint8_t> data,
    ConsensusHookPtrs& hooks,
    std::vector<Version>* view_history,
    const SnapshotPublicMaps* public_maps)
  {
    return deserialise_snapshot_internal(
      data.data(),
      data.size(),
      data.data(),
      hooks,
      view_history,
      false,
      nullptr,
      public_maps);
  }

  ApplyResult RustStore::deserialise_public_snapshot_capturing(
    const uint8_t* data,
    size_t size,
    ConsensusHookPtrs& hooks,
    std::vector<Version>* view_history,
    std::optional<SnapshotPublicMaps>& captured)
  {
    captured.reset();
    return deserialise_snapshot_internal(
      data, size, nullptr, hooks, view_history, true, &captured, nullptr);
  }

  ApplyResult RustStore::deserialise_snapshot_internal(
    const uint8_t* data,
    size_t size,
    uint8_t* writable,
    ConsensusHookPtrs& hooks,
    std::vector<Version>* view_history,
    bool public_only,
    std::optional<SnapshotPublicMaps>* capture,
    const SnapshotPublicMaps* reuse)
  {
    KV_TRACE(trace::unsupported(this, "snapshot import"));
    std::scoped_lock lock(maps_lock, state_lock);
    RawKvStoreDeserialiser decoder(
      encryptor, public_only ? std::make_optional(PUBLIC) : std::nullopt);
    Term read_term = 0;
    EntryFlags flags{};
    const auto version = writable ?
      decoder.init_in_place(writable, size, read_term, flags, is_historical) :
      decoder.init(data, size, read_term, flags, is_historical);
    if (
      !version || flags != 0 || decoder.get_entry_type() != EntryType::Snapshot)
    {
      LOG_FAIL_FMT("Rust KV could not decode the snapshot envelope");
      return ApplyResult::FAIL;
    }
    if (reuse != nullptr && reuse->version != *version)
    {
      LOG_FAIL_FMT("Rust KV snapshot does not match the captured version");
      return ApplyResult::FAIL;
    }
    auto hash_at_snapshot =
      history ? decoder.deserialise_raw() : std::vector<uint8_t>{};
    auto decoded_history = view_history ? decoder.deserialise_view_history() :
                                          std::vector<Version>{};

    struct MapImage
    {
      Version revision;
      Rows rows;
      std::vector<SnapshotCell> views;
    };

    struct AddressMapOrder
    {
      bool operator()(const std::string& a, const std::string& b) const
      {
        return a.size() != b.size() ? a.size() < b.size() : a < b;
      }
    };

    std::map<std::string, MapImage, AddressMapOrder> maps;
    SnapshotPublicMaps captured;
    captured.version = *version;
    size_t reused = 0;
    for (auto name = decoder.start_map(); name; name = decoder.start_map())
    {
      const auto domain = parse_map_name(*name).first;
      if ((public_only && domain != PUBLIC) || maps.contains(*name))
      {
        LOG_FAIL_FMT("Rust KV snapshot contains a duplicate or invalid map");
        return ApplyResult::FAIL;
      }
      const auto revision = decoder.deserialise_entry_version();
      const auto raw = decoder.deserialise_raw_span();
      Rows rows;
      if (reuse != nullptr && domain == PUBLIC)
      {
        const auto it = reuse->maps.find(*name);
        if (
          it == reuse->maps.end() || it->second.revision != revision ||
          it->second.digest != ccf::crypto::Sha256Hash(raw.data(), raw.size()))
        {
          LOG_FAIL_FMT("Rust KV snapshot map differs from captured public map");
          return ApplyResult::FAIL;
        }
        rows = it->second.rows;
        ++reused;
      }
      else
      {
        rows = decode_snapshot_rows(raw);
        if (capture != nullptr && domain == PUBLIC)
        {
          captured.maps.emplace(
            *name,
            SnapshotPublicMaps::CapturedMap{
              revision, ccf::crypto::Sha256Hash(raw.data(), raw.size()), rows});
        }
      }
      auto& image = maps.emplace(*name, MapImage{revision, std::move(rows), {}})
                      .first->second;
      for (const auto& [key, value] : image.rows)
      {
        image.views.push_back({bytes(key), bytes(value.value), value.version});
      }
    }
    if (reuse != nullptr && reused != reuse->maps.size())
    {
      LOG_FAIL_FMT("Rust KV snapshot omits captured public maps");
      return ApplyResult::FAIL;
    }
    std::vector<SnapshotInput> inputs;
    for (const auto& [name, image] : maps)
    {
      inputs.push_back(
        {{bytes(name), image.revision, image.views.size()},
         image.views.data()});
    }
    Status status;
    {
      ShardedRwLock::WriteGuard native_guard(native_lock);
      sync_hazards_locked();
      status = ccf_rust_kv_install_snapshot(
        native.get(), *version, inputs.data(), inputs.size());
    }
    if (status != Status::OK)
    {
      LOG_FAIL_FMT(
        "Rust KV did not install snapshot {} (status {})",
        *version,
        static_cast<unsigned>(status));
      return ApplyResult::FAIL;
    }
    head = *version;
    open_reservations.clear();
    last_replicated = head;
    pending_txs.clear();
    global = *version;
    last_committable = *version;
    last_view.store(read_term, std::memory_order_release);
    for (const auto& [name, _] : maps)
    {
      map_deltas.erase(name);
    }
    for (const auto& [name, image] : maps)
    {
      const auto it = local_hooks.find(name);
      const auto glob = global_hooks.find(name);
      const bool local = it != local_hooks.end() && it->second;
      const bool global_hook = glob != global_hooks.end() && glob->second;
      if ((local || global_hook) && !image.rows.empty())
      {
        untyped::Write writes;
        for (const auto& [key, value] : image.rows)
        {
          writes.emplace(key, value.value);
        }
        if (local)
        {
          if (auto hook = it->second(image.revision, writes); hook)
          {
            hooks.push_back(std::move(hook));
          }
        }
        map_deltas[name].emplace(image.revision, MapDelta{std::move(writes)});
      }
    }
    if (view_history)
    {
      *view_history = std::move(decoded_history);
    }
    if (this->history && !this->history->init_from_snapshot(hash_at_snapshot))
    {
      LOG_FAIL_FMT("Rust KV could not initialise history from the snapshot");
      return ApplyResult::FAIL;
    }
    if (capture)
    {
      *capture = std::move(captured);
    }
    return ApplyResult::PASS;
  }

  bool RustStore::acquire_map_for_tx(
    NativeTx* tx,
    const std::string& map_name,
    bool& registered,
    int& hazard_slot,
    const std::optional<TxID>& reserved,
    bool explicit_read_txid,
    std::optional<TxID>& read_txid,
    View& commit_view
#ifdef CCF_KV_TRACING
    ,
    trace::Identity trace_id
#endif
  )
  {
#ifdef CCF_KV_TRACING
    const bool had_snapshot = read_txid.has_value();
    auto emit_acquire_trace =
      [&](const Response& res, uint64_t local_rev, uint64_t global_rev) {
        if (!trace::enabled())
        {
          return;
        }
        trace::Context trace_context(trace_id);
        if (!had_snapshot)
        {
          trace::snapshot(this, res.number, res.detail);
        }
        if (res.status == Status::OK)
        {
          trace::operation(
            trace_id,
            "map_acquire",
            map_name,
            {{"version", local_rev}, {"global", global_rev}});
        }
        else
        {
          trace::operation(trace_id, "map_unavailable", map_name);
        }
      };
#endif
    bool acquired = false;
    if (!registered && !reserved.has_value() && !explicit_read_txid)
    {
      if (hazard_slot < 0)
      {
        hazard_slot = try_claim_hazard_slot();
      }
      if (hazard_slot >= 0)
      {
        auto& slot = hazard_slots[static_cast<size_t>(hazard_slot)];
        size_t free_entries = 0;
        for (const auto& existing : slot.roots)
        {
          if (existing.load(std::memory_order_relaxed) == 0)
          {
            ++free_entries;
          }
        }
        if (free_entries >= 2)
        {
          uint32_t r0 = 0;
          uint32_t r1 = 0;
          uint64_t local_rev = 0;
          uint64_t global_rev = 0;
          auto r = [&]() {
            ShardedRwLock::ReadGuard guard(native_lock);
            auto res = wrap_reply(ccf_rust_kv_tx_ro_acquire(
              native.get(),
              tx,
              bytes(map_name),
              &r0,
              &r1,
              &local_rev,
              &global_rev));
            if (res.status == Status::OK)
            {
              auto add_root = [&](uint32_t root) {
                if (root == 0)
                {
                  return;
                }
                for (auto& existing : slot.roots)
                {
                  const auto cur = existing.load(std::memory_order_relaxed);
                  if (cur == root)
                  {
                    return;
                  }
                  if (cur == 0)
                  {
                    existing.store(root, std::memory_order_release);
                    return;
                  }
                }
              };
              add_root(r0);
              add_root(r1);
              if (slot.snap_plus_one.load(std::memory_order_relaxed) == 0)
              {
                slot.snap_plus_one.store(
                  res.number + 1, std::memory_order_release);
              }
            }
            if (res.status == Status::OK || res.status == Status::UNAVAILABLE)
            {
              KV_TRACE(emit_acquire_trace(res, local_rev, global_rev));
            }
            return res;
          }();
          if (r.status == Status::UNAVAILABLE)
          {
            if (!read_txid.has_value())
            {
              read_txid =
                TxID{last_view.load(std::memory_order_acquire), r.number};
            }
            return false;
          }
          r.require();
          if (!read_txid.has_value())
          {
            commit_view = r.detail;
            read_txid =
              TxID{last_view.load(std::memory_order_acquire), r.number};
          }
          acquired = true;
        }
        else
        {
          uint64_t local_rev = 0;
          uint64_t global_rev = 0;
          ShardedRwLock::WriteGuard guard(native_lock);
          const auto pstatus = ccf_rust_kv_tx_promote(native.get(), tx);
          if (pstatus != Status::OK)
          {
            throw std::logic_error(
              "Unexpected Rust KV promote status " +
              std::to_string(static_cast<unsigned>(pstatus)));
          }
          registered = true;
          release_hazard_slot(hazard_slot);
          hazard_slot = -1;
          auto r = wrap_reply(ccf_rust_kv_tx_snapshot_and_acquire(
            native.get(),
            tx,
            bytes(map_name),
            false,
            0,
            &local_rev,
            &global_rev));
          if (r.status == Status::OK || r.status == Status::UNAVAILABLE)
          {
            KV_TRACE(emit_acquire_trace(r, local_rev, global_rev));
          }
          if (r.status == Status::UNAVAILABLE)
          {
            return false;
          }
          r.require();
          acquired = true;
        }
      }
    }
    if (!acquired)
    {
      const bool has_explicit_ver = reserved.has_value() || explicit_read_txid;
      const Version explicit_ver = reserved.has_value() ?
        reserved->seqno - 1 :
        (read_txid.has_value() ? read_txid->seqno : 0);
      uint64_t local_rev = 0;
      uint64_t global_rev = 0;
      auto r = [&]() {
        ShardedRwLock::WriteGuard guard(native_lock);
        auto res = wrap_reply(ccf_rust_kv_tx_snapshot_and_acquire(
          native.get(),
          tx,
          bytes(map_name),
          has_explicit_ver,
          explicit_ver,
          &local_rev,
          &global_rev));
        if (res.status == Status::OK || res.status == Status::UNAVAILABLE)
        {
          KV_TRACE(emit_acquire_trace(res, local_rev, global_rev));
        }
        return res;
      }();
      registered = true;
      if (
        r.status == Status::UNAVAILABLE ||
        (explicit_read_txid && r.status == Status::DISABLED &&
         explicit_ver < compacted_version()))
      {
        if (r.status != Status::UNAVAILABLE)
        {
          KV_TRACE(emit_acquire_trace(r, local_rev, global_rev));
        }
        return false;
      }
      r.require();
      if (!read_txid.has_value())
      {
        commit_view = r.detail;
        read_txid = TxID{last_view.load(std::memory_order_acquire), r.number};
      }
    }
    return true;
  }

  PendingTxInfo RustStore::commit_tx_impl(TxCommitParams& params)
  {
    using TxFlag = CommittableTx::TxFlag;
    auto flag_enabled = [&](TxFlag flag) {
      return (params.flags & static_cast<CommittableTx::TxFlags>(flag)) != 0;
    };
    auto unset_flag = [&](TxFlag flag) {
      params.flags &= ~static_cast<CommittableTx::TxFlags>(flag);
    };
    auto result_only = [](CommitResult result) -> PendingTxInfo {
      return {result, {}, empty_claims(), {}, {}};
    };
    if (params.committed || params.committing)
    {
      throw std::logic_error("Transaction already committed");
    }
    if (params.is_reserved != params.reserved.has_value())
    {
      throw std::logic_error("Use the commit method for this transaction kind");
    }
#ifdef CCF_KV_TRACING
    std::optional<trace::Commit> trace_commit;
    if (params.is_reserved)
    {
      KV_TRACE(trace::unsupported(this, "reserved transaction"));
    }
    else
    {
      trace_commit.emplace(params.trace_id);
    }
#endif
    if (!params.has_any_changes || params.rust_tx == nullptr)
    {
      if (params.is_reserved)
      {
        throw std::logic_error("Reserved transaction cannot be empty");
      }
      params.committed = true;
      params.success = true;
      params.committing = true;
      KV_TRACE(trace_commit->result("success", 0));
      return result_only(CommitResult::SUCCESS);
    }

    auto pending = wrap_reply(ccf_rust_kv_tx_pending_writes(params.rust_tx));
    pending.require();
    if (params.is_reserved && pending.size == 0)
    {
      throw std::logic_error("Reserved transaction cannot be empty");
    }

    MapWrites writes;
    EncryptorPtr enc;
    size_t max_size = max_serialised_entry_size;
    if (pending.size != 0)
    {
      if (params.claims.empty())
      {
        throw std::logic_error("Missing claims");
      }
      {
        std::lock_guard lock(state_lock);
        enc = encryptor;
        max_size = max_entry_size;
      }
      if (enc == nullptr)
      {
        throw KvSerialiserException("No encryptor set");
      }
      writes = collect_writes(pending);
      pending.data.reset();
      if (!params.is_reserved)
      {
        auto checked_add = [](size_t& acc, size_t delta) -> bool {
          if (delta > std::numeric_limits<size_t>::max() - acc)
          {
            return false;
          }
          acc += delta;
          return true;
        };
        size_t est = sizeof(SerialisedEntryHeader) + enc->get_header_length() +
          sizeof(size_t);
        bool ok = checked_add(
          est,
          sizeof(uint8_t) + sizeof(Version) +
            sizeof(ccf::crypto::Sha256Hash::Representation) * 2 +
            sizeof(Version));
        for (const auto& [name, rows] : writes)
        {
          if (!ok)
          {
            break;
          }
          ok = checked_add(
            est,
            sizeof(size_t) + name.size() + sizeof(Version) +
              sizeof(uint64_t) * 3);
          for (const auto& [key, val] : rows)
          {
            if (!ok)
            {
              break;
            }
            const size_t row_bytes = val.has_value() ?
              (sizeof(size_t) * 2 + key.size() + val->size()) :
              (sizeof(size_t) + key.size());
            ok = checked_add(est, row_bytes);
          }
        }
        if (!ok || est > max_size)
        {
          SizeKvStoreSerialiser shape(
            enc,
            {params.commit_view, NoVersion},
            EntryType::WriteSetWithCommitEvidenceAndClaims,
            0,
            {},
            params.claims);
          serialise_writes(shape, writes);
          const auto size = shape.get_serialised_size();
          if (size > max_size)
          {
            throw MaxTransactionSizeExceeded(
              describe_serialised_entry_size_error(size, max_size));
          }
        }
      }
    }

    TxID id{};
    size_t epoch = 0;
    SerialisedEntryFlags local_entry_flags = 0;
    ConsensusHookPtrs hooks;

    {
      std::scoped_lock lock(maps_lock, state_lock);
      if (params.is_reserved)
      {
        const auto reserved_id = *params.reserved;
        if (params.reserve_epoch != rollback_count || reserved_id.view != term)
        {
          params.committing = true;
          params.aborted = true;
          params.committed = true;
          params.success = false;
          params.version = reserved_id.seqno;
          return result_only(CommitResult::FAIL_NO_REPLICATE);
        }
        if (!open_reservations.contains(reserved_id.seqno))
        {
          throw std::logic_error("Reserved transaction slot is not open");
        }
      }

      if (!writes.empty())
      {
        enc = encryptor;
        max_size = max_entry_size;
        if (enc == nullptr)
        {
          throw KvSerialiserException("No encryptor set");
        }
      }

      params.committing = true;
#ifdef CCF_KV_TRACING
      trace::Json trace_writes;
      if (!params.is_reserved && trace::enabled())
      {
        trace_writes = trace::Json::array();
        for (const auto& [name, rows] : writes)
        {
          for (const auto& [key, val] : rows)
          {
            trace_writes.push_back(
              {{"map", name},
               {"key", ccf::ds::to_hex(key)},
               {"value", trace::bytes(val.has_value() ? &*val : nullptr)}});
          }
        }
      }
      std::optional<trace::Context> trace_context;
      if (!params.is_reserved)
      {
        trace_context.emplace(params.trace_id, &trace_writes, &*trace_commit);
      }
#endif
      auto applied = [&]() {
        ShardedRwLock::WriteGuard native_guard(native_lock);
        auto res = params.is_reserved ?
          wrap_reply(ccf_rust_kv_tx_commit_reserved(
            native.get(), params.rust_tx, params.reserved->seqno)) :
          wrap_reply(
            ccf_rust_kv_tx_prepare_commit(native.get(), params.rust_tx));
        if (!params.is_reserved)
        {
          if (res.status == Status::CONFLICT)
          {
            KV_TRACE(trace::local_result("conflict", 0));
          }
          else if (res.status == Status::STALE_TERM)
          {
            KV_TRACE(trace::local_result("no_replicate", 0));
          }
          else if (res.status == Status::READ_ONLY)
          {
            KV_TRACE(trace::local_result("success", 0));
          }
          else if (res.status == Status::OK)
          {
            KV_TRACE(trace::apply(this, res.number, res.detail));
          }
        }
        return res;
      }();
      if (applied.status == Status::CONFLICT)
      {
        if (params.is_reserved)
        {
          throw std::logic_error("Failed to commit reserved transaction");
        }
        params.success = false;
        KV_TRACE(trace_commit->result("conflict", 0));
        return result_only(CommitResult::FAIL_CONFLICT);
      }
      if (applied.status == Status::STALE_TERM)
      {
        params.success = false;
        KV_TRACE(trace_commit->result("no_replicate", 0));
        return result_only(CommitResult::FAIL_NO_REPLICATE);
      }
      if (applied.status == Status::READ_ONLY)
      {
        if (
          flag_enabled(TxFlag::SNAPSHOT_AT_NEXT_SIGNATURE) &&
          params.has_snapshot)
        {
          snapshot_requested.store(true, std::memory_order_release);
          unset_flag(TxFlag::SNAPSHOT_AT_NEXT_SIGNATURE);
        }
        params.version = NoVersion;
        params.committed = true;
        params.success = true;
        KV_TRACE(trace_commit->result("success", 0));
        return result_only(CommitResult::SUCCESS);
      }
      applied.require();
      if (params.is_reserved)
      {
        open_reservations.erase(applied.number);
      }
      else
      {
        head = applied.number;
        last_view.store(applied.detail, std::memory_order_release);
      }
      id = TxID{applied.detail, applied.number};
      epoch = rollback_count;

      if (flag_enabled(TxFlag::LEDGER_CHUNK_BEFORE_THIS_TX))
      {
        local_entry_flags |= EntryFlags::FORCE_LEDGER_CHUNK_BEFORE;
      }
      if (!params.is_reserved)
      {
        apply_tx_flags_locked(
          id.seqno,
          flag_enabled(TxFlag::LEDGER_CHUNK_AT_NEXT_SIGNATURE),
          flag_enabled(TxFlag::SNAPSHOT_AT_NEXT_SIGNATURE));
      }
      else if (mark_reserved_chunk_locked(id.seqno))
      {
        local_entry_flags |= EntryFlags::FORCE_LEDGER_CHUNK_AFTER;
      }

      hooks = record_commit_locked(id.seqno, writes);
    }

    const auto evidence = enc->get_commit_evidence(id);
    auto evidence_digest = ccf::crypto::Sha256Hash(evidence);
    RawKvStoreSerialiser serialiser(
      enc,
      id,
      EntryType::WriteSetWithCommitEvidenceAndClaims,
      local_entry_flags,
      evidence_digest,
      params.claims,
      false,
      params.is_reserved ? max_serialised_entry_size : max_size);
    serialise_writes(serialiser, writes);
    auto data = serialiser.get_raw_data();

    if (params.is_reserved)
    {
      wrap_reply(ccf_rust_kv_tx_finish(
                   params.rust_tx, static_cast<uint64_t>(Outcome::SUCCESS)))
        .require();
      params.version = id.seqno;
      params.commit_view = id.view;
      params.committed = true;
      params.success = true;
      return {
        CommitResult::SUCCESS,
        std::move(data),
        empty_claims(),
        std::move(evidence_digest),
        std::move(hooks)};
    }

    // Match the C++ CommittableTx contract: once local application and
    // serialisation succeed, the assigned TxID is observable (including from
    // write_set_observer callbacks) before consensus replication completes.
    params.version = id.seqno;
    params.commit_view = id.view;
    params.committed = true;
    params.success = true;

    if (params.observer)
    {
      KV_TRACE(trace::unsupported(this, "write set observer"));
      const auto digest = ccf::crypto::Sha256Hash(data.data(), data.size());
      params.observer(digest, evidence);
    }

    bool survived_pre_commit = true;
    {
      std::lock_guard lock(state_lock);
      survived_pre_commit = (rollback_count == epoch && term == id.view);
    }

    ClaimsDigest claims_copy = params.claims;
    const auto commit_result = survived_pre_commit ?
      commit(
        id,
        std::make_unique<MovePendingTx>(
          std::move(data),
          std::move(claims_copy),
          std::move(evidence_digest),
          std::move(hooks)),
        false) :
      CommitResult::FAIL_NO_REPLICATE;

    const auto outcome = commit_result == CommitResult::SUCCESS ?
      Outcome::SUCCESS :
      Outcome::NO_REPLICATE;
    auto output = wrap_reply(
      ccf_rust_kv_tx_finish(params.rust_tx, static_cast<uint64_t>(outcome)));
    output.require();
    KV_TRACE(trace_commit->result(
      commit_result == CommitResult::SUCCESS ? "success" : "no_replicate",
      output.number));
    return result_only(commit_result);
  }

#ifdef CCF_USE_RUST_KV
  PendingTxInfo CommittableTx::commit_rust_impl(
    const ccf::ClaimsDigest& claims,
    const WriteSetObserver& observer,
    bool reserved)
  {
    auto& store = *pimpl->rust_store;
    RustStore::TxCommitParams params{
      .rust_tx = pimpl->rust_tx,
      .reserved = pimpl->rust_reserved,
      .reserve_epoch = pimpl->rust_reserve_epoch,
      .claims = claims,
      .observer = observer,
      .is_reserved = reserved,
      .has_any_changes = !all_changes.empty(),
      .has_snapshot = pimpl->read_txid.has_value(),
      .committing = pimpl->rust_committing,
      .committed = committed,
      .success = success,
      .aborted = pimpl->rust_aborted,
      .version = version,
      .commit_view = pimpl->commit_view,
      .flags = flags
#  ifdef CCF_KV_TRACING
      ,
      .trace_id = pimpl->trace_attempt.id
#  endif
    };
    auto info = store.commit_tx_impl(params);
    if (committed)
    {
      pimpl->rust_committed = true;
    }
    return info;
  }
#endif
}
