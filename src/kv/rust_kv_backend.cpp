// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ds/internal_logger.h"
#include "kv/committable_tx.h"
#include "kv/internal_table_names.h"
#include "kv/snapshot.h"
#include "kv/store.h"
#include "kv/tx_pimpl.h"
#include "kv/untyped_change_set.h"

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
    Store& store;
    const std::vector<uint8_t> data;
    const bool public_only;
    const std::optional<TxID> expected_txid;
    TxID applied;
    ConsensusHookPtrs hooks;
    ClaimsDigest claims = no_claims();
    std::optional<ccf::crypto::Sha256Hash> evidence;

  public:
    RustReplayEntry(
      Store& store_,
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
        Store::ShardedRwLock::WriteGuard native_guard(store.native_lock);
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

  std::unique_ptr<AbstractExecutionWrapper> Store::deserialize(
    const std::vector<uint8_t>& data,
    bool public_only,
    const std::optional<TxID>& expected_txid)
  {
    return std::make_unique<RustReplayEntry>(
      *this, data, public_only, expected_txid);
  }

  CommitResult Store::commit(
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

  std::unique_ptr<AbstractStore::AbstractSnapshot> Store::snapshot_unsafe_maps(
    Version version)
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

  std::unique_ptr<AbstractStore::AbstractSnapshot> Store::snapshot_maps(
    Version version)
  {
    std::lock_guard lock(maps_lock);
    return snapshot_unsafe_maps(version);
  }

  std::vector<uint8_t> Store::serialise_snapshot(
    std::unique_ptr<AbstractStore::AbstractSnapshot> snapshot)
  {
    EncryptorPtr e;
    {
      std::lock_guard lock(state_lock);
      e = encryptor;
    }
    return snapshot->serialise(e);
  }

  void Store::swap_private_maps(Store& source)
  {
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

  ApplyResult Store::deserialise_snapshot(
    const uint8_t* data,
    size_t size,
    ConsensusHookPtrs& hooks,
    std::vector<Version>* view_history,
    bool public_only)
  {
    return deserialise_snapshot_internal(
      data, size, nullptr, hooks, view_history, public_only, nullptr, nullptr);
  }

  ApplyResult Store::deserialise_snapshot_in_place(
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

  ApplyResult Store::deserialise_public_snapshot_capturing(
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

  ApplyResult Store::deserialise_snapshot_internal(
    const uint8_t* data,
    size_t size,
    uint8_t* writable,
    ConsensusHookPtrs& hooks,
    std::vector<Version>* view_history,
    bool public_only,
    std::optional<SnapshotPublicMaps>* capture,
    const SnapshotPublicMaps* reuse)
  {
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

    std::map<std::string, MapImage> maps;
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

  PendingTxInfo CommittableTx::commit_rust_impl(
    const ccf::ClaimsDigest& claims,
    const WriteSetObserver& observer,
    bool reserved)
  {
    auto result_only = [](CommitResult result) -> PendingTxInfo {
      return {result, {}, empty_claims(), {}, {}};
    };
    if (committed || pimpl->rust_committing)
    {
      throw std::logic_error("Transaction already committed");
    }
    if (reserved != pimpl->rust_reserved.has_value())
    {
      throw std::logic_error("Use the commit method for this transaction kind");
    }
    if (!reserved && all_changes.empty())
    {
      committed = true;
      success = true;
      pimpl->rust_committing = true;
      pimpl->rust_committed = true;
      return result_only(CommitResult::SUCCESS);
    }

    auto& store = *pimpl->rust_store;
    auto pending = wrap_reply(ccf_rust_kv_tx_pending_writes(pimpl->rust_tx));
    pending.require();
    if (reserved && pending.size == 0)
    {
      throw std::logic_error("Reserved transaction cannot be empty");
    }

    MapWrites writes;
    EncryptorPtr encryptor;
    size_t max_entry_size = max_serialised_entry_size;
    if (pending.size != 0)
    {
      if (claims.empty())
      {
        throw std::logic_error("Missing claims");
      }
      {
        std::lock_guard lock(store.state_lock);
        encryptor = store.encryptor;
        max_entry_size = store.max_entry_size;
      }
      if (encryptor == nullptr)
      {
        throw KvSerialiserException("No encryptor set");
      }
      writes = collect_writes(pending);
      pending.data.reset();
      if (!reserved)
      {
        auto checked_add = [](size_t& acc, size_t delta) -> bool {
          if (delta > std::numeric_limits<size_t>::max() - acc)
          {
            return false;
          }
          acc += delta;
          return true;
        };
        size_t est = sizeof(SerialisedEntryHeader) +
          encryptor->get_header_length() + sizeof(size_t);
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
        if (!ok || est > max_entry_size)
        {
          SizeKvStoreSerialiser shape(
            encryptor,
            {pimpl->commit_view, NoVersion},
            EntryType::WriteSetWithCommitEvidenceAndClaims,
            0,
            {},
            claims);
          serialise_writes(shape, writes);
          const auto size = shape.get_serialised_size();
          if (size > max_entry_size)
          {
            throw MaxTransactionSizeExceeded(
              describe_serialised_entry_size_error(size, max_entry_size));
          }
        }
      }
    }

    TxID id{};
    size_t epoch = 0;
    SerialisedEntryFlags local_entry_flags = 0;
    ConsensusHookPtrs hooks;

    {
      std::scoped_lock lock(store.maps_lock, store.state_lock);
      if (reserved)
      {
        const auto reserved_id = *pimpl->rust_reserved;
        if (
          pimpl->rust_reserve_epoch != store.rollback_count ||
          reserved_id.view != store.term)
        {
          pimpl->rust_committing = true;
          pimpl->rust_aborted = true;
          committed = true;
          success = false;
          version = reserved_id.seqno;
          return result_only(CommitResult::FAIL_NO_REPLICATE);
        }
        if (!store.open_reservations.contains(reserved_id.seqno))
        {
          throw std::logic_error("Reserved transaction slot is not open");
        }
      }

      if (!writes.empty())
      {
        encryptor = store.encryptor;
        max_entry_size = store.max_entry_size;
        if (encryptor == nullptr)
        {
          throw KvSerialiserException("No encryptor set");
        }
      }

      pimpl->rust_committing = true;
      auto applied = [&]() {
        Store::ShardedRwLock::WriteGuard native_guard(store.native_lock);
        return reserved ?
          wrap_reply(ccf_rust_kv_tx_commit_reserved(
            store.native.get(), pimpl->rust_tx, pimpl->rust_reserved->seqno)) :
          wrap_reply(
            ccf_rust_kv_tx_prepare_commit(store.native.get(), pimpl->rust_tx));
      }();
      if (applied.status == Status::CONFLICT)
      {
        if (reserved)
        {
          throw std::logic_error("Failed to commit reserved transaction");
        }
        success = false;
        return result_only(CommitResult::FAIL_CONFLICT);
      }
      if (applied.status == Status::STALE_TERM)
      {
        success = false;
        return result_only(CommitResult::FAIL_NO_REPLICATE);
      }
      if (applied.status == Status::READ_ONLY)
      {
        if (
          tx_flag_enabled(TxFlag::SNAPSHOT_AT_NEXT_SIGNATURE) &&
          pimpl->read_txid.has_value())
        {
          store.snapshot_requested.store(true, std::memory_order_release);
          unset_tx_flag(TxFlag::SNAPSHOT_AT_NEXT_SIGNATURE);
        }
        version = NoVersion;
        committed = true;
        success = true;
        pimpl->rust_committed = true;
        return result_only(CommitResult::SUCCESS);
      }
      applied.require();
      if (reserved)
      {
        store.open_reservations.erase(applied.number);
      }
      else
      {
        store.head = applied.number;
        store.last_view.store(applied.detail, std::memory_order_release);
      }
      id = TxID{applied.detail, applied.number};
      epoch = store.rollback_count;

      if (tx_flag_enabled(TxFlag::LEDGER_CHUNK_BEFORE_THIS_TX))
      {
        local_entry_flags |= EntryFlags::FORCE_LEDGER_CHUNK_BEFORE;
      }
      if (!reserved)
      {
        store.apply_tx_flags_locked(
          id.seqno,
          tx_flag_enabled(TxFlag::LEDGER_CHUNK_AT_NEXT_SIGNATURE),
          tx_flag_enabled(TxFlag::SNAPSHOT_AT_NEXT_SIGNATURE));
      }
      else if (store.mark_reserved_chunk_locked(id.seqno))
      {
        local_entry_flags |= EntryFlags::FORCE_LEDGER_CHUNK_AFTER;
      }

      hooks = store.record_commit_locked(id.seqno, writes);
    }

    const auto evidence = encryptor->get_commit_evidence(id);
    auto evidence_digest = ccf::crypto::Sha256Hash(evidence);
    RawKvStoreSerialiser serialiser(
      encryptor,
      id,
      EntryType::WriteSetWithCommitEvidenceAndClaims,
      local_entry_flags,
      evidence_digest,
      claims,
      false,
      reserved ? max_serialised_entry_size : max_entry_size);
    serialise_writes(serialiser, writes);
    auto data = serialiser.get_raw_data();

    if (reserved)
    {
      wrap_reply(ccf_rust_kv_tx_finish(
                   pimpl->rust_tx, static_cast<uint64_t>(Outcome::SUCCESS)))
        .require();
      version = id.seqno;
      pimpl->commit_view = id.view;
      committed = true;
      success = true;
      pimpl->rust_committed = true;
      return {
        CommitResult::SUCCESS,
        std::move(data),
        empty_claims(),
        std::move(evidence_digest),
        std::move(hooks)};
    }

    if (observer)
    {
      const auto digest = ccf::crypto::Sha256Hash(data.data(), data.size());
      observer(digest, evidence);
    }

    bool survived_pre_commit = true;
    {
      std::lock_guard lock(store.state_lock);
      survived_pre_commit =
        (store.rollback_count == epoch && store.term == id.view);
    }

    ClaimsDigest claims_copy = claims;
    const auto commit_result = survived_pre_commit ?
      store.commit(
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
      ccf_rust_kv_tx_finish(pimpl->rust_tx, static_cast<uint64_t>(outcome)));
    output.require();
    version = output.number;
    pimpl->commit_view = id.view;
    committed = true;
    success = true;
    pimpl->rust_committed = true;
    return result_only(commit_result);
  }
}
