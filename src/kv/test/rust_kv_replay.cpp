// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ds/internal_logger.h"
#include "kv/internal_table_names.h"
#include "kv/test/rust_kv_store.h"

namespace ccf::kv::rust_test
{
  class ReplayEntry : public AbstractExecutionWrapper
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
    ReplayEntry(
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
      const auto version =
        decoder.init(data.data(), data.size(), term, flags, false);
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
      const auto status = ccf_rust_kv_replay(
        store.native.get(),
        id.seqno,
        entries.data(),
        entries.size(),
        track_deletes_on_missing_keys);
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
      store.last_view = id.view;
      store.reserved_through = id.seqno;
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
    return std::make_unique<ReplayEntry>(
      *this, data, public_only, expected_txid);
  }
}
