// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "kv/test/rust_kv_store.h"

namespace ccf::kv::rust_test
{
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
        // Fast path for the common in-order commit: avoid touching the map.
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
      // Invoked without maps_lock/state_lock so reserved PendingTx::call() can
      // create/commit a reserved transaction or trigger rollback safely.
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

  Tx Store::create_reserved_tx(const TxID& version)
  {
    if (version.seqno == NoVersion)
    {
      throw std::logic_error("Reserved transaction needs a version");
    }
    auto tx = create_tx();
    std::lock_guard lock(state_lock);
    tx.state->reserved = version;
    tx.state->reserve_epoch = rollback_count;
    return tx;
  }

  CommitResult Tx::commit(
    const ClaimsDigest& claims, const CommittableTx::WriteSetObserver& observer)
  {
    return commit_impl(claims, observer, false).success;
  }

  PendingTxInfo Tx::commit_reserved()
  {
    return commit_impl(empty_claims(), nullptr, true);
  }

  PendingTxInfo Tx::commit_impl(
    const ClaimsDigest& claims,
    const CommittableTx::WriteSetObserver& observer,
    bool reserved)
  {
    using Flag = CommittableTx::TxFlag;
    auto& s = *state;
    auto& store = s.store;
    auto result_only = [](CommitResult result) -> PendingTxInfo {
      return {result, {}, empty_claims(), {}, {}};
    };
    if (s.committing)
    {
      throw std::logic_error("Transaction already committed");
    }
    if (reserved != s.reserved.has_value())
    {
      throw std::logic_error("Use the commit method for this transaction kind");
    }

    // Collect pending writes and run size pre-checks outside all store locks.
    auto pending =
      Store::wrap_reply(ccf_rust_kv_tx_pending_writes(s.native_tx));
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
        // Fast overflow-checked exact size pre-check; fall back to
        // SizeKvStoreSerialiser if close to or above the limit or on overflow.
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
            {s.captured_term.value(), NoVersion},
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
    SerialisedEntryFlags entry_flags = 0;
    ConsensusHookPtrs hooks;

    {
      std::scoped_lock lock(store.maps_lock, store.state_lock);
      if (reserved)
      {
        const auto reserved_id = *s.reserved;
        if (
          s.reserve_epoch != store.rollback_count ||
          reserved_id.view != store.term)
        {
          s.committing = true;
          s.aborted = true;
          s.version = reserved_id.seqno;
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

      s.committing = true;
      auto applied = reserved ?
        Store::wrap_reply(ccf_rust_kv_tx_commit_reserved(
          store.native.get(), s.native_tx, s.reserved->seqno)) :
        Store::wrap_reply(
          ccf_rust_kv_tx_prepare_commit(store.native.get(), s.native_tx));
      if (applied.status == Status::CONFLICT)
      {
        if (reserved)
        {
          throw std::logic_error("Failed to commit reserved transaction");
        }
        return result_only(CommitResult::FAIL_CONFLICT);
      }
      if (applied.status == Status::STALE_TERM)
      {
        return result_only(CommitResult::FAIL_NO_REPLICATE);
      }
      if (applied.status == Status::READ_ONLY)
      {
        if (
          tx_flag_enabled(Flag::SNAPSHOT_AT_NEXT_SIGNATURE) &&
          s.captured_term.has_value())
        {
          store.snapshot_requested.store(true, std::memory_order_release);
          unset_tx_flag(Flag::SNAPSHOT_AT_NEXT_SIGNATURE);
        }
        s.version = NoVersion;
        s.committed = true;
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
        store.last_view = applied.detail;
      }
      id = TxID{applied.detail, applied.number};
      epoch = store.rollback_count;

      if (tx_flag_enabled(Flag::LEDGER_CHUNK_BEFORE_THIS_TX))
      {
        entry_flags |= EntryFlags::FORCE_LEDGER_CHUNK_BEFORE;
      }
      if (!reserved)
      {
        store.apply_tx_flags_locked(
          id.seqno,
          tx_flag_enabled(Flag::LEDGER_CHUNK_AT_NEXT_SIGNATURE),
          tx_flag_enabled(Flag::SNAPSHOT_AT_NEXT_SIGNATURE));
      }
      else if (store.mark_reserved_chunk_locked(id.seqno))
      {
        entry_flags |= EntryFlags::FORCE_LEDGER_CHUNK_AFTER;
      }

      hooks = store.record_commit_locked(id.seqno, writes);
    }

    // Encryption, serialisation, commit evidence hashing, write-set observer,
    // and consensus replication all run outside maps_lock and state_lock.
    const auto evidence = encryptor->get_commit_evidence(id);
    auto evidence_digest = ccf::crypto::Sha256Hash(evidence);
    RawKvStoreSerialiser serialiser(
      encryptor,
      id,
      EntryType::WriteSetWithCommitEvidenceAndClaims,
      entry_flags,
      evidence_digest,
      claims,
      false,
      reserved ? max_serialised_entry_size : max_entry_size);
    serialise_writes(serialiser, writes);
    auto data = serialiser.get_raw_data();

    if (reserved)
    {
      Store::wrap_reply(ccf_rust_kv_tx_finish(
                          s.native_tx, static_cast<uint64_t>(Outcome::SUCCESS)))
        .require();
      s.version = id.seqno;
      s.committed = true;
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
    auto output = Store::wrap_reply(
      ccf_rust_kv_tx_finish(s.native_tx, static_cast<uint64_t>(outcome)));
    output.require();
    s.version = output.number;
    s.committed = true;
    return result_only(commit_result);
  }
}
