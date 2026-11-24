// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "kv/test/rust_kv_store.h"

namespace ccf::kv::rust_test
{
  CommitResult Store::commit(
    const TxID& id, std::unique_ptr<PendingTx> entry, bool committable)
  {
    size_t epoch = 0;
    {
      std::lock_guard lock(mutex);
      if (term != id.view || id.seqno > reserved_through)
      {
        return CommitResult::FAIL_NO_REPLICATE;
      }
      epoch = rollback_count;
    }
    // The callback can publish a reserved transaction and roll back the store.
    auto info = entry->call();
    if (info.success != CommitResult::SUCCESS)
    {
      return info.success;
    }
    std::lock_guard ordered(commit_order);
    std::unique_lock lock(mutex);
    const auto slot = reserved_entries.find(id.seqno);
    if (
      term != id.view || epoch != rollback_count ||
      slot == reserved_entries.end() ||
      slot->second != std::make_pair(id.view, epoch))
    {
      return CommitResult::FAIL_NO_REPLICATE;
    }
    reserved_entries.erase(slot);
    const auto size = info.data.size();
    if (auto c = consensus)
    {
      if (history)
      {
        history->append_entry(
          ccf::entry_leaf(
            info.data, info.commit_evidence_digest, info.claims_digest),
          id.view);
      }
      BatchVector batch{
        {id.seqno,
         std::make_shared<std::vector<uint8_t>>(std::move(info.data)),
         committable,
         std::make_shared<ConsensusHookPtrs>(std::move(info.hooks))}};
      lock.unlock();
      const auto submitted = c->replicate(batch, id.view);
      lock.lock();
      if (!submitted || rollback_count != epoch || term != id.view)
      {
        return CommitResult::FAIL_NO_REPLICATE;
      }
      if (chunker)
      {
        chunker->append_entry_size(size);
      }
    }
    if (committable)
    {
      last_committable = std::max(last_committable, id.seqno);
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
    std::lock_guard lock(mutex);
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
    std::lock_guard ordered(store.commit_order);
    std::unique_lock lock(store.mutex);
    auto action = [&](Opcode op, Outcome outcome = Outcome::SUCCESS) {
      return store.dispatch(
        {.op = op, .attempt = s.id, .number = static_cast<uint64_t>(outcome)});
    };
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
    auto pending = action(Opcode::PENDING_WRITES);
    pending.require();
    if (reserved)
    {
      if (pending.size == 0)
      {
        throw std::logic_error("Reserved transaction cannot be empty");
      }
      const auto id = *s.reserved;
      if (s.reserve_epoch != store.rollback_count || id.view != store.term)
      {
        s.committing = true;
        s.aborted = true;
        s.version = id.seqno;
        return result_only(CommitResult::FAIL_NO_REPLICATE);
      }
      if (
        id.seqno <= store.head || id.seqno - store.head != 1 ||
        id.seqno > store.reserved_through)
      {
        throw std::logic_error("Reserved transaction is not the next slot");
      }
    }
    else if (pending.size != 0 && store.reserved_through > store.head)
    {
      throw std::logic_error(
        "A reserved slot must be filled before a normal write");
    }
    MapWrites writes;
    if (pending.size != 0)
    {
      if (claims.empty())
      {
        throw std::logic_error("Missing claims");
      }
      if (store.encryptor == nullptr)
      {
        throw KvSerialiserException("No encryptor set");
      }
      // CommitBegin freezes the pending writes, and Apply publishes that
      // same set while the store mutex is held.
      writes = collect_writes(pending);
      pending.data.reset();
      if (!reserved)
      {
        SizeKvStoreSerialiser shape(
          store.encryptor,
          {s.captured_term.value(), NoVersion},
          EntryType::WriteSetWithCommitEvidenceAndClaims,
          0,
          {},
          claims);
        serialise_writes(shape, writes);
        const auto size = shape.get_serialised_size();
        if (size > store.max_entry_size)
        {
          throw MaxTransactionSizeExceeded(
            describe_serialised_entry_size_error(size, store.max_entry_size));
        }
      }
    }
    action(Opcode::COMMIT_BEGIN).require();
    s.committing = true;
    auto applied = action(Opcode::APPLY);
    if (applied.status == Status::CONFLICT)
    {
      action(Opcode::COMMIT_RESULT, Outcome::CONFLICT).require();
      if (reserved)
      {
        throw std::logic_error("Failed to commit reserved transaction");
      }
      return result_only(CommitResult::FAIL_CONFLICT);
    }
    if (applied.status == Status::STALE_TERM)
    {
      action(Opcode::COMMIT_RESULT, Outcome::NO_REPLICATE).require();
      return result_only(CommitResult::FAIL_NO_REPLICATE);
    }

    if (applied.status == Status::READ_ONLY)
    {
      if (
        tx_flag_enabled(Flag::SNAPSHOT_AT_NEXT_SIGNATURE) &&
        s.captured_term.has_value())
      {
        store.snapshot_requested = true;
        unset_tx_flag(Flag::SNAPSHOT_AT_NEXT_SIGNATURE);
      }
      action(Opcode::COMMIT_RESULT).require();
      s.version = NoVersion;
      s.committed = true;
      return result_only(CommitResult::SUCCESS);
    }
    applied.require();
    store.head = applied.number;
    store.last_view = applied.detail;
    const TxID id{applied.detail, applied.number};
    const auto epoch = store.rollback_count;
    SerialisedEntryFlags entry_flags = 0;
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

    const auto evidence = store.encryptor->get_commit_evidence(id);
    auto evidence_digest = ccf::crypto::Sha256Hash(evidence);
    RawKvStoreSerialiser serialiser(
      store.encryptor,
      id,
      EntryType::WriteSetWithCommitEvidenceAndClaims,
      entry_flags,
      evidence_digest,
      claims,
      false,
      reserved ? max_serialised_entry_size : store.max_entry_size);
    auto hooks = store.record_commit(id.seqno, writes);
    serialise_writes(serialiser, writes);
    auto data = serialiser.get_raw_data();
    if (reserved)
    {
      action(Opcode::COMMIT_RESULT).require();
      s.version = id.seqno;
      s.committed = true;
      store.reserved_entries.emplace(id.seqno, std::make_pair(id.view, epoch));
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
      lock.unlock();
      observer(digest, evidence);
      lock.lock();
    }
    auto survives = [&]() {
      return store.rollback_count == epoch && store.term == id.view;
    };
    bool submitted = survives();
    const auto data_size = data.size();
    if (auto consensus = store.consensus; consensus && submitted)
    {
      if (store.history)
      {
        store.history->append_entry(
          ccf::entry_leaf(data, evidence_digest, claims), id.view);
      }
      BatchVector batch{
        {id.seqno,
         std::make_shared<std::vector<uint8_t>>(std::move(data)),
         false,
         std::make_shared<ConsensusHookPtrs>(std::move(hooks))}};
      lock.unlock();
      submitted = consensus->replicate(batch, id.view);
      lock.lock();
      submitted = submitted && survives();
      if (submitted && store.chunker)
      {
        store.chunker->append_entry_size(data_size);
      }
    }
    auto output = action(
      Opcode::COMMIT_RESULT,
      submitted ? Outcome::SUCCESS : Outcome::NO_REPLICATE);
    output.require();
    s.version = output.number;
    s.committed = true;
    return result_only(
      submitted ? CommitResult::SUCCESS : CommitResult::FAIL_NO_REPLICATE);
  }
}
