// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ccf_assert.h"
#include "ccf/ds/logger.h"
#include "consensus/ledger_enclave_types.h"
#include "ds/thread_messaging.h"
#include "kv/kv_types.h"
#include "kv/store.h"
#include "node/network_state.h"
#include "node/snapshot_serdes.h"
#include "service/tables/snapshot_evidence.h"

#include <deque>
#include <optional>

namespace ccf
{
  class Snapshotter : public std::enable_shared_from_this<Snapshotter>,
                      public kv::AbstractSnapshotter
  {
  public:
    static constexpr auto max_tx_interval = std::numeric_limits<size_t>::max();

  private:
    ringbuffer::WriterPtr to_host;
    ccf::Mutex lock;

    std::shared_ptr<kv::Store> store;

    // Snapshots are never generated by default (e.g. during public recovery)
    size_t snapshot_tx_interval = max_tx_interval;

    struct SnapshotInfo
    {
      consensus::Index idx;
      consensus::Index evidence_idx;

      crypto::Sha256Hash write_set_digest;
      std::string commit_evidence;
      crypto::Sha256Hash snapshot_digest;

      std::optional<NodeId> node_id = std::nullopt;
      std::optional<crypto::Pem> node_cert = std::nullopt;
      std::optional<std::vector<uint8_t>> sig = std::nullopt;
      std::optional<std::vector<uint8_t>> tree = std::nullopt;

      SnapshotInfo(
        consensus::Index idx,
        consensus::Index evidence_idx,
        const crypto::Sha256Hash& write_set_digest_,
        const std::string& commit_evidence_,
        const crypto::Sha256Hash& snapshot_digest_) :
        idx(idx),
        evidence_idx(evidence_idx),
        write_set_digest(write_set_digest_),
        commit_evidence(commit_evidence_),
        snapshot_digest(snapshot_digest_)
      {}
    };
    // Queue of pending snapshots that have been generated, but are not yet
    // committed
    std::deque<SnapshotInfo> pending_snapshots;

    // Initial snapshot index
    static constexpr consensus::Index initial_snapshot_idx = 0;

    // Index at which the lastest snapshot was generated
    consensus::Index last_snapshot_idx = 0;

    // Used to suspend snapshot generation during public recovery
    bool snapshot_generation_enabled = true;

    // Indices at which a snapshot will be next generated and Boolean to
    // indicate whether a snapshot was forced at the given index
    struct SnapshotEntry
    {
      consensus::Index idx;
      bool forced;
      bool done;
    };

    std::deque<SnapshotEntry> next_snapshot_indices;

    void record_snapshot(
      consensus::Index idx,
      consensus::Index evidence_idx,
      const std::vector<uint8_t>& serialised_snapshot)
    {
      size_t max_message_size = to_host->get_max_message_size();
      if (serialised_snapshot.size() > max_message_size)
      {
        LOG_FAIL_FMT(
          "Could not write snapshot of size {} > max ring buffer msg size {}",
          serialised_snapshot.size(),
          max_message_size);
        return;
      }
      RINGBUFFER_WRITE_MESSAGE(
        consensus::snapshot, to_host, idx, evidence_idx, serialised_snapshot);
    }

    void commit_snapshot(
      consensus::Index snapshot_idx,
      const std::vector<uint8_t>& serialised_receipt)
    {
      // The snapshot_idx is used to retrieve the correct snapshot file
      // previously generated.
      RINGBUFFER_WRITE_MESSAGE(
        consensus::snapshot_commit, to_host, snapshot_idx, serialised_receipt);
    }

    struct SnapshotMsg
    {
      std::shared_ptr<Snapshotter> self;
      std::unique_ptr<kv::AbstractStore::AbstractSnapshot> snapshot;
    };

    static void snapshot_cb(std::unique_ptr<threading::Tmsg<SnapshotMsg>> msg)
    {
      msg->data.self->snapshot_(std::move(msg->data.snapshot));
    }

    void snapshot_(
      std::unique_ptr<kv::AbstractStore::AbstractSnapshot> snapshot)
    {
      auto snapshot_version = snapshot->get_version();

      auto serialised_snapshot = store->serialise_snapshot(std::move(snapshot));

      auto tx = store->create_tx();
      auto evidence = tx.rw<SnapshotEvidence>(Tables::SNAPSHOT_EVIDENCE);
      auto snapshot_hash = crypto::Sha256Hash(serialised_snapshot);
      evidence->put({snapshot_hash, snapshot_version});

      ccf::ClaimsDigest cd;
      cd.set(std::move(snapshot_hash));

      crypto::Sha256Hash ws_digest;
      std::string commit_evidence;
      auto capture_ws_digest_and_commit_evidence =
        [&ws_digest, &commit_evidence](
          const std::vector<uint8_t>& write_set,
          const std::string& commit_evidence_) {
          new (&ws_digest)
            crypto::Sha256Hash({write_set.data(), write_set.size()});
          commit_evidence = commit_evidence_;
        };

      auto rc =
        tx.commit(cd, false, nullptr, capture_ws_digest_and_commit_evidence);
      if (rc != kv::CommitResult::SUCCESS)
      {
        LOG_FAIL_FMT(
          "Could not commit snapshot evidence for seqno {}: {}",
          snapshot_version,
          rc);
        return;
      }

      auto evidence_version = tx.commit_version();

      record_snapshot(snapshot_version, evidence_version, serialised_snapshot);
      consensus::Index snapshot_idx =
        static_cast<consensus::Index>(snapshot_version);
      consensus::Index snapshot_evidence_idx =
        static_cast<consensus::Index>(evidence_version);
      pending_snapshots.emplace_back(
        snapshot_idx,
        snapshot_evidence_idx,
        ws_digest,
        commit_evidence,
        cd.value());

      LOG_DEBUG_FMT(
        "Snapshot successfully generated for seqno {}, with evidence seqno "
        "{}: "
        "{}, ws digest: {}",
        snapshot_idx,
        snapshot_evidence_idx,
        cd.value(),
        ws_digest);
    }

    void update_indices(consensus::Index idx)
    {
      while ((next_snapshot_indices.size() > 1) &&
             (std::next(next_snapshot_indices.begin())->idx <= idx))
      {
        next_snapshot_indices.pop_front();
      }

      for (auto it = pending_snapshots.begin(); it != pending_snapshots.end();)
      {
        if (idx > it->evidence_idx)
        {
          auto serialised_receipt = build_and_serialise_receipt(
            it->sig.value(),
            it->tree.value(),
            it->node_id.value(),
            it->node_cert.value(),
            it->evidence_idx,
            it->write_set_digest,
            it->commit_evidence,
            std::move(it->snapshot_digest));
          commit_snapshot(it->idx, serialised_receipt);
          auto it_ = it;
          ++it;
          pending_snapshots.erase(it_);
        }
        else
        {
          ++it;
        }
      }
    }

  public:
    Snapshotter(
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::shared_ptr<kv::Store>& store_,
      size_t snapshot_tx_interval_) :
      to_host(writer_factory.create_writer_to_outside()),
      store(store_),
      snapshot_tx_interval(snapshot_tx_interval_)
    {
      next_snapshot_indices.push_back({initial_snapshot_idx, false, true});
    }

    void init_after_public_recovery()
    {
      // After public recovery, the first node should have restored all
      // snapshot indices in next_snapshot_indices so that snapshot
      // generation can continue at the correct interval
      std::lock_guard<ccf::Mutex> guard(lock);

      last_snapshot_idx = next_snapshot_indices.back().idx;
    }

    void set_snapshot_generation(bool enabled)
    {
      std::lock_guard<ccf::Mutex> guard(lock);
      snapshot_generation_enabled = enabled;
    }

    void set_last_snapshot_idx(consensus::Index idx)
    {
      // Should only be called once, after a snapshot has been applied
      std::lock_guard<ccf::Mutex> guard(lock);

      if (last_snapshot_idx != 0)
      {
        throw std::logic_error(
          "Last snapshot index can only be set if no snapshot has been "
          "generated");
      }

      last_snapshot_idx = idx;

      next_snapshot_indices.clear();
      next_snapshot_indices.push_back({last_snapshot_idx, false, true});
    }

    bool record_committable(consensus::Index idx) override
    {
      // Returns true if the committable idx will require the generation of a
      // snapshot, and thus a new ledger chunk
      std::lock_guard<ccf::Mutex> guard(lock);

      CCF_ASSERT_FMT(
        idx >= next_snapshot_indices.back().idx,
        "Committable seqno {} < next snapshot seqno {}",
        idx,
        next_snapshot_indices.back().idx);

      bool forced = store->flag_enabled_unsafe(
        kv::AbstractStore::Flag::SNAPSHOT_AT_NEXT_SIGNATURE);

      consensus::Index last_unforced_idx = last_snapshot_idx;
      for (auto it = next_snapshot_indices.rbegin();
           it != next_snapshot_indices.rend();
           it++)
      {
        if (!it->forced)
        {
          last_unforced_idx = it->idx;
          break;
        }
      }

      auto due = (idx - last_unforced_idx) >= snapshot_tx_interval;
      if (due || forced)
      {
        next_snapshot_indices.push_back({idx, !due, false});
        LOG_TRACE_FMT(
          "{} {} as snapshot index", !due ? "Forced" : "Recorded", idx);
        store->unset_flag_unsafe(
          kv::AbstractStore::Flag::SNAPSHOT_AT_NEXT_SIGNATURE);
        return due;
      }

      return false;
    }

    void record_signature(
      consensus::Index idx,
      const std::vector<uint8_t>& sig,
      const NodeId& node_id,
      const crypto::Pem& node_cert)
    {
      std::lock_guard<ccf::Mutex> guard(lock);

      for (auto& pending_snapshot : pending_snapshots)
      {
        if (
          pending_snapshot.evidence_idx < idx &&
          !pending_snapshot.sig.has_value())
        {
          pending_snapshot.node_id = node_id;
          pending_snapshot.node_cert = node_cert;
          pending_snapshot.sig = sig;
        }
      }
    }

    void record_serialised_tree(
      consensus::Index idx, const std::vector<uint8_t>& tree)
    {
      std::lock_guard<ccf::Mutex> guard(lock);

      for (auto& pending_snapshot : pending_snapshots)
      {
        if (
          pending_snapshot.evidence_idx < idx &&
          !pending_snapshot.tree.has_value())
        {
          pending_snapshot.tree = tree;
        }
      }
    }

    void schedule_snapshot(consensus::Index idx)
    {
      auto msg = std::make_unique<threading::Tmsg<SnapshotMsg>>(&snapshot_cb);
      msg->data.self = shared_from_this();
      msg->data.snapshot = store->snapshot(idx);
      static uint32_t generation_count = 0;
      threading::ThreadMessaging::thread_messaging.add_task(
        threading::ThreadMessaging::get_execution_thread(generation_count++),
        std::move(msg));
    }

    void commit(consensus::Index idx, bool generate_snapshot) override
    {
      // If generate_snapshot is true, takes a snapshot of the key value store
      // at the last snapshottable index before idx, and schedule snapshot
      // serialisation on another thread (round-robin). Otherwise, only record
      // that a snapshot was generated.
      std::lock_guard<ccf::Mutex> guard(lock);

      update_indices(idx);

      if (idx < last_snapshot_idx)
      {
        throw std::logic_error(fmt::format(
          "Cannot snapshot at seqno {} which is earlier than last snapshot "
          "seqno {}",
          idx,
          last_snapshot_idx));
      }

      CCF_ASSERT_FMT(
        idx >= next_snapshot_indices.front().idx,
        "Cannot commit snapshotter at {}, which is before last snapshottable "
        "idx {}",
        idx,
        next_snapshot_indices.front().idx);

      auto& next = next_snapshot_indices.front();
      auto due = next.idx - last_snapshot_idx >= snapshot_tx_interval;
      if (due || (next.forced && !next.done))
      {
        if (snapshot_generation_enabled && generate_snapshot && next.idx)
        {
          schedule_snapshot(next.idx);
          next.done = true;
        }

        if (due && !next.forced)
        {
          // last_snapshot_idx records the last normally scheduled, i.e.
          // unforced, snapshot index, so that backups (which don't know forced
          // indices) continue the snapshot interval normally.
          last_snapshot_idx = next.idx;
          LOG_TRACE_FMT(
            "Recorded {} as last snapshot index", last_snapshot_idx);
        }
      }
    }

    void rollback(consensus::Index idx) override
    {
      std::lock_guard<ccf::Mutex> guard(lock);

      while (!next_snapshot_indices.empty() &&
             (next_snapshot_indices.back().idx > idx))
      {
        next_snapshot_indices.pop_back();
      }

      if (next_snapshot_indices.empty())
      {
        next_snapshot_indices.push_back({last_snapshot_idx, false, true});
      }

      LOG_TRACE_FMT(
        "Rolled back snapshotter: last snapshottable idx is now {}",
        next_snapshot_indices.front().idx);

      while (!pending_snapshots.empty() &&
             (pending_snapshots.back().evidence_idx > idx))
      {
        pending_snapshots.pop_back();
      }
    }
  };
}
