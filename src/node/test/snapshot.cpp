// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "kv/test/stub_consensus.h"
#include "node/history.h"
#include "node/nodes.h"
#include "node/signatures.h"
#include "tls/key_pair.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <string>

threading::ThreadMessaging threading::ThreadMessaging::thread_messaging;
std::atomic<uint16_t> threading::ThreadMessaging::thread_count = 0;

TEST_CASE("Snapshot with merkle tree" * doctest::test_suite("snapshot"))
{
  auto source_consensus = std::make_shared<kv::StubConsensus>();
  kv::Store source_store(source_consensus);

  ccf::NodeId source_node_id = 0;
  auto source_node_kp = tls::make_key_pair();

  auto source_history =
    std::make_shared<ccf::MerkleTxHistory>(source_store, 0, *source_node_kp);

  source_store.set_history(source_history);

  kv::Map<std::string, std::string> string_map("public:string_map");

  size_t transactions_count = 3;
  kv::Version snapshot_version = kv::NoVersion;

  INFO("Apply transactions to original store");
  {
    for (size_t i = 0; i < transactions_count; i++)
    {
      auto tx = source_store.create_tx();
      auto view = tx.get_view(string_map);
      view->put(fmt::format("key#{}", i), "value");
      REQUIRE(tx.commit() == kv::CommitSuccess::OK);
    }
  }

  auto source_root_before_signature =
    source_history->get_replicated_state_root();

  INFO("Emit signature");
  {
    source_history->emit_signature();
    // Snapshot version is the version of the signature
    snapshot_version = transactions_count + 1;
  }

  INFO("Check tree start from mini-tree and sig hash");
  {
    // No snapshot here, only verify that a fresh tree can be started from the
    // mini-tree in a signature and the hash of the signature
    auto tx = source_store.create_read_only_tx();
    auto view = tx.get_read_only_view<ccf::Signatures>(ccf::Tables::SIGNATURES);
    REQUIRE(view->has(0));
    auto sig = view->get(0).value();

    auto serialised_signature = source_consensus->get_latest_data().value();
    auto serialised_signature_hash = crypto::Sha256Hash(serialised_signature);

    ccf::MerkleTreeHistory target_tree(sig.tree);

    REQUIRE(source_root_before_signature == target_tree.get_root());

    target_tree.append(serialised_signature_hash);
    REQUIRE(
      target_tree.get_root() == source_history->get_replicated_state_root());
  }

  INFO("Snapshot at signature");
  {
    kv::Store target_store;
    INFO("Setup target store");
    {
      auto target_node_kp = tls::make_key_pair();

      auto target_history = std::make_shared<ccf::MerkleTxHistory>(
        target_store, 0, *target_node_kp);
      target_store.set_history(target_history);
    }

    auto target_history = target_store.get_history();

    INFO("Apply snapshot taken before any signature was emitted");
    {
      auto snapshot = source_store.snapshot(snapshot_version - 1);
      auto serialised_snapshot =
        source_store.serialise_snapshot(std::move(snapshot));

      // There is no signature to read to seed the target history
      std::vector<kv::Version> view_history;
      kv::ConsensusHookPtrs hooks;
      REQUIRE(
        target_store.deserialise_snapshot(
          serialised_snapshot, hooks, &view_history) ==
        kv::ApplySuccess::FAILED);
    }

    INFO("Apply snapshot taken at signature");
    {
      auto snapshot = source_store.snapshot(snapshot_version);
      auto serialised_snapshot =
        source_store.serialise_snapshot(std::move(snapshot));

      std::vector<kv::Version> view_history;
      kv::ConsensusHookPtrs hooks;
      REQUIRE(
        target_store.deserialise_snapshot(
          serialised_snapshot, hooks, &view_history) == kv::ApplySuccess::PASS);

      // Merkle history and view history thus far are restored when applying
      // snapshot
      REQUIRE(
        source_history->get_replicated_state_root() ==
        target_history->get_replicated_state_root());
      REQUIRE(
        source_consensus->view_history.get_history_until() == view_history);
    }

    INFO("Deserialise additional transaction after restart");
    {
      auto tx = source_store.create_tx();
      auto view = tx.get_view(string_map);
      view->put("key", "value");
      REQUIRE(tx.commit() == kv::CommitSuccess::OK);

      auto serialised_tx = source_consensus->get_latest_data().value();

      target_store.apply(serialised_tx, ConsensusType::CFT)->execute();

      REQUIRE(
        target_history->get_replicated_state_root() ==
        source_history->get_replicated_state_root());
    }
  }
}
