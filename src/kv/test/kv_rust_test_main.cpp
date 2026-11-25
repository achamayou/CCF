// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "kv/test/kv_test_store.h"
#include "kv/test/stub_consensus.h"

#include <atomic>
#include <doctest/doctest.h>
#include <thread>
#include <vector>

TEST_CASE("Rust KV adapter preserves empty byte strings and range bounds")
{
  using namespace ccf::kv::rust_test;
  ccf::kv::test::TestStore store;
  auto tx = store.create_tx();
  auto* map = tx.rw<ccf::kv::untyped::Map>("public:bytes");
  map->put({}, {});
  map->put({128}, {0, 255});
  map->put({255}, {1});
  REQUIRE(map->get({}).has_value());
  CHECK(map->get({})->empty());
  CHECK_FALSE(map->get({0}).has_value());

  std::vector<Bytes> keys;
  auto collect = [&](const Bytes& k, const Bytes&) { keys.push_back(k); };
  map->range(collect, std::nullopt, Bytes{});
  CHECK(keys.empty());
  map->range(collect, Bytes{}, Bytes{255});
  CHECK(keys == std::vector<Bytes>{{}, {128}});
  keys.clear();
  map->range(collect, Bytes{128}, std::nullopt);
  CHECK(keys == std::vector<Bytes>{{128}, {255}});
}

TEST_CASE("Rust KV adapter rejects stale-term writes before publication")
{
  using namespace ccf::kv::rust_test;
  ccf::kv::test::TestStore store;
  auto tx = store.create_tx();
  tx.rw<ccf::kv::untyped::Map>("public:bytes")->put({1}, {2});
  store.rollback({0, 0}, 1);
  CHECK(tx.commit() == ccf::kv::CommitResult::FAIL_NO_REPLICATE);
  CHECK(store.current_version() == 0);
  auto fresh = store.create_tx();
  CHECK_FALSE(fresh.rw<ccf::kv::untyped::Map>("public:bytes")->has({1}));
}

TEST_CASE("Rust KV rejects invalid history operations without changing state")
{
  using namespace ccf::kv;
  test::TestStore store;
  const Map<std::string, std::string> map("public:map");
  store.initialise_term(1);
  REQUIRE_THROWS_AS(store.initialise_term(2), std::logic_error);
  {
    auto tx = store.create_tx();
    tx.rw(map)->put("key", "committed");
    REQUIRE(tx.commit() == CommitResult::SUCCESS);
  }
  store.compact(1);
  REQUIRE_THROWS_AS(store.snapshot_maps(0), std::logic_error);
  REQUIRE_THROWS_AS(store.snapshot_maps(2), std::logic_error);
  REQUIRE_THROWS_AS(store.rollback({1, 0}, 2), std::logic_error);
  CHECK(store.current_txid() == ccf::TxID{1, 1});
  CHECK(store.compacted_version() == 1);
  CHECK(store.commit_view() == 1);
  auto tx = store.create_read_only_tx();
  CHECK(tx.ro(map)->get("key") == "committed");
}

TEST_CASE("Rust KV store implements AbstractStore lifecycle and snapshot hooks")
{
  using namespace ccf::kv;
  test::TestStore store;
  AbstractStore& abstract = store;
  const Map<std::string, std::string> map("public:abstract");

  abstract.initialise_term(2);
  CHECK(abstract.commit_view() == 2);
  CHECK(abstract.get_encryptor() != nullptr);
  CHECK(abstract.get_consensus() == nullptr);
  CHECK(abstract.get_history() == nullptr);
  CHECK(abstract.get_chunker() == nullptr);

  {
    auto tx = store.create_tx();
    tx.rw(map)->put("a", "1");
    REQUIRE(tx.commit() == CommitResult::SUCCESS);
  }

  const auto [txid, commit_term] = abstract.current_txid_and_commit_term();
  CHECK(txid == ccf::TxID{2, 1});
  CHECK(commit_term == 2);
  CHECK(abstract.current_version() == 1);
  CHECK(abstract.compacted_version() == 0);

  CHECK_FALSE(abstract.next_version(1).has_value());
  const auto reserved = abstract.next_version(2);
  REQUIRE(reserved.has_value());
  CHECK(std::get<0>(*reserved) == 2);
  CHECK(std::get<1>(*reserved) == 0);
  CHECK(abstract.check_rollback_count(0));
  abstract.rollback({2, 1}, 2);
  CHECK(abstract.check_rollback_count(1));

  {
    ScopedStoreMapsLock lock(&abstract);
    abstract.set_flag_unsafe(
      AbstractStore::StoreFlag::SNAPSHOT_AT_NEXT_SIGNATURE);
    CHECK(abstract.flag_enabled_unsafe(
      AbstractStore::StoreFlag::SNAPSHOT_AT_NEXT_SIGNATURE));
    abstract.unset_flag_unsafe(
      AbstractStore::StoreFlag::SNAPSHOT_AT_NEXT_SIGNATURE);
    CHECK_FALSE(abstract.flag_enabled_unsafe(
      AbstractStore::StoreFlag::SNAPSHOT_AT_NEXT_SIGNATURE));
  }

  std::unique_ptr<AbstractStore::AbstractSnapshot> snap;
  {
    ScopedStoreMapsLock lock(&abstract);
    CHECK(abstract.current_version() == 1);
    CHECK(abstract.get_encryptor() != nullptr);
    snap = abstract.snapshot_unsafe_maps(1);
    REQUIRE(snap != nullptr);
    CHECK(snap->get_version() == 1);
  }
  const auto raw_snapshot = abstract.serialise_snapshot(std::move(snap));

  test::TestStore restored;
  AbstractStore& restored_abstract = restored;
  ConsensusHookPtrs hooks;
  CHECK(
    restored_abstract.deserialise_snapshot(
      raw_snapshot.data(), raw_snapshot.size(), hooks) == ApplyResult::PASS);
  CHECK(restored_abstract.current_version() == 1);
  CHECK(restored.create_read_only_tx().ro(map)->get("a") == "1");

  REQUIRE_THROWS_AS(abstract.get_map(1, "public:abstract"), std::logic_error);
  REQUIRE_THROWS_AS(
    abstract.get_map_unsafe(1, "public:abstract"), std::logic_error);
  REQUIRE_THROWS_AS(abstract.add_dynamic_map(1, nullptr), std::logic_error);
}

TEST_CASE("Rust KV Store::commit reorders and batches out-of-order entries")
{
  using namespace ccf::kv;

  class RecordingConsensus : public test::PrimaryStubConsensus
  {
  public:
    std::vector<std::vector<Version>> batches;

    bool replicate(const BatchVector& entries, ccf::View view) override
    {
      std::vector<Version> seqnos;
      for (const auto& [v, _data, _committable, _hooks] : entries)
      {
        seqnos.push_back(v);
      }
      batches.push_back(std::move(seqnos));
      return test::PrimaryStubConsensus::replicate(entries, view);
    }
  };

  test::TestStore store;
  auto consensus = std::make_shared<RecordingConsensus>();
  store.set_consensus(consensus);
  store.initialise_term(1);

  auto make_entry = [](uint8_t tag) {
    return std::make_unique<MovePendingTx>(
      std::vector<uint8_t>{tag},
      ccf::empty_claims(),
      ccf::crypto::Sha256Hash{},
      ConsensusHookPtrs{});
  };

  // Arriving out-of-order: seqno 2 buffers and returns SUCCESS immediately.
  REQUIRE(store.commit({1, 2}, make_entry(2), false) == CommitResult::SUCCESS);
  CHECK(consensus->batches.empty());

  // Arriving seqno 1 drains [1, 2] together as one contiguous batch.
  REQUIRE(store.commit({1, 1}, make_entry(1), true) == CommitResult::SUCCESS);
  REQUIRE(consensus->batches.size() == 1);
  CHECK(consensus->batches[0] == std::vector<Version>{1, 2});

  // Stale-term commit is rejected without buffering.
  CHECK(
    store.commit({0, 3}, make_entry(3), false) ==
    CommitResult::FAIL_NO_REPLICATE);
  CHECK(consensus->batches.size() == 1);
}

TEST_CASE(
  "Rust KV adapter runs concurrent reads and writes while another commit "
  "observes")
{
  using namespace ccf::kv;
  test::TestStore store;
  auto consensus = std::make_shared<test::PrimaryStubConsensus>();
  store.set_consensus(consensus);
  const Map<std::string, std::string> map("public:concurrent");
  store.initialise_term(1);

  {
    auto tx = store.create_tx();
    tx.rw(map)->put("seed", "ok");
    REQUIRE(tx.commit() == CommitResult::SUCCESS);
  }

  std::atomic<bool> in_observer{false};
  std::atomic<bool> readers_done{false};

  auto writer_thread = std::thread([&]() {
    auto tx = store.create_tx();
    tx.rw(map)->put("writer", "v2");
    auto observer = [&](const ccf::crypto::Sha256Hash&, const std::string&) {
      in_observer.store(true, std::memory_order_release);
      while (!readers_done.load(std::memory_order_acquire))
      {
        std::this_thread::yield();
      }
    };
    REQUIRE(tx.commit(ccf::empty_claims(), observer) == CommitResult::SUCCESS);
  });

  while (!in_observer.load(std::memory_order_acquire))
  {
    std::this_thread::yield();
  }

  // While the writer is paused inside its write-set observer, multiple threads
  // must be able to read, write, and commit concurrently without blocking.
  constexpr size_t worker_count = 4;
  std::vector<std::thread> workers;
  workers.reserve(worker_count);
  for (size_t i = 0; i < worker_count; ++i)
  {
    workers.emplace_back([&, i]() {
      auto rtx = store.create_read_only_tx();
      auto* h = rtx.ro(map);
      CHECK(h->get("seed") == "ok");
      CHECK(h->get("writer") == "v2");

      auto wtx = store.create_tx();
      auto* wh = wtx.rw<Map<std::string, std::string>>(
        "public:worker_" + std::to_string(i));
      for (size_t k = 0; k < 16; ++k)
      {
        wh->put("k" + std::to_string(k), "v");
      }
      REQUIRE(wtx.commit() == CommitResult::SUCCESS);
    });
  }
  for (auto& w : workers)
  {
    w.join();
  }

  readers_done.store(true, std::memory_order_release);
  writer_thread.join();
  CHECK(store.current_version() == 2 + worker_count);
  CHECK(consensus->number_of_replicas() == 2 + worker_count);
}

TEST_CASE("Rust KV commits normal transactions across open reserved slots")
{
  using namespace ccf::kv;
  using MapT = Map<size_t, size_t>;

  class ReservedPendingTx : public PendingTx
  {
    ccf::TxID txid;
    test::TestStore& store;
    MapT& table;
    size_t val;

  public:
    ReservedPendingTx(
      ccf::TxID txid_, test::TestStore& store_, MapT& table_, size_t val_) :
      txid(txid_),
      store(store_),
      table(table_),
      val(val_)
    {}

    PendingTxInfo call() override
    {
      auto tx = store.create_reserved_tx(txid);
      tx.rw(table)->put(0, val);
      return tx.commit_reserved();
    }
  };

  class RecordingConsensus : public test::PrimaryStubConsensus
  {
  public:
    std::vector<std::vector<Version>> batches;

    bool replicate(const BatchVector& entries, ccf::View view) override
    {
      std::vector<Version> seqnos;
      for (const auto& [v, _data, _committable, _hooks] : entries)
      {
        seqnos.push_back(v);
      }
      batches.push_back(std::move(seqnos));
      return test::PrimaryStubConsensus::replicate(entries, view);
    }
  };

  test::TestStore store;
  auto consensus = std::make_shared<RecordingConsensus>();
  store.set_consensus(consensus);
  store.initialise_term(1);

  MapT table("public:table");
  MapT sig_table("public:sig");

  // Baseline commit at v1.
  {
    auto tx = store.create_tx();
    tx.rw(table)->put(0, 1);
    REQUIRE(tx.commit() == CommitResult::SUCCESS);
  }
  REQUIRE(consensus->number_of_replicas() == 1);

  // Single-threaded batch of two across an open reserved slot (mirrors
  // src/node/test/history.cpp:733): reserve v2, commit normal tx at v3, then
  // fill and commit v2 to flush [2, 3] together.
  const auto rv = store.next_txid();
  REQUIRE(rv == ccf::TxID{1, 2});

  {
    auto tx = store.create_tx();
    tx.rw(table)->put(0, 2);
    REQUIRE(tx.commit() == CommitResult::SUCCESS);
    CHECK(tx.commit_version() == 3);
  }
  CHECK(consensus->number_of_replicas() == 1);

  REQUIRE(
    store.commit(
      rv,
      std::make_unique<ReservedPendingTx>(rv, store, sig_table, 99),
      true) == CommitResult::SUCCESS);
  CHECK(consensus->number_of_replicas() == 3);
  REQUIRE(consensus->batches.size() == 2);
  CHECK(consensus->batches[1] == std::vector<Version>{2, 3});

  // Both the backfilled reserved write and the normal write are visible.
  {
    auto rtx = store.create_read_only_tx();
    CHECK(rtx.ro(table)->get(0) == 2);
    CHECK(rtx.ro(sig_table)->get(0) == 99);
  }

  // Multi-threaded writers keep committing concurrently while a reserved slot
  // is open, then filling the reserved slot drains the full contiguous batch.
  const auto rv2 = store.next_txid();
  REQUIRE(rv2 == ccf::TxID{1, 4});

  constexpr size_t worker_count = 4;
  std::vector<std::thread> workers;
  workers.reserve(worker_count);
  for (size_t i = 0; i < worker_count; ++i)
  {
    workers.emplace_back([&, i]() {
      auto tx = store.create_tx();
      MapT worker_map("public:w_" + std::to_string(i));
      tx.rw(worker_map)->put(i, i + 10);
      REQUIRE(tx.commit() == CommitResult::SUCCESS);
    });
  }
  for (auto& w : workers)
  {
    w.join();
  }
  CHECK(store.current_version() == 4 + worker_count);
  CHECK(consensus->number_of_replicas() == 3);

  REQUIRE(
    store.commit(
      rv2,
      std::make_unique<ReservedPendingTx>(rv2, store, sig_table, 100),
      true) == CommitResult::SUCCESS);
  CHECK(consensus->number_of_replicas() == 4 + worker_count);

  // Replay all replicated entries on a fresh store and confirm identical state.
  test::TestStore backup;
  backup.initialise_term(1);
  for (size_t idx = 0; idx < consensus->replica.size(); ++idx)
  {
    auto exec = backup.deserialize(*std::get<1>(consensus->replica[idx]));
    REQUIRE(exec != nullptr);
    REQUIRE(exec->apply() != ApplyResult::FAIL);
  }
  auto btx = backup.create_read_only_tx();
  CHECK(btx.ro(table)->get(0) == 2);
  CHECK(btx.ro(sig_table)->get(0) == 100);
  for (size_t i = 0; i < worker_count; ++i)
  {
    MapT worker_map("public:w_" + std::to_string(i));
    CHECK(btx.ro(worker_map)->get(i) == i + 10);
  }
}
