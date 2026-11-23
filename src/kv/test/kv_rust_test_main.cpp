// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "kv/test/kv_test_store.h"

#include <doctest/doctest.h>
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
