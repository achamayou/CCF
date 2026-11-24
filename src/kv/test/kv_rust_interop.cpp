// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/kv/map.h"
#include "kv/null_encryptor.h"
#include "kv/store.h"
#include "kv/test/rust_kv_store.h"
#include "kv/test/stub_consensus.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#undef FAIL

namespace
{
  template <typename Source, typename Target>
  void replay_both_domains()
  {
    using namespace ccf::kv;
    auto encryptor = std::make_shared<NullTxEncryptor>();
    auto consensus = std::make_shared<test::StubConsensus>();
    Source source;
    source.set_encryptor(encryptor);
    source.set_consensus(consensus);
    Target target;
    target.set_encryptor(encryptor);
    const Map<std::string, std::string> pub("public:interop");
    const Map<std::string, std::string> priv("interop");

    {
      auto tx = source.create_tx();
      tx.rw(pub)->put("key", "public");
      tx.rw(priv)->put("key", "private");
      tx.rw(pub)->put("z", "last");
      tx.rw(pub)->put("a", "first");
      tx.rw(priv)->put("a", "private first");
      tx.rw(pub)->put("middle", "middle");
      REQUIRE(tx.commit() == CommitResult::SUCCESS);
    }
    const auto first = consensus->get_latest_data();
    REQUIRE(first.has_value());

    {
      auto tx = source.create_tx();
      tx.rw(pub)->remove("key");
      tx.rw(priv)->put("key", "");
      tx.rw(pub)->put("z", "changed");
      tx.rw(pub)->remove("a");
      REQUIRE(tx.commit() == CommitResult::SUCCESS);
    }
    const auto second = consensus->get_latest_data();
    REQUIRE(second.has_value());

    REQUIRE(target.deserialize(*first)->apply() == ApplyResult::PASS);
    {
      auto reader = target.create_read_only_tx();
      CHECK(reader.ro(pub)->get("key") == "public");
      CHECK(reader.ro(priv)->get("key") == "private");
      CHECK(reader.ro(pub)->get("z") == "last");
      CHECK(reader.ro(pub)->get("a") == "first");
      CHECK(reader.ro(pub)->get("middle") == "middle");
      CHECK(reader.ro(priv)->get("a") == "private first");
    }
    REQUIRE(target.deserialize(*second)->apply() == ApplyResult::PASS);
    auto reader = target.create_read_only_tx();
    CHECK_FALSE(reader.ro(pub)->has("key"));
    CHECK_FALSE(reader.ro(pub)->has("a"));
    CHECK(reader.ro(pub)->get("z") == "changed");
    CHECK(reader.ro(pub)->get("middle") == "middle");
    CHECK(reader.ro(priv)->get("a") == "private first");
    CHECK(reader.ro(priv)->get("key") == "");
    CHECK(reader.ro(priv)->get_version_of_previous_write("key") == 2);
  }

  template <typename Source, typename Target>
  void restore_both_domains()
  {
    using namespace ccf::kv;
    auto encryptor = std::make_shared<NullTxEncryptor>();
    Source source;
    source.set_encryptor(encryptor);
    Target target;
    target.set_encryptor(encryptor);
    const Map<std::string, std::string> pub("public:interop");
    const Map<std::string, std::string> priv("interop");
    {
      auto tx = source.create_tx();
      tx.rw(pub)->put("key", "public");
      tx.rw(priv)->put("key", "private");
      REQUIRE(tx.commit() == CommitResult::SUCCESS);
    }
    {
      auto tx = source.create_tx();
      tx.rw(pub)->put("other", "new");
      REQUIRE(tx.commit() == CommitResult::SUCCESS);
    }
    auto snapshot = [&]() -> std::unique_ptr<AbstractStore::AbstractSnapshot> {
      if constexpr (std::is_same_v<Source, Store>)
      {
        ScopedStoreMapsLock lock(&source);
        return source.snapshot_unsafe_maps(2);
      }
      else
      {
        return source.snapshot_maps(2);
      }
    }();
    const auto wire = source.serialise_snapshot(std::move(snapshot));
    ConsensusHookPtrs hooks;
    REQUIRE(
      target.deserialise_snapshot(wire.data(), wire.size(), hooks) ==
      ApplyResult::PASS);
    auto reader = target.create_read_only_tx();
    CHECK(reader.ro(pub)->get("key") == "public");
    CHECK(reader.ro(priv)->get("key") == "private");
    CHECK(reader.ro(pub)->get_version_of_previous_write("key") == 1);
    CHECK(reader.ro(pub)->get_version_of_previous_write("other") == 2);
  }
}

TEST_CASE("Rust replays ordinary C++ ledger entries")
{
  replay_both_domains<ccf::kv::Store, ccf::kv::rust_test::Store>();
}

TEST_CASE("C++ replays ordinary Rust ledger entries")
{
  replay_both_domains<ccf::kv::rust_test::Store, ccf::kv::Store>();
}

TEST_CASE("Rust restores ordinary C++ snapshots")
{
  restore_both_domains<ccf::kv::Store, ccf::kv::rust_test::Store>();
}

TEST_CASE("C++ restores ordinary Rust snapshots")
{
  restore_both_domains<ccf::kv::rust_test::Store, ccf::kv::Store>();
}
