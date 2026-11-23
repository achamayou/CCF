// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf/app_interface.h"
#include "ccf/crypto/ec_key_pair.h"
#include "ccf/kv/map.h"
#include "ccf/kv/set.h"
#include "ccf/kv/unit_value.h"
#include "ccf/kv/value.h"
#include "ccf/service/tables/nodes.h"
#include "crypto/openssl/hash.h"
#include "ds/internal_logger.h"
#include "kv/claims.h"
#include "kv/compacted_version_conflict.h"
#include "kv/kv_serialiser.h"
#include "kv/ledger_chunker.h"
#include "kv/null_encryptor.h"
#include "kv/store.h"
#include "kv/test/null_tx_history.h"
#include "kv/test/stub_consensus.h"

#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest/doctest.h>
#undef FAIL
#include <functional>
#include <random>
#include <set>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

struct MapTypes
{
  using StringString = ccf::kv::Map<std::string, std::string>;
  using NumNum = ccf::kv::Map<size_t, size_t>;
  using NumString = ccf::kv::Map<size_t, std::string>;
  using StringNum = ccf::kv::Map<std::string, size_t>;
  using UntypedMap = ccf::kv::untyped::Map;
};

TEST_CASE("Map name parsing")
{
  using SD = ccf::kv::SecurityDomain;
  using AC = ccf::kv::AccessCategory;

  auto parse = ccf::kv::parse_map_name;
  auto mp = std::make_pair<SD, AC>;

  REQUIRE(parse("foo") == mp(SD::PRIVATE, AC::APPLICATION));
  REQUIRE(parse("public:foo") == mp(SD::PUBLIC, AC::APPLICATION));
  REQUIRE(parse("public:ccf.gov.foo") == mp(SD::PUBLIC, AC::GOVERNANCE));
  REQUIRE(parse("ccf.internal.foo") == mp(SD::PRIVATE, AC::INTERNAL));
  REQUIRE(parse("public:ccf.internal.foo") == mp(SD::PUBLIC, AC::INTERNAL));

  REQUIRE_THROWS(parse("ccf.foo"));
  REQUIRE_THROWS(parse("public:ccf.foo"));

  // Typos may lead to unexpected behaviour!
  REQUIRE(parse("publik:ccf.gov.foo") == mp(SD::PRIVATE, AC::APPLICATION));
  REQUIRE(parse("PUBLIC:ccf.gov.foo") == mp(SD::PRIVATE, AC::APPLICATION));
  REQUIRE(parse("public:Ccf.gov.foo") == mp(SD::PUBLIC, AC::APPLICATION));

  REQUIRE(parse("ccf_foo") == mp(SD::PRIVATE, AC::APPLICATION));
  REQUIRE(parse("public:ccf_foo") == mp(SD::PUBLIC, AC::APPLICATION));
}

namespace
{
  // A minimal AbstractMap which is not a ccf::kv::untyped::Map, used only to
  // exercise Store::add_dynamic_map's type check. None of the other virtuals
  // are expected to be called in that test.
  class FakeMap : public ccf::kv::AbstractMap
  {
  public:
    explicit FakeMap(const std::string& name_) : ccf::kv::AbstractMap(name_) {}

    std::unique_ptr<ccf::kv::AbstractCommitter> create_committer(
      ccf::kv::AbstractChangeSet*) override
    {
      throw std::logic_error("FakeMap::create_committer not implemented");
    }

    ccf::kv::AbstractStore* get_store() override
    {
      return nullptr;
    }

    void serialise_changes(
      const ccf::kv::AbstractChangeSet*, ccf::kv::KvStoreSerialiser&) override
    {}

    void compact(ccf::kv::Version) override {}

    std::unique_ptr<Snapshot> snapshot(ccf::kv::Version) override
    {
      return nullptr;
    }

    void post_compact() override {}

    void rollback(ccf::kv::Version) override {}

    void lock() override {}

    void unlock() override {}

    ccf::kv::SecurityDomain get_security_domain() override
    {
      return ccf::kv::SecurityDomain::PUBLIC;
    }

    void clear() override {}
  };
}

TEST_CASE("Store error handling")
{
  ccf::kv::Store kv_store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);
  MapTypes::StringString map("public:map");

  SUBCASE("Readiness defaults to Ready and can be set/reset")
  {
    REQUIRE(kv_store.get_readiness() == ccf::kv::StoreReadiness::Ready);
    REQUIRE(kv_store.is_ready());

    kv_store.set_readiness(ccf::kv::StoreReadiness::InstallingSnapshot);
    REQUIRE(
      kv_store.get_readiness() == ccf::kv::StoreReadiness::InstallingSnapshot);
    REQUIRE_FALSE(kv_store.is_ready());

    kv_store.set_readiness(ccf::kv::StoreReadiness::Ready);
    REQUIRE(kv_store.is_ready());
  }

  SUBCASE("add_dynamic_map rejects a map of the wrong type")
  {
    auto fake = std::make_shared<FakeMap>("public:fake");
    REQUIRE_THROWS_WITH_AS(
      kv_store.add_dynamic_map(1, fake),
      "Can't add dynamic map - public:fake is not of expected type",
      std::logic_error);
  }

  SUBCASE("add_dynamic_map rejects a duplicate map name")
  {
    {
      auto tx = kv_store.create_tx();
      tx.rw(map)->put("k", "v");
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    auto duplicate =
      std::make_shared<ccf::kv::untyped::Map>(&kv_store, map.get_name());
    REQUIRE_THROWS_WITH_AS(
      kv_store.add_dynamic_map(kv_store.current_version(), duplicate),
      "Can't add dynamic map - already have a map named public:map",
      std::logic_error);
  }

  SUBCASE("snapshot version must not be earlier than the compacted version")
  {
    {
      auto tx = kv_store.create_tx();
      tx.rw(map)->put("k", "v1");
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }
    const auto v1 = kv_store.current_version();

    {
      auto tx = kv_store.create_tx();
      tx.rw(map)->put("k", "v2");
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }
    kv_store.compact(kv_store.current_version());

    ccf::kv::ScopedStoreMapsLock maps_lock(&kv_store);
    REQUIRE_THROWS_WITH_AS(
      kv_store.snapshot_unsafe_maps(v1),
      doctest::Contains("earlier than last compacted version"),
      std::logic_error);
  }

  SUBCASE("snapshot version must not be later than the current version")
  {
    {
      auto tx = kv_store.create_tx();
      tx.rw(map)->put("k", "v1");
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    ccf::kv::ScopedStoreMapsLock maps_lock(&kv_store);
    REQUIRE_THROWS_WITH_AS(
      kv_store.snapshot_unsafe_maps(kv_store.current_version() + 100),
      doctest::Contains("later than current version"),
      std::logic_error);
  }

  SUBCASE("rollback rejects a target earlier than the compacted version")
  {
    {
      auto tx = kv_store.create_tx();
      tx.rw(map)->put("k", "v1");
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }
    kv_store.compact(kv_store.current_version());

    REQUIRE_THROWS_WITH_AS(
      kv_store.rollback({kv_store.commit_view(), 0}, kv_store.commit_view()),
      "Attempting rollback to 0, earlier than commit version 1",
      std::logic_error);
  }

  SUBCASE("initialise_term cannot be called twice")
  {
    kv_store.initialise_term(2);
    REQUIRE_THROWS_WITH_AS(
      kv_store.initialise_term(3),
      "term_of_next_version is already initialised",
      std::logic_error);
  }

  SUBCASE("start_map rejects a private map without an encryptor")
  {
    ccf::kv::RawKvStoreSerialiser serialiser(
      nullptr, ccf::TxID{0, 1}, ccf::kv::EntryType::WriteSet, 0);
    REQUIRE_THROWS_WITH_AS(
      serialiser.start_map("a_private_map", ccf::kv::SecurityDomain::PRIVATE),
      "Private map a_private_map cannot be serialised without an encryptor",
      ccf::kv::KvSerialiserException);
  }
}

std::string rand_string(size_t i)
{
  return fmt::format("{}: {}", i, rand());
}

int main(int argc, char** argv)
{
  ccf::logger::config::default_init();
  doctest::Context context;
  context.applyCommandLine(argc, argv);
  int res = context.run();
  if (context.shouldExit())
    return res;
  return res;
}
