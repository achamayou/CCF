// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf/kv/map.h"
#include "ccf/kv/set.h"
#include "ccf/kv/unit_value.h"
#include "ccf/kv/value.h"
#include "ccf/service/tables/nodes.h"
#include "kv/ledger_chunker.h"
#include "kv/test/kv_test_store.h"
#include "kv/test/null_tx_history.h"
#include "kv/test/stub_consensus.h"
#include "node/encryptor.h"

#include <algorithm>
#include <cstring>
#include <doctest/doctest.h>
#include <format>
#undef FAIL
#include <span>
#include <stop_token>
#include <string>
#include <thread>

namespace
{
  using BackendStore = ccf::kv::test::TestStoreBase;

  struct MapTypes
  {
    using StringString = ccf::kv::Map<std::string, std::string>;
    using NumNum = ccf::kv::Map<size_t, size_t>;
    using NumString = ccf::kv::Map<size_t, std::string>;
  };
}

TEST_CASE("Invalid ledger entries do not advance the store")
{
  using namespace ccf::kv;
  test::TestStore target;
  const auto encryptor = std::make_shared<NullTxEncryptor>();
  const auto write_set = [&](const std::vector<std::string>& map_names) {
    RawKvStoreSerialiser serialiser(
      encryptor, ccf::TxID{0, 1}, EntryType::WriteSet, 0);
    for (const auto& map_name : map_names)
    {
      serialiser.start_map(map_name, SecurityDomain::PUBLIC);
      serialiser.serialise_entry_version(NoVersion);
      serialiser.serialise_count_header(0); // reads
      serialiser.serialise_count_header(0); // writes
      serialiser.serialise_count_header(0); // removes
    }
    return serialiser.get_raw_data();
  };
  const auto edit_header = [](std::vector<uint8_t>& data, auto edit) {
    SerialisedEntryHeader header;
    std::memcpy(&header, data.data(), sizeof(header));
    edit(header);
    std::memcpy(data.data(), &header, sizeof(header));
  };

  SUBCASE("Duplicate map writes")
  {
    REQUIRE(
      target.deserialize(write_set({"public:dup", "public:dup"}))->apply() ==
      ApplyResult::FAIL);
  }

  SUBCASE("Trailing content after the last map")
  {
    auto data = write_set({"public:m"});
    constexpr size_t trailing_size = 4;
    data.resize(data.size() + trailing_size, 0xAA);
    edit_header(
      data, [](auto& header) { header.set_size(header.size + trailing_size); });
    REQUIRE_THROWS_WITH_AS(
      target.deserialize(data)->apply(),
      "Expected 8 bytes for fixed-size entry, found only 4",
      std::runtime_error);
  }

  SUBCASE("Header size does not match the entry size")
  {
    auto data = write_set({"public:m"});
    edit_header(data, [](auto& header) { header.set_size(header.size + 4); });
    REQUIRE_THROWS_WITH_AS(
      target.deserialize(data)->apply(),
      doctest::Contains("does not match size of entry"),
      std::logic_error);
  }

  SUBCASE("Unsupported entry format")
  {
    auto data = write_set({"public:m"});
    edit_header(
      data, [](auto& header) { header.version = entry_format_v1 + 1; });
    REQUIRE_THROWS_WITH_AS(
      target.deserialize(data)->apply(),
      "Cannot deserialise entry format 2",
      std::logic_error);
  }

  CHECK(target.current_version() == NoVersion);
}

TEST_CASE(
  "Serialise/deserialise public map only" *
  doctest::test_suite("serialisation"))
{
  // No need for an encryptor here as all maps are public. Both serialisation
  // and deserialisation should succeed.

  BackendStore kv_store;

  auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
  kv_store.set_consensus(consensus);
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);

  BackendStore kv_store_target;
  kv_store_target.set_encryptor(encryptor);

  MapTypes::StringString map("public:pub_map");

  const auto k1 = "pubk1";
  const auto k2 = "pubk2";
  const auto k3 = "pubk3";
  const auto k4 = "never_written";

  const auto v1 = "pubv1";
  const auto v2 = "pubv2";

  {
    INFO("Commit to public map in source store");
    auto tx = kv_store.create_tx();
    auto handle0 = tx.rw(map);
    handle0->put(k1, v1);
    handle0->put(k2, v1);
    handle0->put(k3, v1);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  const auto first_version = kv_store.current_version();
  const auto first_tx_serialised = consensus->get_latest_data();
  REQUIRE(first_tx_serialised.has_value());
  REQUIRE(!first_tx_serialised.value().empty());

  {
    INFO("Modify source store in second transaction");
    auto tx = kv_store.create_tx();
    auto handle0 = tx.rw(map);
    // no change to k1, write to k2, remove k3
    handle0->put(k2, v2);
    handle0->remove(k3);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  const auto second_version = kv_store.current_version();
  const auto second_tx_serialised = consensus->get_latest_data();
  REQUIRE(second_tx_serialised.has_value());
  REQUIRE(!second_tx_serialised.value().empty());

  {
    INFO("Deserialise first transaction in target store");
    REQUIRE(
      kv_store_target.deserialize(first_tx_serialised.value())->apply() ==
      ccf::kv::ApplyResult::PASS);

    auto tx_target = kv_store_target.create_tx();
    auto handle_target = tx_target.ro(map);

    REQUIRE(handle_target->has(k1));
    REQUIRE(handle_target->get(k1) == v1);
    REQUIRE(handle_target->get_version_of_previous_write(k1) == first_version);

    REQUIRE(handle_target->has(k2));
    REQUIRE(handle_target->get(k2) == v1);
    REQUIRE(handle_target->get_version_of_previous_write(k2) == first_version);

    REQUIRE(handle_target->has(k3));
    REQUIRE(handle_target->get(k3) == v1);
    REQUIRE(handle_target->get_version_of_previous_write(k3) == first_version);

    REQUIRE(!handle_target->has(k4));
    REQUIRE(!handle_target->get_version_of_previous_write(k4).has_value());
  }

  {
    INFO("Deserialise second transaction in target store");
    REQUIRE(
      kv_store_target.deserialize(second_tx_serialised.value())->apply() ==
      ccf::kv::ApplyResult::PASS);

    auto tx_target = kv_store_target.create_tx();
    auto handle_target = tx_target.ro(map);

    REQUIRE(handle_target->has(k1));
    REQUIRE(handle_target->get(k1) == v1);
    REQUIRE(handle_target->get_version_of_previous_write(k1) == first_version);

    REQUIRE(handle_target->has(k2));
    REQUIRE(handle_target->get(k2) == v2);
    REQUIRE(handle_target->get_version_of_previous_write(k2) == second_version);

    REQUIRE(!handle_target->has(k3));
    REQUIRE(!handle_target->get_version_of_previous_write(k3).has_value());

    REQUIRE(!handle_target->has(k4));
    REQUIRE(!handle_target->get_version_of_previous_write(k4).has_value());
  }
}

TEST_CASE(
  "Serialise/deserialise private map only" *
  doctest::test_suite("serialisation"))
{
  auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();

  BackendStore kv_store;
  kv_store.set_consensus(consensus);

  BackendStore kv_store_target;
  kv_store_target.set_encryptor(encryptor);

  SUBCASE(
    "Commit a private transaction without an encryptor throws an exception")
  {
    auto tx = kv_store.create_tx();
    auto handle0 = tx.rw<MapTypes::StringString>("priv_map");
    handle0->put("privk1", "privv1");
    REQUIRE_THROWS_AS(tx.commit(), ccf::kv::KvSerialiserException);
  }

  SUBCASE("Commit private transaction with encryptor")
  {
    kv_store.set_encryptor(encryptor);
    INFO("Commit to private map in source store");
    {
      auto tx = kv_store.create_tx();
      auto handle0 = tx.rw<MapTypes::StringString>("priv_map");
      handle0->put("privk1", "privv1");
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    INFO("Deserialise transaction in target store");
    {
      const auto latest_data = consensus->get_latest_data();
      REQUIRE(latest_data.has_value());
      REQUIRE(
        kv_store_target.deserialize(latest_data.value())->apply() ==
        ccf::kv::ApplyResult::PASS);

      auto tx_target = kv_store_target.create_tx();
      auto handle_target = tx_target.rw<MapTypes::StringString>("priv_map");
      REQUIRE(handle_target->get("privk1") == "privv1");
    }
  }
}

TEST_CASE(
  "Reject transactions exceeding configured serialised size" *
  doctest::test_suite("serialisation"))
{
  auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();

  BackendStore kv_store;
  kv_store.set_consensus(consensus);
  kv_store.set_encryptor(encryptor);
  kv_store.set_max_transaction_size(1024);

  MapTypes::StringString map("public:pub_map");

  {
    INFO("An oversized transaction is rejected before it is applied");
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    handle->put("oversized", std::string(2048, 'A'));
    REQUIRE_THROWS_AS(tx.commit(), ccf::kv::MaxTransactionSizeExceeded);
    REQUIRE(kv_store.current_version() == 0);
    REQUIRE(!consensus->get_latest_data().has_value());
  }

  {
    INFO("Later transactions are unaffected");
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    handle->put("small", "ok");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    REQUIRE(kv_store.current_version() == 1);
  }
}

TEST_CASE(
  "The transaction size limit is compared against the exact entry size" *
  doctest::test_suite("serialisation"))
{
  auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();

  MapTypes::StringString map("public:pub_map");
  const auto value = std::string(512, 'A');

  // Serialise the transaction under a permissive limit to find the exact size
  // of the ledger entry it produces.
  size_t entry_size = 0;
  {
    BackendStore kv_store;
    kv_store.set_consensus(consensus);
    kv_store.set_encryptor(encryptor);

    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    handle->put("key", value);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

    const auto latest_data = consensus->get_latest_data();
    REQUIRE(latest_data.has_value());
    entry_size = latest_data->size();
  }

  // The allocation-free sizing pass must report the exact size of the entry
  // which is eventually written. A limit of precisely that size is accepted,
  // and one byte less is not.
  {
    BackendStore kv_store;
    kv_store.set_encryptor(encryptor);
    kv_store.set_max_transaction_size(entry_size);

    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    handle->put("key", value);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  {
    BackendStore kv_store;
    kv_store.set_encryptor(encryptor);
    kv_store.set_max_transaction_size(entry_size - 1);

    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    handle->put("key", value);
    REQUIRE_THROWS_AS(tx.commit(), ccf::kv::MaxTransactionSizeExceeded);
    REQUIRE(kv_store.current_version() == 0);
  }
}

TEST_CASE(
  "The transaction size limit includes encrypted private data" *
  doctest::test_suite("serialisation"))
{
  const auto create_encryptor = []() {
    auto secrets = std::make_shared<ccf::LedgerSecrets>();
    secrets->init();
    return std::make_shared<ccf::NodeEncryptor>(secrets);
  };

  MapTypes::StringString public_map("public:pub_map");
  MapTypes::StringString private_map("priv_map");
  const auto value = std::string(512, 'A');

  const auto populate = [&](auto& tx) {
    tx.rw(public_map)->put("public_key", value);
    tx.rw(private_map)->put("private_key", value);
  };

  size_t entry_size = 0;
  {
    auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
    BackendStore kv_store;
    kv_store.set_consensus(consensus);
    kv_store.set_encryptor(create_encryptor());

    auto tx = kv_store.create_tx();
    populate(tx);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

    const auto latest_data = consensus->get_latest_data();
    REQUIRE(latest_data.has_value());
    entry_size = latest_data->size();
  }

  {
    BackendStore kv_store;
    kv_store.set_encryptor(create_encryptor());
    kv_store.set_max_transaction_size(entry_size);

    auto tx = kv_store.create_tx();
    populate(tx);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  {
    BackendStore kv_store;
    kv_store.set_encryptor(create_encryptor());
    kv_store.set_max_transaction_size(entry_size - 1);

    auto tx = kv_store.create_tx();
    populate(tx);
    REQUIRE_THROWS_AS(tx.commit(), ccf::kv::MaxTransactionSizeExceeded);
    REQUIRE(kv_store.current_version() == 0);
  }
}

TEST_CASE(
  "Deserialisation is not subject to the transaction size limit" *
  doctest::test_suite("serialisation"))
{
  auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();

  // Serialise a transaction under a permissive (default) limit.
  BackendStore kv_store;
  kv_store.set_consensus(consensus);
  kv_store.set_encryptor(encryptor);

  MapTypes::StringString map("public:pub_map");

  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    handle->put("large", std::string(2048, 'A'));
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  const auto latest_data = consensus->get_latest_data();
  REQUIRE(latest_data.has_value());

  // The cap applies only to serialisation. A tiny limit on the target store
  // must not prevent it from deserialising an already-serialised transaction.
  BackendStore kv_store_target;
  kv_store_target.set_encryptor(encryptor);
  kv_store_target.set_max_transaction_size(1);

  REQUIRE(
    kv_store_target.deserialize(latest_data.value())->apply() ==
    ccf::kv::ApplyResult::PASS);
}

TEST_CASE(
  "Serialise/deserialise private map and public maps" *
  doctest::test_suite("serialisation"))
{
  auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();

  BackendStore kv_store;
  kv_store.set_consensus(consensus);
  kv_store.set_encryptor(encryptor);

  constexpr auto priv_map = "priv_map";
  constexpr auto pub_map = "public:pub_map";

  BackendStore kv_store_target;
  kv_store_target.set_encryptor(encryptor);

  INFO("Commit to public and private map in source store");
  {
    auto tx = kv_store.create_tx();
    auto handle_priv = tx.rw<MapTypes::StringString>(priv_map);
    auto handle_pub = tx.rw<MapTypes::StringString>(pub_map);

    handle_priv->put("privk1", "privv1");
    handle_pub->put("pubk1", "pubv1");

    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  INFO("Deserialise transaction in target store");
  {
    const auto latest_data = consensus->get_latest_data();
    REQUIRE(latest_data.has_value());
    REQUIRE(
      kv_store_target.deserialize(latest_data.value())->apply() !=
      ccf::kv::ApplyResult::FAIL);

    auto tx_target = kv_store_target.create_tx();
    auto handle_priv = tx_target.rw<MapTypes::StringString>(priv_map);
    auto handle_pub = tx_target.rw<MapTypes::StringString>(pub_map);

    REQUIRE(handle_priv->get("privk1") == "privv1");
    REQUIRE(handle_pub->get("pubk1") == "pubv1");
  }
}

TEST_CASE(
  "Encrypted public and private transactions replay" *
  doctest::test_suite("serialisation"))
{
  auto secrets = std::make_shared<ccf::LedgerSecrets>();
  secrets->init();
  auto encryptor = std::make_shared<ccf::NodeEncryptor>(secrets);
  auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
  BackendStore source;
  source.set_encryptor(encryptor);
  source.set_consensus(consensus);
  BackendStore recovered;
  recovered.set_encryptor(encryptor);

  MapTypes::StringString public_map("public:pub_map");
  MapTypes::StringString private_map("priv_map");
  for (size_t i = 1; i <= 3; ++i)
  {
    auto tx = source.create_tx();
    if (i != 2)
    {
      tx.rw(public_map)->put(std::to_string(i), "public");
    }
    if (i != 1)
    {
      tx.rw(private_map)->put(std::to_string(i), "private");
    }
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    const auto entry = consensus->get_latest_data();
    REQUIRE(entry.has_value());
    REQUIRE(
      recovered.deserialize(*entry)->apply() == ccf::kv::ApplyResult::PASS);
  }

  auto tx = recovered.create_tx();
  REQUIRE(tx.ro(public_map)->get("1") == "public");
  REQUIRE(tx.ro(private_map)->get("2") == "private");
  REQUIRE(tx.ro(public_map)->get("3") == "public");
  REQUIRE(tx.ro(private_map)->get("3") == "private");
}

TEST_CASE(
  "Partial encryption failure cannot replicate an entry" *
  doctest::test_suite("serialisation"))
{
  class FailingEncryptor : public ccf::NodeEncryptor
  {
  public:
    using ccf::NodeEncryptor::NodeEncryptor;

    bool encrypt(
      std::span<const uint8_t>,
      std::span<const uint8_t>,
      std::span<uint8_t> header,
      std::span<uint8_t> cipher,
      const ccf::TxID&,
      ccf::kv::EntryType,
      bool) override
    {
      std::fill(header.begin(), header.end(), 0xAA);
      std::fill(cipher.begin(), cipher.end(), 0xBB);
      return false;
    }
  };

  auto secrets = std::make_shared<ccf::LedgerSecrets>();
  secrets->init();
  auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
  BackendStore store;
  store.set_encryptor(std::make_shared<FailingEncryptor>(secrets));
  store.set_consensus(consensus);

  auto tx = store.create_tx();
  tx.rw<MapTypes::StringString>("private_map")->put("key", "secret");
  REQUIRE_THROWS_AS(tx.commit(), ccf::kv::KvSerialiserException);
  REQUIRE_FALSE(consensus->get_latest_data().has_value());
}

TEST_CASE(
  "Serialise/deserialise removed keys" * doctest::test_suite("serialisation"))
{
  auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();

  BackendStore kv_store;
  kv_store.set_consensus(consensus);
  kv_store.set_encryptor(encryptor);

  BackendStore kv_store_target;
  kv_store_target.set_encryptor(encryptor);

  INFO("Commit new keys in source store and deserialise in target store");
  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw<MapTypes::StringString>("map");
    auto handle2 = tx.rw<MapTypes::StringString>("map2");
    handle->put("key1", "value1");
    handle2->put("key2", "value2");
    handle2->put("key3", "value3");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

    const auto latest_data = consensus->get_latest_data();
    REQUIRE(latest_data.has_value());
    REQUIRE(
      kv_store_target.deserialize(latest_data.value())->apply() !=
      ccf::kv::ApplyResult::FAIL);

    auto tx_target = kv_store_target.create_tx();
    auto handle_target = tx_target.rw<MapTypes::StringString>("map");
    auto handle_target2 = tx_target.rw<MapTypes::StringString>("map2");
    REQUIRE(handle_target->get("key1") == "value1");
    REQUIRE(handle_target2->get("key2") == "value2");
    REQUIRE(handle_target2->get("key3") == "value3");
  }

  INFO("Commit keys removal in source store and deserialise in target store");
  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw<MapTypes::StringString>("map");
    auto handle_ = tx.rw<MapTypes::StringString>("map2");

    // Key only exists in state
    handle->remove("key1");

    // Key exists in write set as well as state
    handle_->put("key2", "value2");
    handle_->remove("key2");

    // Key doesn't exist in either write set or state
    handle->remove("unknown_key");

    // Key only exists in write set
    handle_->put("uncommitted_key", "uncommitted_value");
    handle_->remove("uncommitted_key");

    // Key is removed then added again
    handle_->remove("key3");
    handle_->put("key3", "value3");

    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

    // Make sure keys have been marked as deleted in source store
    auto tx2 = kv_store.create_tx();
    auto handle2 = tx2.rw<MapTypes::StringString>("map");
    auto handle_2 = tx2.rw<MapTypes::StringString>("map2");
    REQUIRE_FALSE(handle2->get("key1").has_value());
    REQUIRE_FALSE(handle_2->get("key2").has_value());
    REQUIRE_FALSE(handle2->get("unknown_key").has_value());
    REQUIRE_FALSE(handle_2->get("uncommitted_key").has_value());

    const auto latest_data = consensus->get_latest_data();
    REQUIRE(latest_data.has_value());
    REQUIRE(
      kv_store_target.deserialize(latest_data.value())->apply() !=
      ccf::kv::ApplyResult::FAIL);

    auto tx_target = kv_store_target.create_tx();
    auto handle_target = tx_target.rw<MapTypes::StringString>("map");
    auto handle_target_2 = tx_target.rw<MapTypes::StringString>("map2");
    REQUIRE_FALSE(handle_target->get("key1").has_value());
    REQUIRE_FALSE(handle_target_2->get("key2").has_value());
    REQUIRE_FALSE(handle_target->get("unknown_key").has_value());
    REQUIRE_FALSE(handle_target_2->get("uncommitted_key").has_value());
  }
}

TEST_CASE(
  "Serialise/deserialise maps with claims" *
  doctest::test_suite("serialisation"))
{
  auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();

  BackendStore kv_store;
  kv_store.set_consensus(consensus);
  kv_store.set_encryptor(encryptor);

  constexpr auto priv_map = "priv_map";
  constexpr auto pub_map = "public:pub_map";

  BackendStore kv_store_target;
  kv_store_target.set_encryptor(encryptor);

  ccf::ClaimsDigest claims_digest;
  claims_digest.set(ccf::crypto::Sha256Hash("claim text"));
  ccf::crypto::Sha256Hash expected_commit_evidence_digest;

  INFO("Commit to source store, including claims");
  {
    auto tx = kv_store.create_tx();
    auto handle_priv = tx.rw<MapTypes::StringString>(priv_map);
    auto handle_pub = tx.rw<MapTypes::StringString>(pub_map);

    handle_priv->put("privk1", "privv1");
    handle_pub->put("pubk1", "pubv1");

    REQUIRE(tx.commit(claims_digest) == ccf::kv::CommitResult::SUCCESS);
    expected_commit_evidence_digest = ccf::crypto::Sha256Hash(
      encryptor->get_commit_evidence({tx.commit_term(), tx.commit_version()}));
  }

  INFO("Deserialise transaction in target store and extract digests");
  {
    const auto latest_data = consensus->get_latest_data();
    REQUIRE(latest_data.has_value());
    auto wrapper = kv_store_target.deserialize(latest_data.value());
    REQUIRE(wrapper->apply() != ccf::kv::ApplyResult::FAIL);
    auto deserialised_claims = wrapper->consume_claims_digest();
    REQUIRE(claims_digest == deserialised_claims);
    auto deserialised_commit_evidence =
      wrapper->consume_commit_evidence_digest();
    REQUIRE(deserialised_commit_evidence.has_value());
    REQUIRE(
      deserialised_commit_evidence.value() == expected_commit_evidence_digest);

    auto tx_target = kv_store_target.create_tx();
    auto handle_priv = tx_target.rw<MapTypes::StringString>(priv_map);
    auto handle_pub = tx_target.rw<MapTypes::StringString>(pub_map);

    REQUIRE(handle_priv->get("privk1") == "privv1");
    REQUIRE(handle_pub->get("pubk1") == "pubv1");
  }
}

TEST_CASE("Reported TxID after commit")
{
  BackendStore kv_store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);
  auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
  kv_store.set_consensus(consensus);

  const auto map_name = "public:map";
  MapTypes::StringString map(map_name);
  auto store_last_seqno = kv_store.current_version();
  ccf::kv::Term initial_term = 2;
  ccf::kv::Term store_commit_term = initial_term;
  ccf::kv::Term store_read_term = 0;

  INFO("Initialise store");
  {
    kv_store.initialise_term(store_commit_term);

    for (store_last_seqno = kv_store.current_version(); store_last_seqno < 10;
         store_last_seqno++)
    {
      auto tx = kv_store.create_tx();
      auto handle = tx.rw(map);
      handle->put("key", "value");
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
      store_read_term = store_commit_term;
    }

    REQUIRE(kv_store.current_version() == store_last_seqno);
    REQUIRE_EQ(
      kv_store.current_txid(), ccf::TxID(store_read_term, store_last_seqno));
  }

  INFO("Empty committed tx");
  {
    auto tx = kv_store.create_tx();

    // No map handle acquired

    // Tx is not yet committed
    REQUIRE_THROWS_AS(auto _ = tx.get_txid(), std::logic_error);

    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

    // Committed transaction was not assigned a TxID because it was empty
    REQUIRE_FALSE(tx.get_txid().has_value());
  }

  INFO("Simple read-only tx");
  {
    // The ReadOnlyTx returned by store.create_read_only_tx() has no commit()
    // member. Here, we want to specifically test generic Txs that are created
    // by the CCF frontend, but do not write to the key-value store.
    auto tx = kv_store.create_tx();
    tx.ro(map); // Remember: opacity tx_id is acquired here

    // No need to read a key, acquiring a map handle is sufficient to acquire a
    // valid TxID

    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

    // Reported TxID includes store read term and last seqno
    auto tx_id = tx.get_txid();
    REQUIRE(tx_id.has_value());
    REQUIRE(tx_id->view == store_read_term);
    REQUIRE(tx_id->seqno == store_last_seqno);
    REQUIRE_EQ(tx_id.value(), kv_store.current_txid());
  }

  INFO("Rollback while read-only tx is in progress");
  {
    auto tx = kv_store.create_tx();

    // Still a trivial case since the opacity TxID is acquired here
    tx.ro(map);

    // Rollback at the current TxID, in the next term
    kv_store.rollback(kv_store.current_txid(), ++store_commit_term);

    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

    auto tx_id = tx.get_txid();
    REQUIRE(tx_id.has_value());
    REQUIRE(tx_id->view == store_read_term); // Read in term in which
                                             // last entry was committed
    REQUIRE(tx_id->seqno == store_last_seqno);
    REQUIRE_EQ(tx_id.value(), kv_store.current_txid());
  }

  INFO("Read-only tx after rollback");
  {
    // Tricky! Rollback before opacity TxID is acquired

    kv_store.rollback(kv_store.current_txid(), ++store_commit_term);

    auto tx = kv_store.create_tx();
    tx.ro(map);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

    auto tx_id = tx.get_txid();
    REQUIRE(tx_id.has_value());
    REQUIRE(tx_id->view == store_read_term); // Read in term in which
                                             // last entry was committed
    REQUIRE(tx_id->seqno == store_last_seqno);
    REQUIRE_EQ(tx_id.value(), kv_store.current_txid());
  }

  INFO("More rollbacks");
  {
    kv_store.rollback(kv_store.current_txid(), ++store_commit_term);
    kv_store.rollback(kv_store.current_txid(), ++store_commit_term);

    auto tx = kv_store.create_tx();
    tx.ro(map);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

    auto tx_id = tx.get_txid();
    REQUIRE(tx_id.has_value());
    REQUIRE(tx_id->view == store_read_term);
    REQUIRE(tx_id->seqno == store_last_seqno);
    REQUIRE_EQ(tx_id.value(), kv_store.current_txid());
  }

  INFO("Commit tx in new term and no-op rollback");
  {
    {
      auto tx = kv_store.create_tx();
      auto handle = tx.rw(map);
      handle->put("key", "value");
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
      store_last_seqno = kv_store.current_version();
      store_read_term = store_commit_term;

      auto tx_id = tx.get_txid();
      REQUIRE(tx_id.has_value());
      REQUIRE(tx_id->view == store_commit_term);
      REQUIRE(tx_id->seqno == store_last_seqno);

      // Since a write Tx was committed, further Txs should read from there
    }

    {
      // Read-only tx should report the new term
      auto tx = kv_store.create_tx();
      tx.ro(map);
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

      auto tx_id = tx.get_txid();
      REQUIRE(tx_id.has_value());
      REQUIRE(tx_id->view == store_read_term);
      REQUIRE(tx_id->seqno == store_last_seqno);
      REQUIRE_EQ(tx_id.value(), kv_store.current_txid());
    }

    {
      kv_store.rollback(kv_store.current_txid(), ++store_commit_term);

      auto tx = kv_store.create_tx();
      tx.ro(map);
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

      auto tx_id = tx.get_txid();
      REQUIRE(tx_id.has_value());
      REQUIRE(tx_id->view == store_read_term);
      REQUIRE(tx_id->seqno == store_last_seqno);
      REQUIRE_EQ(tx_id.value(), kv_store.current_txid());
    }
  }

  INFO("Rollback to last entry in previous committed term");
  {
    // Rollback to initial term
    kv_store.rollback(
      {initial_term, store_last_seqno - 1}, ++store_commit_term);
    store_read_term = initial_term;

    auto tx = kv_store.create_tx();
    tx.ro(map);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

    auto tx_id = tx.get_txid();
    REQUIRE(tx_id.has_value());
    REQUIRE(tx_id->view == store_read_term);
    REQUIRE(tx_id->seqno == store_last_seqno - 1);
    REQUIRE_EQ(tx_id.value(), kv_store.current_txid());
  }
}

TEST_CASE("Dynamic map serialisation" * doctest::test_suite("dynamic"))
{
  auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  BackendStore kv_store;

  kv_store.set_encryptor(encryptor);
  kv_store.set_consensus(consensus);

  BackendStore kv_store_target;
  kv_store_target.set_encryptor(encryptor);

  const auto map_name = "new_map";
  const auto key = "foo";
  const auto value = "bar";

  {
    INFO("Commit a map creation in source store");
    auto tx = kv_store.create_tx();
    auto handle = tx.rw<MapTypes::StringString>(map_name);
    handle->put(key, value);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  {
    INFO("Deserialise transaction in target store");
    const auto latest_data = consensus->get_latest_data();
    REQUIRE(latest_data.has_value());
    REQUIRE(
      kv_store_target.deserialize(latest_data.value())->apply() ==
      ccf::kv::ApplyResult::PASS);

    auto tx_target = kv_store_target.create_tx();
    auto handle_target = tx_target.rw<MapTypes::StringString>(map_name);
    const auto v = handle_target->get(key);
    REQUIRE(v.has_value());
    REQUIRE(v.value() == value);
  }
}

TEST_CASE("nlohmann (de)serialisation" * doctest::test_suite("serialisation"))
{
  const auto k0 = "abc";
  const auto v0 = 123;

  const std::vector<int> k1{4, 5, 6, 7};
  const std::string v1 = "xyz";

  SUBCASE("baseline")
  {
    auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
    using Table = ccf::kv::Map<std::vector<int>, std::string>;
    BackendStore s0, s1;
    s0.set_consensus(consensus);
    auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
    s0.set_encryptor(encryptor);
    s1.set_encryptor(encryptor);

    Table t("public:t");

    auto tx = s0.create_tx();
    tx.rw(t)->put(k1, v1);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

    const auto latest_data = consensus->get_latest_data();
    REQUIRE(latest_data.has_value());
    REQUIRE(
      s1.deserialize(latest_data.value())->apply() !=
      ccf::kv::ApplyResult::FAIL);
  }

  SUBCASE("nlohmann")
  {
    auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
    using Table = ccf::kv::Map<nlohmann::json, nlohmann::json>;
    BackendStore s0, s1;
    s0.set_consensus(consensus);
    auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
    s0.set_encryptor(encryptor);
    s1.set_encryptor(encryptor);

    Table t("public:t");

    auto tx = s0.create_tx();
    tx.rw(t)->put(k0, v0);
    tx.rw(t)->put(k1, v1);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

    const auto latest_data = consensus->get_latest_data();
    REQUIRE(latest_data.has_value());
    REQUIRE(
      s1.deserialize(latest_data.value())->apply() !=
      ccf::kv::ApplyResult::FAIL);
  }
}

struct NonSerialisable
{};

struct NonSerialiser
{
  using Bytes = ccf::kv::serialisers::SerialisedEntry;

  static Bytes to_serialised(const NonSerialisable& ns)
  {
    throw std::runtime_error("Serialise failure");
  }

  static NonSerialisable from_serialised(const Bytes& b)
  {
    throw std::runtime_error("Deserialise failure");
  }
};

TEST_CASE("Exceptional serdes" * doctest::test_suite("serialisation"))
{
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();

  BackendStore store;
  store.set_consensus(consensus);
  store.set_encryptor(encryptor);

  ccf::kv::TypedMap<
    NonSerialisable,
    size_t,
    NonSerialiser,
    ccf::kv::serialisers::JsonSerialiser<size_t>>
    bad_map_k("bad_map_k");
  ccf::kv::TypedMap<
    size_t,
    NonSerialisable,
    ccf::kv::serialisers::JsonSerialiser<size_t>,
    NonSerialiser>
    bad_map_v("bad_map_v");

  {
    auto tx = store.create_tx();
    auto bad_handle = tx.rw(bad_map_k);
    REQUIRE_THROWS(bad_handle->put({}, 0));
  }

  {
    auto tx = store.create_tx();
    auto bad_handle = tx.rw(bad_map_v);
    REQUIRE_THROWS(bad_handle->put(0, {}));
  }
}

TEST_CASE("Stale-view writes are rejected before local application")
{
  BackendStore store;
  store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());
  auto consensus = std::make_shared<ccf::kv::test::PrimaryStubConsensus>();
  store.set_consensus(consensus);

  constexpr ccf::kv::Term initial_term = 2;
  constexpr auto key = "key";
  MapTypes::StringString map("public:map");
  store.initialise_term(initial_term);

  {
    auto tx = store.create_tx();
    tx.rw(map)->put(key, "initial");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  const auto baseline_txid = store.current_txid();
  const auto baseline_replica_count = consensus->replica.size();

  auto stale_tx = store.create_tx();
  stale_tx.rw(map)->put(key, "stale");

  const auto new_term = initial_term + 1;
  store.rollback(baseline_txid, new_term);

  REQUIRE(stale_tx.commit() == ccf::kv::CommitResult::FAIL_NO_REPLICATE);
  CHECK(store.current_txid() == baseline_txid);
  CHECK(consensus->replica.size() == baseline_replica_count);
  {
    auto tx = store.create_read_only_tx();
    CHECK(tx.ro(map)->get(key) == "initial");
  }

  {
    auto tx = store.create_tx();
    tx.rw(map)->put(key, "fresh");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  CHECK(store.current_txid() == ccf::TxID(new_term, baseline_txid.seqno + 1));
  CHECK(consensus->replica.size() == baseline_replica_count + 1);
  {
    auto tx = store.create_read_only_tx();
    CHECK(tx.ro(map)->get(key) == "fresh");
  }

  const auto before_dynamic_map_txid = store.current_txid();
  auto stale_dynamic_map_tx = store.create_tx();
  stale_dynamic_map_tx.rw<MapTypes::StringString>("public:new_map")
    ->put(key, "stale");

  store.rollback(before_dynamic_map_txid, new_term + 1);

  REQUIRE(
    stale_dynamic_map_tx.commit() == ccf::kv::CommitResult::FAIL_NO_REPLICATE);
  CHECK(store.current_txid() == before_dynamic_map_txid);
  CHECK(!ccf::kv::test::has_map_at(
    store, store.current_version(), "public:new_map"));

  auto fresh_dynamic_map_tx = store.create_tx();
  fresh_dynamic_map_tx.rw<MapTypes::StringString>("public:new_map")
    ->put(key, "fresh");
  REQUIRE(fresh_dynamic_map_tx.commit() == ccf::kv::CommitResult::SUCCESS);
}

TEST_CASE(
  "Concurrent deserialised dynamic map publication" *
  doctest::test_suite("dynamic"))
{
  constexpr size_t map_count = 256;
  constexpr size_t reader_count = 4;

  auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();

  BackendStore source_store;
  source_store.set_encryptor(encryptor);
  source_store.set_consensus(consensus);

  std::vector<std::vector<uint8_t>> entries;
  entries.reserve(map_count);

  // Keep map comparisons in progress long enough for TSAN to observe overlap.
  const std::string map_name_prefix(4096, 'm');
  for (size_t i = 0; i < map_count; ++i)
  {
    auto tx = source_store.create_tx();
    auto handle =
      tx.rw<MapTypes::StringString>(map_name_prefix + std::to_string(i));
    handle->put("key", "value");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

    const auto latest_data = consensus->get_latest_data();
    REQUIRE(latest_data.has_value());
    entries.push_back(latest_data.value());
  }

  BackendStore target_store;
  target_store.set_encryptor(encryptor);

  std::atomic<size_t> ready = 0;
  std::atomic<bool> start = false;
  std::atomic<bool> done = false;
  std::atomic<size_t> readers_started = 0;
  std::atomic<size_t> reads = 0;
  std::atomic<bool> all_entries_applied = true;
  std::exception_ptr writer_exception;

  const auto searched_map_name = map_name_prefix + "not_present";
  std::vector<std::thread> readers;
  readers.reserve(reader_count);
  for (size_t i = 0; i < reader_count; ++i)
  {
    readers.emplace_back([&]() {
      ready.fetch_add(1, std::memory_order_release);
      while (!start.load(std::memory_order_acquire))
      {
        std::this_thread::yield();
      }

      ccf::kv::test::has_map_at(
        target_store, target_store.current_version(), searched_map_name);
      reads.fetch_add(1, std::memory_order_relaxed);
      readers_started.fetch_add(1, std::memory_order_release);

      while (!done.load(std::memory_order_acquire))
      {
        ccf::kv::test::has_map_at(
          target_store, target_store.current_version(), searched_map_name);
        reads.fetch_add(1, std::memory_order_relaxed);
      }
    });
  }

  std::thread writer([&]() {
    ready.fetch_add(1, std::memory_order_release);
    while (!start.load(std::memory_order_acquire))
    {
      std::this_thread::yield();
    }
    while (readers_started.load(std::memory_order_acquire) != reader_count)
    {
      std::this_thread::yield();
    }

    try
    {
      for (const auto& entry : entries)
      {
        if (
          target_store.deserialize(entry)->apply() !=
          ccf::kv::ApplyResult::PASS)
        {
          all_entries_applied.store(false, std::memory_order_relaxed);
          break;
        }
      }
    }
    catch (...)
    {
      writer_exception = std::current_exception();
    }
    done.store(true, std::memory_order_release);
  });

  while (ready.load(std::memory_order_acquire) != reader_count + 1)
  {
    std::this_thread::yield();
  }
  start.store(true, std::memory_order_release);

  writer.join();
  for (auto& reader : readers)
  {
    reader.join();
  }

  if (writer_exception)
  {
    std::rethrow_exception(writer_exception);
  }

  REQUIRE(all_entries_applied.load(std::memory_order_relaxed));
  REQUIRE(reads.load(std::memory_order_relaxed) >= reader_count);
  REQUIRE(target_store.current_version() == map_count);
}

struct CustomUnitCreator
{
  static ccf::kv::serialisers::SerialisedEntry get()
  {
    ccf::kv::serialisers::SerialisedEntry e;

    for (size_t i = 0; i < 42; ++i)
    {
      e.push_back(i);
    }

    return e;
  }
};

TEST_CASE("serialisation of Unit type")
{
  const auto value_name = "public:aa";
  const auto set_name = "public:bb";
  const auto unit_name = "public:cc";

  const auto v1 = "hello";
  const auto v2 = "world";
  const auto v3 = "saluton";

  {
    INFO("The default unit type allows migration to/from a ccf::kv::Map");

    using TValue = ccf::kv::RawCopySerialisedValue<std::string>;
    using TValueEquivalent = ccf::kv::RawCopySerialisedMap<size_t, std::string>;

    using TSet = ccf::kv::RawCopySerialisedSet<std::string>;
    using TSetEquivalent = ccf::kv::RawCopySerialisedMap<std::string, size_t>;

    using TUnit = ccf::kv::UnitValue<>;
    using TUnitEquivalent = ccf::kv::RawCopySerialisedMap<size_t, size_t>;

    BackendStore kv_store;
    auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
    kv_store.set_encryptor(encryptor);

    {
      auto tx = kv_store.create_tx();

      auto val_handle = tx.rw<TValueEquivalent>(value_name);
      val_handle->put(0, v1); // Will be visible in TValue handle
      val_handle->put(1, v2); // Won't be

      auto set_handle = tx.rw<TSetEquivalent>(set_name);
      set_handle->put(v1, 0); // Will be visible in TSet handle
      set_handle->put(v2, 1); // Will be visible in TSet handle, but would be
                              // written with different value

      auto unit_handle = tx.rw<TUnitEquivalent>(unit_name);
      unit_handle->put(0, 0); // Will be visible in TUnit handle
      unit_handle->put(1, 1); // Won't be

      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    {
      auto tx = kv_store.create_tx();

      auto val_handle = tx.rw<TValue>(value_name);
      REQUIRE(val_handle->has());
      REQUIRE(*val_handle->get() == v1);
      val_handle->put(v3);

      auto set_handle = tx.rw<TSet>(set_name);
      REQUIRE(set_handle->contains(v1));
      REQUIRE(set_handle->contains(v2));
      set_handle->insert(v2);
      set_handle->insert(v3);

      auto unit_handle = tx.rw<TUnit>(unit_name);
      REQUIRE(unit_handle->has());
      unit_handle->clear();
      REQUIRE(!unit_handle->has());
      unit_handle->touch();
      REQUIRE(unit_handle->has());

      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    {
      auto tx = kv_store.create_tx();

      auto val_handle = tx.rw<TValueEquivalent>(value_name);
      REQUIRE(val_handle->has(0));
      REQUIRE(*val_handle->get(0) == v3);
      REQUIRE(val_handle->has(1));
      REQUIRE(*val_handle->get(1) == v2);

      auto set_handle = tx.rw<TSetEquivalent>(set_name);
      REQUIRE(set_handle->has(v1));
      REQUIRE(*set_handle->get(v1) == 0);
      REQUIRE(set_handle->has(v2));
      REQUIRE(*set_handle->get(v2) == 0);
      REQUIRE(set_handle->has(v3));
      REQUIRE(*set_handle->get(v3) == 0);

      auto unit_handle = tx.rw<TUnitEquivalent>(unit_name);
      REQUIRE(unit_handle->has(0));
      REQUIRE(*unit_handle->get(0) == 0);
      REQUIRE(!unit_handle->has(1));

      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }
  }

  {
    INFO("Custom UnitCreators produce distinct ledger entries");

    using ValueA = ccf::kv::TypedValue<
      std::string,
      ccf::kv::serialisers::BlitSerialiser<std::string>,
      ccf::kv::serialisers::ZeroBlitUnitCreator>;
    std::vector<uint8_t> entry_a;
    {
      auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
      BackendStore kv_store;
      auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
      kv_store.set_encryptor(encryptor);
      kv_store.set_consensus(consensus);
      auto tx = kv_store.create_tx();
      auto val_handle = tx.rw<ValueA>(value_name);
      val_handle->put(v1);
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
      const auto e = consensus->get_latest_data();
      REQUIRE(e.has_value());
      entry_a = e.value();
    }

    using ValueB = ccf::kv::TypedValue<
      std::string,
      ccf::kv::serialisers::BlitSerialiser<std::string>,
      ccf::kv::serialisers::EmptyUnitCreator>;
    std::vector<uint8_t> entry_b;
    {
      auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
      BackendStore kv_store;
      auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
      kv_store.set_encryptor(encryptor);
      kv_store.set_consensus(consensus);
      auto tx = kv_store.create_tx();
      auto val_handle = tx.rw<ValueB>(value_name);
      val_handle->put(v1);
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
      const auto e = consensus->get_latest_data();
      REQUIRE(e.has_value());
      entry_b = e.value();
    }

    using ValueC = ccf::kv::TypedValue<
      std::string,
      ccf::kv::serialisers::BlitSerialiser<std::string>,
      CustomUnitCreator>;
    std::vector<uint8_t> entry_c;
    {
      auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
      BackendStore kv_store;
      auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
      kv_store.set_encryptor(encryptor);
      kv_store.set_consensus(consensus);
      auto tx = kv_store.create_tx();
      auto val_handle = tx.rw<ValueC>(value_name);
      val_handle->put(v1);
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
      const auto e = consensus->get_latest_data();
      REQUIRE(e.has_value());
      entry_c = e.value();
    }

    REQUIRE(entry_a != entry_b);
    REQUIRE(entry_a != entry_c);
    REQUIRE(entry_b != entry_c);

    using UnitA = ccf::kv::UnitValue<ccf::kv::serialisers::ZeroBlitUnitCreator>;
    std::vector<uint8_t> unit_entry_a;
    {
      auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
      BackendStore kv_store;
      auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
      kv_store.set_encryptor(encryptor);
      kv_store.set_consensus(consensus);
      auto tx = kv_store.create_tx();
      auto unit_handle = tx.rw<UnitA>(unit_name);
      unit_handle->touch();
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
      const auto e = consensus->get_latest_data();
      REQUIRE(e.has_value());
      unit_entry_a = e.value();
    }

    using UnitB = ccf::kv::UnitValue<ccf::kv::serialisers::EmptyUnitCreator>;
    std::vector<uint8_t> unit_entry_b;
    {
      auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
      BackendStore kv_store;
      auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
      kv_store.set_encryptor(encryptor);
      kv_store.set_consensus(consensus);
      auto tx = kv_store.create_tx();
      auto unit_handle = tx.rw<UnitB>(unit_name);
      unit_handle->touch();
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
      const auto e = consensus->get_latest_data();
      REQUIRE(e.has_value());
      unit_entry_b = e.value();
    }

    using UnitC = ccf::kv::UnitValue<CustomUnitCreator>;
    std::vector<uint8_t> unit_entry_c;
    {
      auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
      BackendStore kv_store;
      auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
      kv_store.set_encryptor(encryptor);
      kv_store.set_consensus(consensus);
      auto tx = kv_store.create_tx();
      auto unit_handle = tx.rw<UnitC>(unit_name);
      unit_handle->touch();
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
      const auto e = consensus->get_latest_data();
      REQUIRE(e.has_value());
      unit_entry_c = e.value();
    }

    REQUIRE(unit_entry_a != unit_entry_b);
    REQUIRE(unit_entry_a != unit_entry_c);
    REQUIRE(unit_entry_b != unit_entry_c);
  }
}

TEST_CASE("Transaction diffs")
{
  // Historical queries deserialise each ledger entry into a fresh store, and
  // indexing strategies then read the changes made by that transaction through
  // a TxDiff. Puts are reconstructed from the deserialised state and deletes
  // from the change set, so each must be reported exactly once.
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
  ccf::kv::test::TestStoreBase store;
  store.set_encryptor(encryptor);
  store.set_consensus(consensus);

  MapTypes::StringString map("public:map");
  using Serialiser = ccf::kv::serialisers::JsonSerialiser<std::string>;

  std::vector<uint8_t> initial_entry;
  std::vector<uint8_t> mixed_entry;
  std::vector<uint8_t> delete_only_entry;

  {
    auto tx = store.create_tx();
    auto handle = tx.rw(map);
    handle->put("kept", "v1");
    handle->put("overwritten", "v1");
    handle->put("removed", "v1");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    initial_entry = consensus->get_latest_data().value();
  }

  {
    auto tx = store.create_tx();
    auto handle = tx.rw(map);
    handle->put("overwritten", "v2");
    handle->put("added", "v2");
    handle->remove("removed");
    handle->remove("never_existed");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    mixed_entry = consensus->get_latest_data().value();
  }

  {
    auto tx = store.create_tx();
    auto handle = tx.rw(map);
    handle->remove("kept");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    delete_only_entry = consensus->get_latest_data().value();
  }

  using DiffContents = std::map<std::string, std::optional<std::string>>;
  auto collect = [](auto* diff) {
    DiffContents contents;
    diff->foreach(
      [&contents](const std::string& k, const std::optional<std::string>& v) {
        REQUIRE(contents.find(k) == contents.end());
        contents[k] = v;
        return true;
      });
    return contents;
  };

  const DiffContents mixed_contents{
    {"overwritten", "v2"},
    {"added", "v2"},
    {"removed", std::nullopt},
    {"never_existed", std::nullopt}};

  INFO("Diff of an entry applied to a fresh store");
  {
    ccf::kv::test::TestStoreBase historical;
    historical.set_encryptor(encryptor);
    REQUIRE(
      historical.deserialize(mixed_entry)->apply(true) ==
      ccf::kv::ApplyResult::PASS);

    auto tx_diff = historical.create_tx_diff();
    auto* diff = tx_diff.diff(map);

    REQUIRE(diff->has("overwritten"));
    REQUIRE_FALSE(diff->is_deleted("overwritten"));
    REQUIRE(diff->get("overwritten").value().value() == "v2");

    // Deletes are visible, including of a key absent from the fresh store
    REQUIRE_FALSE(diff->has("never_existed"));
    REQUIRE(diff->is_deleted("never_existed"));

    // Keys not touched by this transaction are absent from the diff
    REQUIRE_FALSE(diff->has("kept"));
    REQUIRE_FALSE(diff->is_deleted("kept"));
    REQUIRE_FALSE(diff->get("kept").has_value());

    REQUIRE(diff->size() == mixed_contents.size());
    REQUIRE(collect(diff) == mixed_contents);

    // The untyped diff distinguishes deleted keys from untouched keys
    auto* untyped_diff = tx_diff.diff<ccf::kv::untyped::Map>(map.get_name());
    {
      const auto removed =
        untyped_diff->get(Serialiser::to_serialised("removed"));
      REQUIRE(removed.has_value());
      REQUIRE_FALSE(removed.value().has_value());

      // Ranges are ordered by serialised key, and exclude the upper bound
      std::vector<std::string> range_keys;
      untyped_diff->range(
        [&range_keys](
          const ccf::kv::serialisers::SerialisedEntry& k,
          const std::optional<ccf::kv::serialisers::SerialisedEntry>&) {
          range_keys.push_back(Serialiser::from_serialised(k));
        },
        Serialiser::to_serialised("added"),
        Serialiser::to_serialised("overwritten"));
      REQUIRE(range_keys == std::vector<std::string>{"added", "never_existed"});
    }
  }

  INFO("Delete-only entries are only visible when tracking deletes");
  {
    {
      ccf::kv::test::TestStoreBase historical;
      historical.set_encryptor(encryptor);
      REQUIRE(
        historical.deserialize(delete_only_entry)->apply(true) ==
        ccf::kv::ApplyResult::PASS);

      auto tx_diff = historical.create_tx_diff();
      auto* diff = tx_diff.diff(map);
      REQUIRE(diff->size() == 1);
      REQUIRE(collect(diff) == DiffContents{{"kept", std::nullopt}});
    }

    {
      // Without tracking, deleting a key which is absent from the fresh store
      // leaves no trace in the map
      ccf::kv::test::TestStoreBase historical;
      historical.set_encryptor(encryptor);
      REQUIRE(
        historical.deserialize(delete_only_entry)->apply(false) ==
        ccf::kv::ApplyResult::PASS);

      auto tx_diff = historical.create_tx_diff();
      REQUIRE(tx_diff.diff(map)->size() == 0);
    }
  }

  INFO("Diff over a store with history only reports the latest commit");
  {
    ccf::kv::test::TestStoreBase replayed;
    replayed.set_encryptor(encryptor);
    REQUIRE(
      replayed.deserialize(initial_entry)->apply(true) ==
      ccf::kv::ApplyResult::PASS);
    REQUIRE(
      replayed.deserialize(mixed_entry)->apply(true) ==
      ccf::kv::ApplyResult::PASS);

    auto tx_diff = replayed.create_tx_diff();
    auto* diff = tx_diff.diff(map);

    // "kept" is still present in the state, but was written by an earlier
    // transaction, so it is not part of this diff
    REQUIRE_FALSE(diff->has("kept"));
    REQUIRE(diff->size() == mixed_contents.size());
    REQUIRE(collect(diff) == mixed_contents);
  }
}

TEST_CASE("Deserialising from other Store")
{
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  BackendStore store;
  store.set_encryptor(encryptor);

  MapTypes::NumString public_map("public:public");
  MapTypes::NumString private_map("private");
  auto tx1 = store.create_reserved_tx(store.next_txid());
  auto handle1 = tx1.rw(public_map);
  auto handle2 = tx1.rw(private_map);
  handle1->put(42, "aardvark");
  handle2->put(14, "alligator");
  auto [success_, data_, claims_digest, commit_evidence_digest, hooks] =
    tx1.commit_reserved();
  auto& success = success_;
  auto& data = data_;
  REQUIRE(success == ccf::kv::CommitResult::SUCCESS);

  BackendStore clone;
  clone.set_encryptor(encryptor);

  REQUIRE(clone.deserialize(data)->apply() == ccf::kv::ApplyResult::PASS);
}

TEST_CASE("CommittableTx guards")
{
  MapTypes::StringString map("public:map");

  SUBCASE("Accessors throw before commit")
  {
    BackendStore kv_store;
    kv_store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());

    auto tx = kv_store.create_tx();
    tx.rw(map)->put("k", "v");

    REQUIRE_THROWS_WITH_AS(
      auto _ = tx.commit_version(),
      "Transaction not yet committed",
      std::logic_error);
    REQUIRE_THROWS_WITH_AS(
      auto _ = tx.commit_term(),
      "Transaction not yet committed",
      std::logic_error);
    REQUIRE_THROWS_WITH_AS(
      auto _ = tx.get_txid(),
      "Transaction not yet committed",
      std::logic_error);
  }

  SUBCASE("Accessors throw after a conflicting commit")
  {
    BackendStore kv_store;
    kv_store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());

    {
      // Ensure this map already exists, by making a prior write to it
      auto tx = kv_store.create_tx();
      tx.rw(map)->put("k", "initial");
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    auto tx1 = kv_store.create_tx();
    auto handle1 = tx1.rw(map);
    // Read, so that a later conflicting write is detected
    handle1->get("k");
    handle1->put("k", "from_tx1");

    {
      auto tx2 = kv_store.create_tx();
      tx2.rw(map)->put("k", "from_tx2");
      REQUIRE(tx2.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    REQUIRE(tx1.commit() == ccf::kv::CommitResult::FAIL_CONFLICT);

    // A conflict leaves the Tx uncommitted (not aborted), so it is the
    // "not yet committed" message which fires, not "Transaction aborted".
    REQUIRE_THROWS_WITH_AS(
      auto _ = tx1.commit_version(),
      "Transaction not yet committed",
      std::logic_error);
    REQUIRE_THROWS_WITH_AS(
      auto _ = tx1.commit_term(),
      "Transaction not yet committed",
      std::logic_error);
  }

  SUBCASE(
    "Accessors throw 'Transaction aborted' for a reserved tx that "
    "loses a rollback race")
  {
    // Unlike a regular Tx (which stays uncommitted on failure), a
    // ReservedTx which loses a race against a concurrent rollback is
    // marked committed but unsuccessful, so its accessors throw
    // "Transaction aborted" rather than "Transaction not yet committed".
    BackendStore kv_store;
    kv_store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());
    auto consensus = std::make_shared<ccf::kv::test::PrimaryStubConsensus>();
    kv_store.set_consensus(consensus);
    kv_store.initialise_term(2);

    {
      auto tx = kv_store.create_tx();
      tx.rw(map)->put("k", "initial");
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    const auto baseline_txid = kv_store.current_txid();

    auto reserved = kv_store.create_reserved_tx(kv_store.next_txid());
    reserved.rw(map)->put("k", "from_reserved");

    // Roll the store back, invalidating the rollback_count that `reserved`
    // captured when it was created.
    kv_store.rollback(baseline_txid, 3);

    const auto info = reserved.commit_reserved();
    REQUIRE(info.success == ccf::kv::CommitResult::FAIL_NO_REPLICATE);

    REQUIRE_THROWS_WITH_AS(
      auto _ = reserved.commit_version(),
      "Transaction aborted",
      std::logic_error);
    REQUIRE_THROWS_WITH_AS(
      auto _ = reserved.commit_term(), "Transaction aborted", std::logic_error);
  }

  SUBCASE("commit_reserved rejects a reserved transaction with no changes")
  {
    BackendStore kv_store;
    kv_store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());

    auto reserved = kv_store.create_reserved_tx(kv_store.next_txid());
    REQUIRE_THROWS_WITH_AS(
      reserved.commit_reserved(),
      "Reserved transaction cannot be empty",
      std::logic_error);
  }

  SUBCASE("commit_reserved rejects being called twice")
  {
    BackendStore kv_store;
    kv_store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());

    auto reserved = kv_store.create_reserved_tx(kv_store.next_txid());
    reserved.rw(map)->put("k", "v");
    REQUIRE(
      reserved.commit_reserved().success == ccf::kv::CommitResult::SUCCESS);

    REQUIRE_THROWS_WITH_AS(
      reserved.commit_reserved(),
      "Transaction already committed",
      std::logic_error);
  }

  SUBCASE("Commit with missing claims throws")
  {
    BackendStore kv_store;
    kv_store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());

    auto tx = kv_store.create_tx();
    tx.rw(map)->put("k", "v");

    REQUIRE_THROWS_WITH_AS(
      tx.commit(ccf::no_claims()), "Missing claims", std::logic_error);
  }

  SUBCASE("Commit without an encryptor throws KvSerialiserException")
  {
    // No call to set_encryptor
    BackendStore kv_store;

    auto tx = kv_store.create_tx();
    tx.rw(map)->put("k", "v");

    REQUIRE_THROWS_WITH_AS(
      tx.commit(), "No encryptor set", ccf::kv::KvSerialiserException);
  }

  SUBCASE("commit_reserved rejects a reserved transaction which only reads")
  {
    BackendStore kv_store;
    kv_store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());

    {
      // Establish the map, so the reserved tx below can read from it without
      // creating it
      auto tx = kv_store.create_tx();
      tx.rw(map)->put("k", "v");
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    // Such a transaction would otherwise succeed with an empty ledger entry,
    // leaving nothing at its reserved version
    auto reserved = kv_store.create_reserved_tx(kv_store.next_txid());
    REQUIRE(reserved.rw(map)->get("k") == "v");
    REQUIRE_THROWS_WITH_AS(
      reserved.commit_reserved(),
      "Reserved transaction cannot be empty",
      std::logic_error);
    REQUIRE_THROWS_WITH_AS(
      auto _ = reserved.commit_version(),
      "Transaction not yet committed",
      std::logic_error);
  }

  SUBCASE("unset_tx_flag clears a previously set flag")
  {
    BackendStore kv_store;
    kv_store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());

    auto tx = kv_store.create_tx();
    tx.set_tx_flag(ccf::kv::CommittableTx::TxFlag::SNAPSHOT_AT_NEXT_SIGNATURE);
    REQUIRE(tx.tx_flag_enabled(
      ccf::kv::CommittableTx::TxFlag::SNAPSHOT_AT_NEXT_SIGNATURE));

    tx.unset_tx_flag(
      ccf::kv::CommittableTx::TxFlag::SNAPSHOT_AT_NEXT_SIGNATURE);
    REQUIRE_FALSE(tx.tx_flag_enabled(
      ccf::kv::CommittableTx::TxFlag::SNAPSHOT_AT_NEXT_SIGNATURE));
  }

  SUBCASE("Committing with SNAPSHOT_AT_NEXT_SIGNATURE sets the store flag")
  {
    BackendStore kv_store;
    kv_store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());

    REQUIRE_FALSE(kv_store.flag_enabled(
      ccf::kv::AbstractStore::StoreFlag::SNAPSHOT_AT_NEXT_SIGNATURE));

    auto tx = kv_store.create_tx();
    tx.set_tx_flag(ccf::kv::CommittableTx::TxFlag::SNAPSHOT_AT_NEXT_SIGNATURE);
    tx.rw(map)->put("k", "v");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

    REQUIRE(kv_store.flag_enabled(
      ccf::kv::AbstractStore::StoreFlag::SNAPSHOT_AT_NEXT_SIGNATURE));
  }

  SUBCASE(
    "Committing SNAPSHOT_AT_NEXT_SIGNATURE with no writes arms the store "
    "flag")
  {
    BackendStore kv_store;
    kv_store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());

    REQUIRE_FALSE(kv_store.flag_enabled(
      ccf::kv::AbstractStore::StoreFlag::SNAPSHOT_AT_NEXT_SIGNATURE));

    // A read-only transaction (no writes) has no version to attach a ledger
    // chunk to, but a requested snapshot must still be armed. Registering a
    // read (rather than leaving the transaction entirely untouched) ensures
    // it reaches that code path, rather than short-circuiting immediately.
    auto tx = kv_store.create_tx();
    tx.set_tx_flag(ccf::kv::CommittableTx::TxFlag::SNAPSHOT_AT_NEXT_SIGNATURE);
    tx.ro(map)->get("k");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

    REQUIRE(kv_store.flag_enabled(
      ccf::kv::AbstractStore::StoreFlag::SNAPSHOT_AT_NEXT_SIGNATURE));
    REQUIRE_FALSE(tx.tx_flag_enabled(
      ccf::kv::CommittableTx::TxFlag::SNAPSHOT_AT_NEXT_SIGNATURE));
  }
}

TEST_CASE("Stale-view writes which took their version early are rejected")
{
  bool reuse_versions = false;
  SUBCASE("No versions allocated after rollback")
  {
    reuse_versions = false;
  }
  SUBCASE("Versions allocated again after rollback")
  {
    reuse_versions = true;
  }

  for (const auto state :
       {ccf::kv::test::StubConsensus::Primary,
        ccf::kv::test::StubConsensus::Backup,
        ccf::kv::test::StubConsensus::Candidate})
  {
    CAPTURE(state);

    BackendStore store;
    store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());
    auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
    consensus->state = ccf::kv::test::StubConsensus::Primary;
    store.set_consensus(consensus);

    constexpr ccf::kv::Term initial_term = 2;
    constexpr ccf::kv::Term new_term = initial_term + 1;
    constexpr ccf::SeqNo rollback_seqno = 2;
    MapTypes::StringString map("public:map");
    store.initialise_term(initial_term);

    auto write = [&](const std::string& key, const std::string& value) {
      auto tx = store.create_tx();
      tx.rw(map)->put(key, value);
      return tx.commit();
    };

    auto read = [&](const std::string& key) {
      auto tx = store.create_read_only_tx();
      return tx.ro(map)->get(key);
    };

    auto replicated_to = [&]() {
      return std::get<0>(consensus->replica.back());
    };

    REQUIRE(write("first", "1") == ccf::kv::CommitResult::SUCCESS);
    REQUIRE(write("second", "2") == ccf::kv::CommitResult::SUCCESS);
    REQUIRE(write("truncated", "3") == ccf::kv::CommitResult::SUCCESS);
    REQUIRE(store.current_version() == 3);
    REQUIRE(consensus->replica.size() == 3);

    INFO("Reject a transaction whose writes were rolled back mid-commit");
    {
      auto stale_tx = store.create_tx();
      stale_tx.rw(map)->put("stale", "4");

      // The observer runs after local application, before Store::commit().
      auto lose_view = [&](const ccf::crypto::Sha256Hash&, const std::string&) {
        REQUIRE(store.current_version() == 4);
        consensus->state = state;
        consensus->replica.resize(rollback_seqno);
        store.rollback({initial_term, rollback_seqno}, new_term);

        if (reuse_versions)
        {
          // New reservations must not make the old-view transaction valid.
          REQUIRE(store.next_txid() == ccf::TxID(new_term, 3));
          REQUIRE(store.next_txid() == ccf::TxID(new_term, 4));
        }
      };

      CHECK(
        stale_tx.commit(ccf::empty_claims(), lose_view) ==
        ccf::kv::CommitResult::FAIL_NO_REPLICATE);
      const auto expected_txid = reuse_versions ?
        ccf::TxID(new_term, 4) :
        ccf::TxID(initial_term, rollback_seqno);
      CHECK(store.current_txid() == expected_txid);
      CHECK(!read("stale").has_value());
      CHECK(!read("truncated").has_value());
      CHECK(replicated_to() == rollback_seqno);
    }

    INFO("Become primary, rolling back any new reservations");
    {
      store.rollback({initial_term, rollback_seqno}, new_term + 1);
      consensus->state = ccf::kv::test::StubConsensus::Primary;
    }

    INFO("The first write after election replicates only itself");
    {
      const auto replicated_before = consensus->replica.size();
      REQUIRE(write("fresh", "3") == ccf::kv::CommitResult::SUCCESS);
      CHECK(read("fresh") == "3");
      CHECK(store.current_txid() == ccf::TxID(new_term + 1, 3));
      CHECK(consensus->replica.size() == replicated_before + 1);
      CHECK(replicated_to() == 3);
      CHECK(store.current_version() == replicated_to());
    }

    INFO("Subsequent writes continue to replicate");
    {
      const auto replicated_before = consensus->replica.size();
      REQUIRE(write("next", "4") == ccf::kv::CommitResult::SUCCESS);
      CHECK(read("next") == "4");
      CHECK(!read("stale").has_value());
      CHECK(consensus->replica.size() == replicated_before + 1);
      CHECK(store.current_version() == replicated_to());
    }
  }
}

// Reproduces the race between a reserved transaction creating a map (which
// writes to the Store's map set) and a concurrent reader looking one up. The
// write happens in Store::add_dynamic_map via commit_reserved; the read holds
// maps_lock via Store::get_map. Only ThreadSanitizer can observe the failure,
// so this asserts nothing about interleaving - it exists to give TSAN both
// accesses concurrently.
TEST_CASE("Reserved transaction map creation is serialised with lookups")
{
  BackendStore store;
  store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());

  {
    auto tx = store.create_tx();
    tx.rw<MapTypes::StringString>("public:existing")->put("k", "v");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  // Ensure every exit path, including a failed REQUIRE, stops and joins
  // readers.
  std::vector<std::jthread> readers;
  readers.reserve(4);
  for (size_t r = 0; r < 4; ++r)
  {
    readers.emplace_back([&store](std::stop_token stop_token) {
      size_t n = 0;
      while (!stop_token.stop_requested())
      {
        // Takes maps_lock and searches the map set. Looks up names in the
        // range being inserted, so the search path traverses the nodes
        // add_dynamic_map is writing. Deliberately avoids current_version(),
        // so this contends only on maps_lock.
        (void)ccf::kv::test::has_map_at(
          store, 1, std::format("public:reserved_{}", n % 2000));
        n++;
      }
    });
  }

  constexpr size_t reserved_txs = 2000;
  for (size_t i = 0; i < reserved_txs; ++i)
  {
    // Each reserved transaction writes to a map that does not exist yet, so
    // committing it adds to the Store's map set. Nothing else here may take
    // maps_lock, or it would order the write against the readers and hide the
    // race being reproduced.
    auto tx = store.create_reserved_tx(store.next_txid());
    tx.rw<MapTypes::StringString>(std::format("public:reserved_{}", i))
      ->put("k", "v");
    const auto [result, data, claims, commit_evidence, hooks] =
      tx.commit_reserved();
    REQUIRE(result == ccf::kv::CommitResult::SUCCESS);
  }

  for (auto& reader : readers)
  {
    reader.request_stop();
  }
  readers.clear();

  // Confirm the writes really did extend the map set, so this exercises
  // Store::add_dynamic_map rather than silently doing nothing.
  REQUIRE(ccf::kv::test::has_map_at(
    store, store.current_version(), "public:reserved_0"));
  REQUIRE(ccf::kv::test::has_map_at(
    store,
    store.current_version(),
    std::format("public:reserved_{}", reserved_txs - 1)));
}

// Exposes the version the chunker has recorded entries up to, which is the
// state a rollback and a concurrent commit can disagree about.
class InspectableChunker : public ccf::kv::LedgerChunker
{
public:
  ccf::kv::Version current_version()
  {
    ccf::ds::MutexGuard guard(chunker_lock);
    return current_tx_version;
  }

  bool has_chunk_end_at(ccf::kv::Version v)
  {
    ccf::ds::MutexGuard guard(chunker_lock);
    return chunk_ends.contains(v);
  }
};

// A PendingTx which rolls the store back while Store::commit() is midway
// through the batch it belongs to. Store::commit() calls this after releasing
// version_lock, so it reproduces a rollback landing between a batch being
// assembled and its chunk metadata being recorded, without needing threads.
class RollingBackPendingTx : public ccf::kv::PendingTx
{
  ccf::TxID txid;
  BackendStore& store;
  MapTypes::StringString& table;
  ccf::TxID rollback_to;
  ccf::kv::Term rollback_term;

public:
  RollingBackPendingTx(
    ccf::TxID txid_,
    BackendStore& store_,
    MapTypes::StringString& table_,
    ccf::TxID rollback_to_,
    ccf::kv::Term rollback_term_) :
    txid(txid_),
    store(store_),
    table(table_),
    rollback_to(rollback_to_),
    rollback_term(rollback_term_)
  {}

  ccf::kv::PendingTxInfo call() override
  {
    auto tx = store.create_reserved_tx(txid);
    tx.rw(table)->put("key", "value");
    auto info = tx.commit_reserved();
    store.rollback(rollback_to, rollback_term);
    return info;
  }
};

TEST_CASE("Chunk metadata is not restored by a batch a rollback discarded")
{
  BackendStore store;
  store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());
  auto consensus = std::make_shared<ccf::kv::test::PrimaryStubConsensus>();
  store.set_consensus(consensus);
  auto chunker = std::make_shared<InspectableChunker>();
  store.set_chunker(chunker);

  constexpr ccf::kv::Term initial_term = 2;
  store.initialise_term(initial_term);
  MapTypes::StringString map("public:map");

  INFO("Commit an ordinary transaction to establish a baseline");
  {
    auto tx = store.create_tx();
    tx.rw(map)->put("key", "initial");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  const auto baseline_txid = store.current_txid();
  REQUIRE(chunker->current_version() == baseline_txid.seqno);

  INFO(
    "A batch whose writes are discarded by a rollback must not leave chunk "
    "metadata behind");
  {
    const auto reserved = store.next_txid();
    REQUIRE(reserved.seqno == baseline_txid.seqno + 1);

    // The rollback target is below the reserved version, so it truncates and
    // moves the rollback epoch on - exactly what a real election would do.
    store.commit(
      reserved,
      std::make_unique<RollingBackPendingTx>(
        reserved, store, map, baseline_txid, initial_term + 1),
      false);
  }

  CHECK(store.current_txid() == baseline_txid);
  CHECK(chunker->current_version() == baseline_txid.seqno);

  INFO(
    "The next transaction is chunked against its own version, with no "
    "accumulated offset from the discarded batch");
  {
    auto tx = store.create_tx();
    tx.rw(map)->put("key", "fresh");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  CHECK(chunker->current_version() == store.current_version());
}

TEST_CASE("A rollback never moves chunk metadata past the store's version")
{
  BackendStore store;
  store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());
  auto consensus = std::make_shared<ccf::kv::test::PrimaryStubConsensus>();
  store.set_consensus(consensus);
  auto chunker = std::make_shared<InspectableChunker>();
  store.set_chunker(chunker);

  constexpr ccf::kv::Term initial_term = 2;
  store.initialise_term(initial_term);
  MapTypes::StringString map("public:map");

  {
    auto tx = store.create_tx();
    tx.rw(map)->put("key", "initial");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  const auto version = store.current_version();
  REQUIRE(chunker->current_version() == version);

  SUBCASE("Rollback to the current version")
  {
    store.rollback(store.current_txid(), initial_term + 1);
  }

  SUBCASE("Rollback beyond the current version")
  {
    store.rollback({initial_term, version + 3}, initial_term + 1);
  }

  // Neither discards anything, so neither may move the chunker.
  CHECK(store.current_version() == version);
  CHECK(chunker->current_version() == version);

  INFO("Later entries are still recorded against their own version");
  {
    auto tx = store.create_tx();
    tx.rw(map)->put("key", "fresh");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }
  CHECK(chunker->current_version() == store.current_version());
}

TEST_CASE("Rollback-sensitive transaction flags are not restored")
{
  BackendStore store;
  store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());
  auto consensus = std::make_shared<ccf::kv::test::PrimaryStubConsensus>();
  store.set_consensus(consensus);
  auto chunker = std::make_shared<InspectableChunker>();
  store.set_chunker(chunker);

  constexpr ccf::kv::Term initial_term = 2;
  store.initialise_term(initial_term);
  MapTypes::StringString map("public:map");

  for (const auto* value : {"first", "second"})
  {
    auto tx = store.create_tx();
    tx.rw(map)->put("key", value);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  const auto discarded = store.current_txid();
  REQUIRE(store.check_rollback_count(0));

  INFO("Flags from a transaction a rollback discarded are dropped");
  {
    // A view change truncates the transaction's write away, then the
    // transaction reaches the point where it would apply its flags.
    store.rollback({initial_term, discarded.seqno - 1}, initial_term + 1);
    REQUIRE(store.check_rollback_count(1));

    CHECK_FALSE(store.apply_tx_flags(
      discarded.seqno,
      discarded.view,
      0,
      /* force_ledger_chunk */ true,
      /* snapshot_at_next_signature */ true));

    CHECK_FALSE(store.flag_enabled(
      ccf::kv::AbstractStore::StoreFlag::SNAPSHOT_AT_NEXT_SIGNATURE));
    CHECK_FALSE(chunker->is_chunk_end_requested(discarded.seqno));
  }

  INFO("Flags from a transaction still in its own epoch are applied");
  {
    auto tx = store.create_tx();
    tx.rw(map)->put("key", "replacement");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    const auto replacement = store.current_txid();

    // Commit a later transaction, so that the store's version has moved on by
    // the time the earlier transaction applies its flags.
    {
      auto later = store.create_tx();
      later.rw(map)->put("other", "later");
      REQUIRE(later.commit() == ccf::kv::CommitResult::SUCCESS);
    }
    REQUIRE(store.current_txid().seqno == replacement.seqno + 1);

    CHECK(store.apply_tx_flags(
      replacement.seqno,
      replacement.view,
      1,
      /* force_ledger_chunk */ true,
      /* snapshot_at_next_signature */ true));

    CHECK(store.flag_enabled(
      ccf::kv::AbstractStore::StoreFlag::SNAPSHOT_AT_NEXT_SIGNATURE));

    INFO("The chunk is requested at the transaction's own version");
    CHECK(chunker->is_chunk_end_requested(replacement.seqno));
    CHECK_FALSE(chunker->is_chunk_end_requested(replacement.seqno - 1));
  }
}

TEST_CASE("Reserved signature side effects are not applied after a rollback")
{
  BackendStore store;
  store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());
  auto consensus = std::make_shared<ccf::kv::test::PrimaryStubConsensus>();
  store.set_consensus(consensus);
  auto chunker = std::make_shared<InspectableChunker>();
  store.set_chunker(chunker);

  constexpr ccf::kv::Term initial_term = 2;
  store.initialise_term(initial_term);
  MapTypes::StringString map("public:map");

  for (const auto* value : {"first", "second"})
  {
    auto tx = store.create_tx();
    tx.rw(map)->put("key", value);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  const auto reserved = store.current_txid();
  REQUIRE(store.check_rollback_count(0));

  INFO("A signature a rollback discarded records no chunk end");
  {
    // A signature ends a chunk when a snapshot is due, which is what the
    // reserved transaction records once it decides to replicate.
    store.set_flag(
      ccf::kv::AbstractStore::StoreFlag::SNAPSHOT_AT_NEXT_SIGNATURE);
    store.rollback({initial_term, reserved.seqno - 1}, initial_term + 1);
    REQUIRE(store.check_rollback_count(1));

    CHECK_FALSE(store
                  .should_create_ledger_chunk_for_reserved_tx(
                    reserved.seqno, reserved.view, 0)
                  .has_value());
    CHECK_FALSE(chunker->has_chunk_end_at(reserved.seqno));
  }

  INFO("A signature whose view has moved on records no chunk end");
  {
    auto tx = store.create_tx();
    tx.rw(map)->put("key", "next");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    const auto superseded = store.current_txid();
    store.set_flag(
      ccf::kv::AbstractStore::StoreFlag::SNAPSHOT_AT_NEXT_SIGNATURE);

    // A rollback which discards nothing locally, but moves the view on, so
    // consensus will refuse to replicate this signature. The snapshot flag
    // survives, so without the view check the chunk end would be recorded.
    store.rollback(superseded, superseded.view + 1);
    REQUIRE(store.check_rollback_count(1));
    REQUIRE(store.flag_enabled(
      ccf::kv::AbstractStore::StoreFlag::SNAPSHOT_AT_NEXT_SIGNATURE));

    CHECK_FALSE(store
                  .should_create_ledger_chunk_for_reserved_tx(
                    superseded.seqno, superseded.view, 1)
                  .has_value());
    CHECK_FALSE(chunker->has_chunk_end_at(superseded.seqno));
  }

  INFO("A signature still in its own epoch records its chunk end");
  {
    auto tx = store.create_tx();
    tx.rw(map)->put("key", "replacement");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    const auto replacement = store.current_txid();
    store.set_flag(
      ccf::kv::AbstractStore::StoreFlag::SNAPSHOT_AT_NEXT_SIGNATURE);

    const auto should_create_chunk =
      store.should_create_ledger_chunk_for_reserved_tx(
        replacement.seqno, replacement.view, 1);
    REQUIRE(should_create_chunk.has_value());
    CHECK(should_create_chunk.value());
    CHECK(chunker->has_chunk_end_at(replacement.seqno));
  }
}

TEST_CASE(
  "Reserved signature transactions ignore the configured transaction size "
  "limit" *
  doctest::test_suite("serialisation"))
{
  BackendStore kv_store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);
  kv_store.set_max_transaction_size(1);

  MapTypes::StringString map("public:signature");
  auto tx = kv_store.create_reserved_tx(kv_store.next_txid());
  tx.rw(map)->put("signature", std::string(512, 'A'));

  const auto [result, data, claims, commit_evidence, hooks] =
    tx.commit_reserved();
  REQUIRE(result == ccf::kv::CommitResult::SUCCESS);
  REQUIRE(data.size() > kv_store.get_max_transaction_size());
}

TEST_CASE(
  "Reject configuring a maximum transaction size beyond the serialisable "
  "limit" *
  doctest::test_suite("serialisation"))
{
  BackendStore kv_store;

  // The largest entry the ledger entry header can describe is accepted.
  REQUIRE_NOTHROW(
    kv_store.set_max_transaction_size(ccf::kv::max_serialised_entry_size));

  // A value larger than can ever be serialised is rejected at configuration
  // time, rather than being deferred to a later serialisation failure.
  REQUIRE_THROWS_AS(
    kv_store.set_max_transaction_size(std::numeric_limits<size_t>::max()),
    std::logic_error);
}

TEST_CASE(
  "Encrypted entries retain the GCM layout and authenticate public bytes" *
  doctest::test_suite("serialisation"))
{
  auto secrets = std::make_shared<ccf::LedgerSecrets>();
  secrets->init();
  secrets->set_secret(4, ccf::make_ledger_secret());
  auto encryptor = std::make_shared<ccf::NodeEncryptor>(secrets);
  const ccf::TxID tx_id{2, 2};

  const auto check = [&](
                       const std::vector<uint8_t>& public_domain,
                       const std::vector<uint8_t>& private_domain,
                       ccf::kv::EntryType type,
                       bool historical_hint) {
    ccf::kv::RawKvStoreSerialiser serialiser(
      encryptor, tx_id, type, 0, {}, ccf::no_claims(), historical_hint);
    const auto entry =
      serialiser.serialise_domains(public_domain, private_domain);

    std::vector<uint8_t> header;
    std::vector<uint8_t> cipher;
    REQUIRE(encryptor->encrypt(
      private_domain,
      public_domain,
      header,
      cipher,
      tx_id,
      type,
      historical_hint));

    ccf::kv::SerialisedEntryHeader entry_header;
    entry_header.set_size(
      header.size() + sizeof(size_t) + public_domain.size() + cipher.size());
    std::vector<uint8_t> expected(entry.size());
    auto* data = expected.data();
    auto remaining = expected.size();
    serialized::write(data, remaining, entry_header);
    serialized::write(data, remaining, header.data(), header.size());
    serialized::write(data, remaining, public_domain.size());
    serialized::write(
      data, remaining, public_domain.data(), public_domain.size());
    serialized::write(data, remaining, cipher.data(), cipher.size());
    REQUIRE(remaining == 0);
    REQUIRE(entry == expected);

    std::vector<uint8_t> decrypted;
    ccf::kv::Term term = 0;
    REQUIRE(encryptor->decrypt(
      cipher, public_domain, header, decrypted, tx_id.seqno, term, true));
    REQUIRE(decrypted == private_domain);
    if (type != ccf::kv::EntryType::Snapshot)
    {
      REQUIRE(term == tx_id.view);
    }

    auto changed_public_domain = public_domain;
    changed_public_domain.front() ^= 1;
    REQUIRE_FALSE(encryptor->decrypt(
      cipher,
      changed_public_domain,
      header,
      decrypted,
      tx_id.seqno,
      term,
      true));
  };

  check({1, 2, 3}, {}, ccf::kv::EntryType::WriteSet, false);
  check({1}, {4, 5, 6}, ccf::kv::EntryType::WriteSet, false);
  check({1, 2, 3}, {4, 5, 6}, ccf::kv::EntryType::WriteSet, false);
  check({1, 2, 3}, {4, 5, 6}, ccf::kv::EntryType::Snapshot, true);

  auto missing_secrets = std::make_shared<ccf::LedgerSecrets>();
  ccf::kv::RawKvStoreSerialiser failing(
    std::make_shared<ccf::NodeEncryptor>(missing_secrets),
    tx_id,
    ccf::kv::EntryType::WriteSet,
    0);
  REQUIRE_THROWS_AS(
    failing.serialise_domains({1, 2, 3}, {4, 5, 6}),
    ccf::kv::KvSerialiserException);
}

// SNIPPET_START: CustomClass definition
struct CustomClass
{
  std::string s;
  size_t n;
};

// These macros allow the default nlohmann JSON serialiser to be used
DECLARE_JSON_TYPE(CustomClass);
DECLARE_JSON_REQUIRED_FIELDS(CustomClass, s, n);

// SNIPPET_END: CustomClass definition

// Not really intended to be extended, but lets us use the BlitSerialiser for
// this specific type
namespace ccf::kv::serialisers
{
  template <>
  struct BlitSerialiser<CustomClass>
  {
    static SerialisedEntry to_serialised(const CustomClass& cc)
    {
      // Don't encode size, entire remainder of buffer is string
      const auto s_size = cc.s.size();
      const auto total_size = sizeof(cc.n) + s_size;
      SerialisedEntry s(total_size);

      uint8_t* data = s.data();
      size_t remaining = s.size();

      memcpy(data, (void*)&cc.n, sizeof(cc.n));
      data += sizeof(cc.n);
      remaining -= sizeof(cc.n);

      memcpy(data, (void*)cc.s.c_str(), remaining);

      return s;
    }

    static CustomClass from_serialised(const SerialisedEntry& s)
    {
      CustomClass cc;
      const uint8_t* data = s.data();
      size_t remaining = s.size();

      cc.n = *(decltype(cc.n)*)data;
      data += sizeof(cc.n);
      remaining -= sizeof(cc.n);

      cc.s.assign(data, data + remaining);

      return cc;
    }
  };
}

// SNIPPET_START: CustomSerialiser definition
struct CustomSerialiser
{
  /**
   * Format:
   * [ 8 bytes=n | 8 bytes=size_of_s | size_of_s bytes=s... ]
   */

  static constexpr auto size_of_n = 8;
  static constexpr auto size_of_size_of_s = 8;

  static ccf::kv::serialisers::SerialisedEntry to_serialised(
    const CustomClass& cc)
  {
    const auto s_size = cc.s.size();
    const auto total_size = size_of_n + size_of_size_of_s + s_size;
    ccf::kv::serialisers::SerialisedEntry serialised(total_size);
    uint8_t* data = serialised.data();
    memcpy(data, (const uint8_t*)&cc.n, size_of_n);
    data += size_of_n;
    memcpy(data, (const uint8_t*)&s_size, size_of_size_of_s);
    data += size_of_size_of_s;
    memcpy(data, (const uint8_t*)cc.s.data(), s_size);
    return serialised;
  }

  static CustomClass from_serialised(
    const ccf::kv::serialisers::SerialisedEntry& ser)
  {
    CustomClass cc;
    const uint8_t* data = ser.data();
    cc.n = *(const uint64_t*)data;
    data += size_of_n;
    const auto s_size = *(const uint64_t*)data;
    data += size_of_size_of_s;
    cc.s.resize(s_size);
    std::memcpy(cc.s.data(), data, s_size);
    return cc;
  }
};

// SNIPPET_END: CustomSerialiser definition

struct CustomJsonSerialiser
{
  using Bytes = ccf::kv::serialisers::SerialisedEntry;

  static Bytes to_serialised(const CustomClass& c)
  {
    nlohmann::json j = nlohmann::json::object();
    j["s"] = c.s;
    j["n"] = c.n;
    const auto s = j.dump();
    return Bytes(s.begin(), s.end());
  }

  static CustomClass from_serialised(const Bytes& b)
  {
    const auto j = nlohmann::json::parse(b.begin(), b.end());
    CustomClass c;
    c.s = j["s"];
    c.n = j["n"];
    return c;
  }
};

struct KPrefix
{
  static constexpr auto prefix = "This is a key:";
};

struct VPrefix
{
  static constexpr auto prefix = "Here follows a value:";
};

template <typename T>
struct CustomVerboseDumbSerialiser
{
  using Bytes = ccf::kv::serialisers::SerialisedEntry;

  static Bytes to_serialised(const CustomClass& c)
  {
    const auto verbose = std::format("{}\ns={}\nn={}", T::prefix, c.s, c.n);
    return Bytes(verbose.begin(), verbose.end());
  }

  static CustomClass from_serialised(const Bytes& b)
  {
    std::string s(b.begin(), b.end());
    const auto prefix_start = s.find(T::prefix);
    if (prefix_start != 0)
    {
      throw std::logic_error("Missing expected prefix");
    }

    CustomClass c;
    const auto first_linebreak = s.find('\n');
    const auto last_linebreak = s.rfind('\n');
    const auto seg_a = s.substr(0, first_linebreak);
    const auto seg_b =
      s.substr(first_linebreak + 1, last_linebreak - first_linebreak - 1);
    const auto seg_c = s.substr(last_linebreak + 1);

    c.s = seg_b.substr(strlen("s="));
    const auto n_str = seg_c.substr(strlen("n="));
    c.n = strtoul(n_str.c_str(), nullptr, 10);
    return c;
  }
};

using JsonSerialisedMap = ccf::kv::JsonSerialisedMap<CustomClass, CustomClass>;
using RawCopySerialisedMap =
  ccf::kv::RawCopySerialisedMap<CustomClass, CustomClass>;
using MixSerialisedMapB = ccf::kv::TypedMap<
  CustomClass,
  CustomClass,
  ccf::kv::serialisers::JsonSerialiser<CustomClass>,
  ccf::kv::serialisers::BlitSerialiser<CustomClass>>;

// SNIPPET_START: CustomSerialisedMap definition
using CustomSerialisedMap = ccf::kv::
  TypedMap<CustomClass, CustomClass, CustomSerialiser, CustomSerialiser>;
// SNIPPET_END: CustomSerialisedMap definition

using CustomJsonMap = ccf::kv::TypedMap<
  CustomClass,
  CustomClass,
  CustomJsonSerialiser,
  CustomJsonSerialiser>;
using VerboseSerialisedMap = ccf::kv::TypedMap<
  CustomClass,
  CustomClass,
  CustomVerboseDumbSerialiser<KPrefix>,
  CustomVerboseDumbSerialiser<VPrefix>>;

TEST_CASE_TEMPLATE(
  "Custom type serialisation test" * doctest::test_suite("serialisation"),
  MapType,
  JsonSerialisedMap,
  RawCopySerialisedMap,
  MixSerialisedMapB,
  CustomSerialisedMap,
  CustomJsonMap,
  VerboseSerialisedMap)
{
  BackendStore kv_store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);

  MapType map("public:map");

  CustomClass k1{"hello", 42};
  CustomClass v1{"world", 43};

  CustomClass k2{"saluton", 100};
  CustomClass v2{"mondo", 1024};

  INFO("Serialise/Deserialise 2 kv stores");
  {
    BackendStore kv_store2;
    kv_store2.set_encryptor(encryptor);

    MapType map2("public:map");

    auto tx = kv_store.create_reserved_tx(kv_store.next_txid());
    auto handle = tx.rw(map);
    handle->put(k1, v1);
    handle->put(k2, v2);

    auto [success_, data_, claims_digest, commit_evidence_digest, hooks] =
      tx.commit_reserved();
    auto& success = success_;
    auto& data = data_;
    REQUIRE(success == ccf::kv::CommitResult::SUCCESS);
    kv_store.compact(kv_store.current_version());

    REQUIRE(kv_store2.deserialize(data)->apply() == ccf::kv::ApplyResult::PASS);
    auto tx2 = kv_store2.create_tx();
    auto handle2 = tx2.rw(map2);

    // operator== does not need to be defined for custom types. In this case
    // it is not, and we check each member manually
    auto va = handle2->get(k1);
    REQUIRE(va.has_value());
    REQUIRE(va->s == v1.s);
    REQUIRE(va->n == v1.n);

    auto vb = handle2->get(k2);
    REQUIRE(vb.has_value());
    REQUIRE(vb->s == v2.s);
    REQUIRE(vb->n == v2.n);
  }
}

TEST_CASE("Deserialise return status")
{
  BackendStore store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  store.set_encryptor(encryptor);

  ccf::Signatures signatures(ccf::Tables::SIGNATURES);
  ccf::SerialisedMerkleTree serialised_tree(
    ccf::Tables::SERIALISED_MERKLE_TREE);

  ccf::Nodes nodes(ccf::Tables::NODES);
  MapTypes::NumNum data("public:data");

  constexpr auto default_curve = ccf::crypto::CurveID::SECP384R1;
  auto kp = ccf::crypto::make_ec_key_pair(default_curve);

  auto history = std::make_shared<ccf::BasicNullTxHistory<BackendStore>>(
    store, ccf::kv::test::PrimaryNodeId, *kp);
  store.set_history(history);

  {
    auto tx = store.create_reserved_tx(store.next_txid());
    auto data_handle = tx.rw(data);
    data_handle->put(42, 42);
    auto [success_, data_, claims_digest, commit_evidence_digest, hooks] =
      tx.commit_reserved();
    auto& success = success_;
    auto& serialised_data = data_;
    REQUIRE(success == ccf::kv::CommitResult::SUCCESS);

    REQUIRE(
      store.deserialize(serialised_data)->apply() ==
      ccf::kv::ApplyResult::PASS);
  }

  {
    auto tx = store.create_reserved_tx(store.next_txid());
    auto sig_handle = tx.rw(signatures);
    auto tree_handle = tx.rw(serialised_tree);
    ccf::PrimarySignature sigv(ccf::kv::test::PrimaryNodeId, 2);
    sig_handle->put(sigv);
    tree_handle->put({});
    auto [success_, data_, claims_digest, commit_evidence_digest, hooks] =
      tx.commit_reserved();
    auto& success = success_;
    auto& serialised_data = data_;
    REQUIRE(success == ccf::kv::CommitResult::SUCCESS);

    REQUIRE(
      store.deserialize(serialised_data)->apply() ==
      ccf::kv::ApplyResult::PASS_SIGNATURE);
  }

  INFO("Signature transactions with additional contents should fail");
  {
    auto tx = store.create_reserved_tx(store.next_txid());
    auto sig_handle = tx.rw(signatures);
    auto data_handle = tx.rw(data);
    ccf::PrimarySignature sigv(ccf::kv::test::PrimaryNodeId, 2);
    sig_handle->put(sigv);
    data_handle->put(43, 43);
    auto [success_, data_, claims_digest, commit_evidence_digest, hooks] =
      tx.commit_reserved();
    auto& success = success_;
    auto& serialised_data = data_;
    REQUIRE(success == ccf::kv::CommitResult::SUCCESS);

    REQUIRE(
      store.deserialize(serialised_data)->apply() ==
      ccf::kv::ApplyResult::FAIL);
  }
}

namespace
{
  std::shared_ptr<ccf::BasicNullTxHistory<BackendStore>> attach_null_history(
    BackendStore& store, const ccf::NodeId& node_id)
  {
    auto kp = ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP384R1);
    auto history = std::make_shared<ccf::BasicNullTxHistory<BackendStore>>(
      store, node_id, *kp);
    store.set_history(history);
    return history;
  }

  // last_committable is only observable through committable_gap(), which is
  // defined as current_version() - last_committable
  ccf::kv::Version last_committable(BackendStore& store)
  {
    return store.current_version() - store.committable_gap();
  }

  // Replays the entries replicated by primary_consensus whose seqno lies in
  // [from_seqno, to_seqno] into store, as a backup or a recovering node would
  void replay_ledger(
    const ccf::kv::test::StubConsensus& primary_consensus,
    BackendStore& store,
    ccf::kv::Version from_seqno,
    ccf::kv::Version to_seqno)
  {
    for (const auto& [seqno, data, committable, hooks] :
         primary_consensus.replica)
    {
      if (seqno < from_seqno || seqno > to_seqno)
      {
        continue;
      }

      INFO("Replaying entry at seqno ", seqno);
      const auto expected = committable ? ccf::kv::ApplyResult::PASS_SIGNATURE :
                                          ccf::kv::ApplyResult::PASS;
      REQUIRE(store.deserialize(*data)->apply() == expected);
      REQUIRE(store.current_version() == seqno);
    }
  }
}

TEST_CASE("committable_gap after replaying a ledger ending in a signature")
{
  // A node recovering the public ledger, or a backup, replays entries
  // produced by another node and may then become primary. The gap used to
  // decide when to emit a signature must count from the latest replayed
  // signature, not from the start of the ledger.
  constexpr ccf::kv::Term term = 2;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  MapTypes::StringString map("public:map");

  BackendStore primary;
  primary.set_encryptor(encryptor);
  auto primary_consensus =
    std::make_shared<ccf::kv::test::PrimaryStubConsensus>();
  primary.set_consensus(primary_consensus);
  auto primary_history =
    attach_null_history(primary, ccf::kv::test::PrimaryNodeId);
  primary.initialise_term(term);

  constexpr size_t tx_count = 3;

  INFO("A signature emitted by the primary itself resets its gap");
  for (size_t i = 1; i <= tx_count; ++i)
  {
    auto tx = primary.create_tx();
    tx.rw(map)->put(std::format("key{}", i), "value");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    REQUIRE(primary.committable_gap() == i);
  }
  primary_history->emit_signature();
  const auto signature_seqno = primary.current_version();
  REQUIRE(signature_seqno == tx_count + 1);
  REQUIRE(primary.committable_gap() == 0);
  REQUIRE(primary_consensus->replica.size() == signature_seqno);

  BackendStore store;
  store.set_encryptor(encryptor);
  auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
  store.set_consensus(consensus);
  auto history = attach_null_history(store, ccf::kv::test::FirstBackupNodeId);
  store.initialise_term(term);

  INFO("Replayed entries grow the gap until a signature is replayed");
  for (const auto& [seqno, data, committable, hooks] :
       primary_consensus->replica)
  {
    REQUIRE(committable == (seqno == signature_seqno));
    replay_ledger(*primary_consensus, store, seqno, seqno);
    REQUIRE(store.committable_gap() == (committable ? 0 : seqno));
  }
  REQUIRE(store.current_version() == signature_seqno);
  REQUIRE(last_committable(store) == signature_seqno);

  INFO(
    "Becoming primary, at the end of recovery or after an election, moves the "
    "term on without disturbing the gap");
  store.rollback(store.current_txid(), term + 1);
  consensus->force_become_primary();
  REQUIRE(consensus->can_replicate());
  REQUIRE(store.current_version() == signature_seqno);
  REQUIRE(store.committable_gap() == 0);

  INFO("Transactions committed by the new primary count from that signature");
  for (size_t i = 1; i <= tx_count; ++i)
  {
    auto tx = store.create_tx();
    tx.rw(map)->put("key", std::format("value{}", i));
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    REQUIRE(store.committable_gap() == i);
  }

  INFO("A signature emitted by the new primary resets the gap");
  history->emit_signature();
  REQUIRE(store.current_version() == signature_seqno + tx_count + 1);
  REQUIRE(store.committable_gap() == 0);
}

TEST_CASE("committable_gap after rolling back replayed entries")
{
  constexpr ccf::kv::Term term = 2;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  MapTypes::StringString map("public:map");

  BackendStore primary;
  primary.set_encryptor(encryptor);
  auto primary_consensus =
    std::make_shared<ccf::kv::test::PrimaryStubConsensus>();
  primary.set_consensus(primary_consensus);
  auto primary_history =
    attach_null_history(primary, ccf::kv::test::PrimaryNodeId);
  primary.initialise_term(term);

  auto commit_txs = [&](size_t count) {
    for (size_t i = 0; i < count; ++i)
    {
      auto tx = primary.create_tx();
      tx.rw(map)->put("key", std::format("value{}", primary.current_version()));
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }
  };

  // Ledger: 3 transactions, a signature, 2 transactions, a signature, 2
  // transactions
  commit_txs(3);
  primary_history->emit_signature();
  const auto first_signature = primary.current_version();
  commit_txs(2);
  primary_history->emit_signature();
  const auto second_signature = primary.current_version();
  commit_txs(2);
  const auto last_seqno = primary.current_version();
  REQUIRE(first_signature == 4);
  REQUIRE(second_signature == 7);
  REQUIRE(last_seqno == 9);

  BackendStore store;
  store.set_encryptor(encryptor);
  attach_null_history(store, ccf::kv::test::FirstBackupNodeId);
  store.initialise_term(term);

  INFO("The gap counts from the latest replayed signature");
  replay_ledger(*primary_consensus, store, 1, last_seqno);
  REQUIRE(last_committable(store) == second_signature);
  REQUIRE(store.committable_gap() == last_seqno - second_signature);

  INFO(
    "Rolling back to the latest signature, as at the end of public recovery, "
    "leaves no gap");
  store.rollback({term, second_signature}, term + 1);
  REQUIRE(store.current_version() == second_signature);
  REQUIRE(store.committable_gap() == 0);

  INFO(
    "Rolling back below the latest signature clamps last_committable to the "
    "rollback point, so that the gap cannot underflow");
  const auto between_signatures = first_signature + 1;
  store.rollback({term, between_signatures}, term + 2);
  REQUIRE(store.current_version() == between_signatures);
  REQUIRE(store.committable_gap() == 0);
  REQUIRE(last_committable(store) == between_signatures);

  INFO("Replaying the discarded entries again restores the gap");
  replay_ledger(*primary_consensus, store, between_signatures + 1, last_seqno);
  REQUIRE(last_committable(store) == second_signature);
  REQUIRE(store.committable_gap() == last_seqno - second_signature);
}

TEST_CASE("Ledger entry chunk request")
{
  BackendStore store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
  store.set_encryptor(encryptor);
  store.set_consensus(consensus);

  ccf::Signatures signatures(ccf::Tables::SIGNATURES);
  ccf::SerialisedMerkleTree serialised_tree(
    ccf::Tables::SERIALISED_MERKLE_TREE);

  ccf::Nodes nodes(ccf::Tables::NODES);
  MapTypes::NumNum data("public:data");

  constexpr auto default_curve = ccf::crypto::CurveID::SECP384R1;
  auto kp = ccf::crypto::make_ec_key_pair(default_curve);

  auto history = std::make_shared<ccf::BasicNullTxHistory<BackendStore>>(
    store, ccf::kv::test::PrimaryNodeId, *kp);
  store.set_history(history);

  auto chunker = std::make_shared<ccf::kv::LedgerChunker>();
  store.set_chunker(chunker);

  SUBCASE("Chunk at next signature")
  {
    // Ledger chunk flag is not set in the store
    REQUIRE(!store.should_create_ledger_chunk(store.current_version()));

    INFO("Add a transaction with the chunking flag enabled");
    {
      MapTypes::StringString map("public:map");
      auto tx = store.create_tx();

      // Request a ledger chunk at the next signature
      tx.set_tx_flag(
        ccf::kv::CommittableTx::TxFlag::LEDGER_CHUNK_AT_NEXT_SIGNATURE);

      auto h1 = tx.rw(map);
      h1->put("key", "value");
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    // Flag is now set in the store
    REQUIRE(store.should_create_ledger_chunk(store.current_version()));

    INFO("Roll back the last transaction");
    {
      // Dummy rollback to the current TxID, which doesn't clear the chunking
      // flag
      store.rollback(store.current_txid(), store.commit_view());

      // Ledger chunk flag is still set in the store
      REQUIRE(store.should_create_ledger_chunk(store.current_version()));

      // Roll the last transaction back to clear the flag in the store
      store.rollback(
        {store.commit_view(), store.current_version() - 1},
        store.commit_view());

      // Ledger chunk flag is not set in the store anymore
      REQUIRE(!store.should_create_ledger_chunk(store.current_version()));
    }

    INFO("Add another transaction with the chunking flag enabled");
    {
      MapTypes::StringString map("public:map");
      auto tx = store.create_tx();

      // Request a ledger chunk at the next signature again
      tx.set_tx_flag(
        ccf::kv::CommittableTx::TxFlag::LEDGER_CHUNK_AT_NEXT_SIGNATURE);

      auto h1 = tx.rw(map);
      h1->put("key", "value");
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    // Ledger chunk flag is now set in the store
    REQUIRE(store.should_create_ledger_chunk(store.current_version()));

    INFO(
      "Add a signature transaction which triggers chunk via entry header flag");
    {
      auto txid = store.next_txid();
      auto tx = store.create_reserved_tx(txid);
      auto sig_handle = tx.rw(signatures);
      auto tree_handle = tx.rw(serialised_tree);
      ccf::PrimarySignature sigv(ccf::kv::test::PrimaryNodeId, txid.seqno);
      sig_handle->put(sigv);
      tree_handle->put({});
      auto [success_, data_, claims_digest, commit_evidence_digest, hooks] =
        tx.commit_reserved();
      auto& success = success_;
      auto& serialised_data = data_;
      REQUIRE(success == ccf::kv::CommitResult::SUCCESS);

      REQUIRE(
        store.deserialize(serialised_data)->apply() ==
        ccf::kv::ApplyResult::PASS_SIGNATURE);

      // Header flag is set in the last entry
      const uint8_t* entry_data = serialised_data.data();
      size_t entry_data_size = serialised_data.size();
      auto header = serialized::peek<ccf::kv::SerialisedEntryHeader>(
        entry_data, entry_data_size);
      REQUIRE(
        (header.flags & ccf::kv::EntryFlags::FORCE_LEDGER_CHUNK_AFTER) != 0);
    }

    // Ledger chunk flag is not set in the store anymore
    chunker->produced_chunk_at(store.current_version());
    REQUIRE(!store.should_create_ledger_chunk(store.current_version()));
  }

  SUBCASE("Chunk before this transaction")
  {
    REQUIRE(!consensus->get_latest_data().has_value());

    INFO("Add a transaction with the chunking flag enabled");
    {
      MapTypes::StringString map("public:map");
      auto tx = store.create_tx();

      // Request a ledger chunk before tx
      tx.set_tx_flag(
        ccf::kv::CommittableTx::TxFlag::LEDGER_CHUNK_BEFORE_THIS_TX);

      auto h1 = tx.rw(map);
      h1->put("key", "value");
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    INFO("Verify that flag is included in serialised entry");
    {
      auto data_ = consensus->get_latest_data();
      REQUIRE(data_.has_value());
      auto& serialised_data = data_.value();

      const uint8_t* entry_data = serialised_data.data();
      size_t entry_data_size = serialised_data.size();
      auto header = serialized::peek<ccf::kv::SerialisedEntryHeader>(
        entry_data, entry_data_size);
      REQUIRE(
        (header.flags & ccf::kv::EntryFlags::FORCE_LEDGER_CHUNK_BEFORE) != 0);
    }
  }

  SUBCASE("Chunk when the snapshotter requires one")
  {
    store.set_flag(
      ccf::kv::AbstractStore::StoreFlag::SNAPSHOT_AT_NEXT_SIGNATURE);

    INFO("Add a signature that triggers a snapshot");
    {
      auto txid = store.next_txid();
      auto tx = store.create_reserved_tx(txid);

      // The store must know that we need a new ledger chunk at this version
      REQUIRE(store.should_create_ledger_chunk(txid.seqno));

      // Add the signature
      auto sig_handle = tx.rw(signatures);
      auto tree_handle = tx.rw(serialised_tree);
      ccf::PrimarySignature sigv(ccf::kv::test::PrimaryNodeId, txid.seqno);
      sig_handle->put(sigv);
      tree_handle->put({});
      auto [success_, data_, claims_digest, commit_evidence_digest, hooks] =
        tx.commit_reserved();
      auto& success = success_;
      auto& serialised_data = data_;
      REQUIRE(success == ccf::kv::CommitResult::SUCCESS);

      REQUIRE(
        store.deserialize(serialised_data)->apply() ==
        ccf::kv::ApplyResult::PASS_SIGNATURE);

      // Check that the ledger chunk header flag is set in the last entry
      const uint8_t* entry_data = serialised_data.data();
      size_t entry_data_size = serialised_data.size();
      auto header = serialized::peek<ccf::kv::SerialisedEntryHeader>(
        entry_data, entry_data_size);
      REQUIRE(
        (header.flags & ccf::kv::EntryFlags::FORCE_LEDGER_CHUNK_AFTER) != 0);
    }
  }
}
