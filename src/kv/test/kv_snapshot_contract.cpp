// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf/kv/map.h"
#include "ccf/kv/set.h"
#include "ccf/kv/value.h"
#include "kv/test/kv_test_store.h"
#include "node/encryptor.h"

#include <cstring>
#include <doctest/doctest.h>
#undef FAIL

namespace
{
  using BackendStore = ccf::kv::test::TestStoreBase;

  struct MapTypes
  {
    using StringString = ccf::kv::Map<std::string, std::string>;
    using NumNum = ccf::kv::Map<size_t, size_t>;
    using StringValue = ccf::kv::Value<std::string>;
    using StringSet = ccf::kv::Set<std::string>;
  };

  MapTypes::StringString string_map("public:string_map");
  MapTypes::NumNum num_map("public:num_map");
}

TEST_CASE(
  "Private map recovery rejects a source ahead of the target" *
  doctest::test_suite("snapshot"))
{
  using namespace ccf::kv;
  test::TestStore target;
  test::TestStore source;
  const MapTypes::StringString map("private_map");
  const auto put = [&](BackendStore& store, const char* value) {
    auto tx = store.create_tx();
    tx.rw(map)->put("key", value);
    REQUIRE(tx.commit() == CommitResult::SUCCESS);
  };
  put(target, "target");
  put(source, "source1");
  put(source, "source2");

  REQUIRE_THROWS_WITH_AS(
    target.swap_private_maps(source),
    "Invalid call to swap_private_maps. Source is at version 2 while "
    "target is at 1",
    std::runtime_error);
  CHECK(target.current_version() == 1);
  CHECK(source.current_version() == 2);
  auto target_tx = target.create_read_only_tx();
  auto source_tx = source.create_read_only_tx();
  CHECK(target_tx.ro(map)->get("key") == "target");
  CHECK(source_tx.ro(map)->get("key") == "source2");
}

TEST_CASE(
  "Snapshots are not subject to the transaction size limit" *
  doctest::test_suite("snapshot"))
{
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();

  BackendStore store;
  store.set_encryptor(encryptor);

  // A deliberately small per-transaction limit.
  constexpr size_t small_limit = 512;
  store.set_max_transaction_size(small_limit);

  // Accumulate committed state larger than the limit across several
  // transactions, each of which individually stays under the limit.
  constexpr size_t num_entries = 32;
  constexpr size_t value_size = 64;
  ccf::kv::Version snapshot_version = ccf::kv::NoVersion;
  for (size_t i = 0; i < num_entries; ++i)
  {
    auto tx = store.create_tx();
    auto handle = tx.rw(string_map);
    handle->put("key_" + std::to_string(i), std::string(value_size, 'x'));
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    snapshot_version = tx.commit_version();
  }
  REQUIRE(num_entries * value_size > small_limit);

  std::unique_ptr<ccf::kv::AbstractStore::AbstractSnapshot> snapshot = nullptr;
  {
    snapshot = ccf::kv::test::take_snapshot(store, snapshot_version);
  }

  // Serialising a snapshot larger than the per-transaction limit must not be
  // rejected by that limit.
  std::vector<uint8_t> serialised_snapshot;
  REQUIRE_NOTHROW(
    serialised_snapshot = store.serialise_snapshot(std::move(snapshot)));

  // And it can be read back into a store configured with the same small limit.
  BackendStore new_store;
  new_store.set_encryptor(encryptor);
  new_store.set_max_transaction_size(small_limit);

  ccf::kv::ConsensusHookPtrs hooks;
  REQUIRE_EQ(
    new_store.deserialise_snapshot(
      serialised_snapshot.data(), serialised_snapshot.size(), hooks),
    ccf::kv::ApplyResult::PASS);
  REQUIRE_EQ(new_store.current_version(), snapshot_version);
}

TEST_CASE(
  "Encrypted snapshot replays both domains" * doctest::test_suite("snapshot"))
{
  auto secrets = std::make_shared<ccf::LedgerSecrets>();
  secrets->init();
  auto encryptor = std::make_shared<ccf::NodeEncryptor>(secrets);
  BackendStore source;
  source.set_encryptor(encryptor);

  MapTypes::StringString private_map("private_map");
  auto tx = source.create_tx();
  tx.rw(string_map)->put("public", "value");
  tx.rw(private_map)->put("private", "secret");
  REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  const auto snapshot_version = tx.commit_version();
  secrets->set_secret(snapshot_version + 1, ccf::make_ledger_secret());

  std::unique_ptr<ccf::kv::AbstractStore::AbstractSnapshot> snapshot;
  {
    snapshot = ccf::kv::test::take_snapshot(source, snapshot_version);
  }
  auto entry = source.serialise_snapshot(std::move(snapshot));

  BackendStore recovered;
  recovered.set_encryptor(encryptor);
  ccf::kv::ConsensusHookPtrs hooks;
  REQUIRE(
    recovered.deserialise_snapshot(entry.data(), entry.size(), hooks) ==
    ccf::kv::ApplyResult::PASS);
  auto recovered_tx = recovered.create_tx();
  REQUIRE(recovered_tx.ro(string_map)->get("public") == "value");
  REQUIRE(recovered_tx.ro(private_map)->get("private") == "secret");
}

TEST_CASE("Simple snapshot" * doctest::test_suite("snapshot"))
{
  BackendStore store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  store.set_encryptor(encryptor);

  ccf::kv::Version first_snapshot_version = ccf::kv::NoVersion;
  ccf::kv::Version second_snapshot_version = ccf::kv::NoVersion;

  INFO("Apply transactions to original store");
  {
    auto tx1 = store.create_tx();
    auto handle_1s = tx1.rw(string_map);
    handle_1s->put("foo", "bar");
    handle_1s->put("baz", "hello");
    auto handle_1n = tx1.rw(num_map);
    handle_1n->put(42, 100);
    REQUIRE(tx1.commit() == ccf::kv::CommitResult::SUCCESS);
    first_snapshot_version = tx1.commit_version();

    auto tx2 = store.create_tx();
    auto handle_2s = tx2.rw(string_map);
    handle_2s->remove("baz");
    auto handle_2n = tx2.rw(num_map);
    handle_2n->put(42, 123);
    REQUIRE(tx2.commit() == ccf::kv::CommitResult::SUCCESS);
    second_snapshot_version = tx2.commit_version();

    auto tx3 = store.create_tx();
    auto handle_3 = tx3.rw(string_map);
    handle_3->put("uncommitted", "not committed");
    REQUIRE(handle_3->get("uncommitted") == "not committed");
    // Do not commit tx3
  }

  std::unique_ptr<ccf::kv::AbstractStore::AbstractSnapshot> first_snapshot =
    nullptr;
  {
    first_snapshot =
      ccf::kv::test::take_snapshot(store, first_snapshot_version);
  }
  auto first_serialised_snapshot =
    store.serialise_snapshot(std::move(first_snapshot));

  INFO("Apply snapshot at 1 to new store");
  {
    BackendStore new_store;
    new_store.set_encryptor(encryptor);

    ccf::kv::ConsensusHookPtrs hooks;
    REQUIRE_EQ(
      new_store.deserialise_snapshot(
        first_serialised_snapshot.data(),
        first_serialised_snapshot.size(),
        hooks),
      ccf::kv::ApplyResult::PASS);
    REQUIRE_EQ(new_store.current_version(), first_snapshot_version);

    auto tx1 = new_store.create_tx();
    {
      auto handle = tx1.rw(string_map);
      {
        auto v = handle->get("foo");
        REQUIRE(v.has_value());
        REQUIRE_EQ(v.value(), "bar");

        const auto ver = handle->get_version_of_previous_write("foo");
        REQUIRE(ver.has_value());
        REQUIRE_EQ(ver.value(), first_snapshot_version);
      }

      {
        auto v = handle->get("baz");
        REQUIRE(v.has_value());
        REQUIRE_EQ(v.value(), "hello");

        const auto ver = handle->get_version_of_previous_write("baz");
        REQUIRE(ver.has_value());
        REQUIRE_EQ(ver.value(), first_snapshot_version);
      }

      REQUIRE(!handle->has("uncommitted"));
    }

    {
      auto num_handle = tx1.rw(num_map);
      auto v = num_handle->get(42);
      REQUIRE(v.has_value());
      REQUIRE_EQ(v.value(), 100);

      const auto ver = num_handle->get_version_of_previous_write(42);
      REQUIRE(ver.has_value());
      REQUIRE_EQ(ver.value(), first_snapshot_version);
    }
  }

  std::unique_ptr<ccf::kv::AbstractStore::AbstractSnapshot> second_snapshot =
    nullptr;
  {
    second_snapshot =
      ccf::kv::test::take_snapshot(store, second_snapshot_version);
  }
  auto second_serialised_snapshot =
    store.serialise_snapshot(std::move(second_snapshot));

  INFO("Apply snapshot at 2 to new store");
  {
    BackendStore new_store;

    new_store.set_encryptor(encryptor);

    ccf::kv::ConsensusHookPtrs hooks;
    new_store.deserialise_snapshot(
      second_serialised_snapshot.data(),
      second_serialised_snapshot.size(),
      hooks);
    REQUIRE_EQ(new_store.current_version(), second_snapshot_version);

    auto tx1 = new_store.create_tx();

    {
      auto handle = tx1.rw(string_map);

      {
        auto v = handle->get("foo");
        REQUIRE(v.has_value());
        REQUIRE_EQ(v.value(), "bar");

        const auto ver = handle->get_version_of_previous_write("foo");
        REQUIRE(ver.has_value());
        REQUIRE_EQ(ver.value(), first_snapshot_version);
      }

      {
        auto v = handle->get("baz");
        REQUIRE(!v.has_value());

        const auto ver = handle->get_version_of_previous_write("baz");
        REQUIRE(!ver.has_value());
      }

      REQUIRE(!handle->has("uncommitted"));
    }

    {
      auto num_handle = tx1.rw(num_map);
      auto num_v = num_handle->get(42);
      REQUIRE(num_v.has_value());
      REQUIRE_EQ(num_v.value(), 123);

      const auto ver = num_handle->get_version_of_previous_write(42);
      REQUIRE(ver.has_value());
      REQUIRE_EQ(ver.value(), second_snapshot_version);
    }
  }
}

TEST_CASE("Old snapshots" * doctest::test_suite("snapshot"))
{
  // Test that this code can still parse snapshots produced by old versions of
  // the code
  // NB: These raw strings are base64 encodings from
  // `second_serialised_snapshot` in the "Simple snapshot" test
  std::string raw_snapshot_b64;
  SUBCASE("Tombstone deletions")
  {
    raw_snapshot_b64 =
      "AQDYAAAAAADQAAAAAAAAAAECAAAAAAAAAAAAAAAAAAAADgAAAAAAAABwdWJsaWM6bnVtX21h"
      "cAIAAAAAAAAAKAAAAAAAAAACAAAAAAAAADQyAAAAAAAACwAAAAAAAAACAAAAAAAAADEyMwAA"
      "AAAAEQAAAAAAAABwdWJsaWM6c3RyaW5nX21hcAIAAAAAAAAASAAAAAAAAAAFAAAAAAAAACJi"
      "YXoiAAAACAAAAAAAAAD+/////////"
      "wUAAAAAAAAAImZvbyIAAAANAAAAAAAAAAEAAAAAAAAAImJhciIAAAA=";
  }
  SUBCASE("True deletions")
  {
    raw_snapshot_b64 =
      "AQC4AAAAAACwAAAAAAAAAAECAAAAAAAAAAAAAAAAAAAADgAAAAAAAABwdWJsaWM6bnVtX21h"
      "cAIAAAAAAAAAKAAAAAAAAAACAAAAAAAAADQyAAAAAAAACwAAAAAAAAACAAAAAAAAADEyMwAA"
      "AAAAEQAAAAAAAABwdWJsaWM6c3RyaW5nX21hcAIAAAAAAAAAKAAAAAAAAAAFAAAAAAAAACJm"
      "b28iAAAADQAAAAAAAAABAAAAAAAAACJiYXIiAAAA";
  }
  const auto raw_snapshot = ccf::ds::raw_from_b64(raw_snapshot_b64);

  BackendStore new_store;

  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  new_store.set_encryptor(encryptor);

  ccf::kv::ConsensusHookPtrs hooks;
  new_store.deserialise_snapshot(
    raw_snapshot.data(), raw_snapshot.size(), hooks);

  REQUIRE_EQ(new_store.current_version(), 2);

  {
    auto tx1 = new_store.create_tx();

    {
      auto handle = tx1.rw(string_map);

      {
        auto v = handle->get("foo");
        REQUIRE(v.has_value());
        REQUIRE_EQ(v.value(), "bar");

        const auto ver = handle->get_version_of_previous_write("foo");
        REQUIRE(ver.has_value());
        REQUIRE_EQ(ver.value(), 1);
      }

      {
        auto v = handle->get("baz");
        REQUIRE(!v.has_value());

        const auto ver = handle->get_version_of_previous_write("baz");
        REQUIRE(!ver.has_value());
      }

      REQUIRE(!handle->has("uncommitted"));
    }

    {
      auto num_handle = tx1.rw(num_map);
      auto num_v = num_handle->get(42);
      REQUIRE(num_v.has_value());
      REQUIRE_EQ(num_v.value(), 123);

      const auto ver = num_handle->get_version_of_previous_write(42);
      REQUIRE(ver.has_value());
      REQUIRE_EQ(ver.value(), 2);
    }
  }
}

TEST_CASE("Malformed snapshots are rejected" * doctest::test_suite("snapshot"))
{
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();

  // The target already has maps, which deserialise_snapshot() locks while it
  // parses a snapshot, and must release however that ends
  BackendStore target;
  target.set_encryptor(encryptor);
  MapTypes::StringString private_map("private_map");
  {
    auto tx = target.create_tx();
    tx.rw(string_map)->put("public", "before");
    tx.rw(private_map)->put("private", "before");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  // Serialises a snapshot containing an empty map snapshot for each of
  // map_names in turn
  auto serialise_snapshot =
    [&encryptor](const std::vector<std::string>& map_names) {
      ccf::kv::RawKvStoreSerialiser serialiser(
        encryptor, ccf::TxID{0, 1}, ccf::kv::EntryType::Snapshot, 0);
      for (const auto& map_name : map_names)
      {
        serialiser.start_map(map_name, ccf::kv::SecurityDomain::PUBLIC);
        serialiser.serialise_entry_version(0);
        serialiser.serialise_raw({});
      }
      return serialiser.get_raw_data();
    };

  SUBCASE("Duplicate writes for the same map")
  {
    auto data =
      serialise_snapshot({string_map.get_name(), string_map.get_name()});

    ccf::kv::ConsensusHookPtrs hooks;
    REQUIRE_EQ(
      target.deserialise_snapshot(data.data(), data.size(), hooks),
      ccf::kv::ApplyResult::FAIL);
  }

  SUBCASE("Trailing content after the last map")
  {
    auto data = serialise_snapshot({string_map.get_name()});

    // Append bytes which do not form another map. The header records the
    // entry's size, so it is rewritten to cover them too.
    const std::vector<uint8_t> trailing = {0xAA, 0xBB, 0xCC, 0xDD};
    data.insert(data.end(), trailing.begin(), trailing.end());
    ccf::kv::SerialisedEntryHeader header;
    std::memcpy(&header, data.data(), sizeof(header));
    header.set_size(header.size + trailing.size());
    std::memcpy(data.data(), &header, sizeof(header));

    // The trailing bytes are read as the size prefix of another map's name,
    // and rejected as too short to be one
    ccf::kv::ConsensusHookPtrs hooks;
    REQUIRE_THROWS_WITH_AS(
      target.deserialise_snapshot(data.data(), data.size(), hooks),
      "Expected 8 bytes for fixed-size entry, found only 4",
      std::runtime_error);
  }

  INFO("The failed snapshot left the target unchanged");
  REQUIRE_EQ(target.current_version(), 1);
  {
    auto tx = target.create_read_only_tx();
    REQUIRE_EQ(tx.ro(string_map)->get("public"), "before");
    REQUIRE_EQ(tx.ro(private_map)->get("private"), "before");
  }

  INFO("The target's maps are not left locked");
  {
    auto tx = target.create_tx();
    tx.rw(string_map)->put("public", "after");
    tx.rw(private_map)->put("private", "after");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  INFO("A valid snapshot can still be applied to the target");
  {
    BackendStore source;
    source.set_encryptor(encryptor);
    for (const auto* value : {"first", "second", "third"})
    {
      auto tx = source.create_tx();
      tx.rw(string_map)->put("public", value);
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    std::unique_ptr<ccf::kv::AbstractStore::AbstractSnapshot> snapshot =
      nullptr;
    {
      snapshot = ccf::kv::test::take_snapshot(source, source.current_version());
    }
    const auto serialised_snapshot =
      source.serialise_snapshot(std::move(snapshot));

    ccf::kv::ConsensusHookPtrs hooks;
    REQUIRE_EQ(
      target.deserialise_snapshot(
        serialised_snapshot.data(), serialised_snapshot.size(), hooks),
      ccf::kv::ApplyResult::PASS);
    REQUIRE_EQ(target.current_version(), source.current_version());

    auto tx = target.create_read_only_tx();
    REQUIRE_EQ(tx.ro(string_map)->get("public"), "third");
    REQUIRE_EQ(tx.ro(private_map)->get("private"), "after");
  }
}

TEST_CASE(
  "Apply snapshot to a store which has rolled back" *
  doctest::test_suite("snapshot"))
{
  BackendStore store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  store.set_encryptor(encryptor);

  ccf::kv::Version snapshot_version = ccf::kv::NoVersion;
  {
    auto tx = store.create_tx();
    tx.rw(string_map)->put("foo", "bar");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    snapshot_version = tx.commit_version();
  }

  std::unique_ptr<ccf::kv::AbstractStore::AbstractSnapshot> snapshot = nullptr;
  {
    snapshot = ccf::kv::test::take_snapshot(store, snapshot_version);
  }
  auto serialised_snapshot = store.serialise_snapshot(std::move(snapshot));

  BackendStore new_store;
  new_store.set_encryptor(encryptor);

  INFO("Roll back a transaction on the target store");
  {
    const auto txid_before = new_store.current_txid();

    auto tx = new_store.create_tx();
    tx.rw(num_map)->put(42, 100);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

    new_store.rollback(txid_before, new_store.commit_view());
    REQUIRE(new_store.check_rollback_count(1));
  }

  INFO("Apply snapshot to the rolled back target store");
  {
    ccf::kv::ConsensusHookPtrs hooks;
    REQUIRE_EQ(
      new_store.deserialise_snapshot(
        serialised_snapshot.data(), serialised_snapshot.size(), hooks),
      ccf::kv::ApplyResult::PASS);
    REQUIRE_EQ(new_store.current_version(), snapshot_version);

    auto tx = new_store.create_read_only_tx();
    const auto v = tx.ro(string_map)->get("foo");
    REQUIRE(v.has_value());
    REQUIRE_EQ(v.value(), "bar");
  }
}

TEST_CASE("Dynamic map snapshot serialisation" * doctest::test_suite("dynamic"))
{
  BackendStore store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  store.set_encryptor(encryptor);

  constexpr auto map_name = "string_map";

  ccf::kv::Version snapshot_version;
  INFO("Create maps in original store");
  {
    auto tx1 = store.create_tx();
    auto handle_1 = tx1.rw<MapTypes::StringString>(map_name);
    handle_1->put("foo", "foo");
    REQUIRE(tx1.commit() == ccf::kv::CommitResult::SUCCESS);

    auto tx2 = store.create_tx();
    auto handle_2 = tx2.rw<MapTypes::StringString>(map_name);
    handle_2->put("bar", "bar");
    REQUIRE(tx2.commit() == ccf::kv::CommitResult::SUCCESS);

    snapshot_version = tx2.commit_version();
  }

  INFO("Create snapshot of original store");
  std::unique_ptr<ccf::kv::AbstractStore::AbstractSnapshot> snapshot = nullptr;
  {
    snapshot = ccf::kv::test::take_snapshot(store, snapshot_version);
  }
  auto serialised_snapshot = store.serialise_snapshot(std::move(snapshot));

  INFO("Apply snapshot to create maps in new store");
  {
    ccf::kv::ConsensusHookPtrs hooks;
    BackendStore new_store;
    new_store.set_encryptor(encryptor);
    new_store.deserialise_snapshot(
      serialised_snapshot.data(), serialised_snapshot.size(), hooks);

    auto tx = new_store.create_tx();
    auto handle = tx.rw<MapTypes::StringString>(map_name);

    const auto foo_v = handle->get("foo");
    REQUIRE(foo_v.has_value());
    REQUIRE(foo_v.value() == "foo");

    const auto bar_v = handle->get("bar");
    REQUIRE(bar_v.has_value());
    REQUIRE(bar_v.value() == "bar");
  }
}

TEST_CASE(
  "Commit transaction while applying snapshot" *
  doctest::test_suite("snapshot"))
{
  BackendStore store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  store.set_encryptor(encryptor);

  ccf::kv::Version snapshot_version = ccf::kv::NoVersion;
  INFO("Apply transactions to original store");
  {
    auto tx1 = store.create_tx();
    auto handle_1 = tx1.rw<MapTypes::StringString>("public:string_map");
    handle_1->put("foo", "foo");
    REQUIRE(tx1.commit() == ccf::kv::CommitResult::SUCCESS); // Committed at 1

    auto tx2 = store.create_tx();
    auto handle_2 = tx2.rw<MapTypes::StringString>("public:string_map");
    handle_2->put("bar", "bar");
    REQUIRE(tx2.commit() == ccf::kv::CommitResult::SUCCESS); // Committed at 2
    snapshot_version = tx2.commit_version();
  }

  std::unique_ptr<ccf::kv::AbstractStore::AbstractSnapshot> snapshot = nullptr;
  {
    snapshot = ccf::kv::test::take_snapshot(store, snapshot_version);
  }
  auto serialised_snapshot = store.serialise_snapshot(std::move(snapshot));

  INFO("Apply snapshot while committing a transaction");
  {
    BackendStore new_store;
    new_store.set_encryptor(encryptor);

    auto tx = new_store.create_tx();
    auto handle = tx.rw<MapTypes::StringString>("public:string_map");
    handle->put("in", "flight");
    // tx is not committed until the snapshot is deserialised

    ccf::kv::ConsensusHookPtrs hooks;
    new_store.deserialise_snapshot(
      serialised_snapshot.data(), serialised_snapshot.size(), hooks);

    // Transaction conflicts as snapshot was applied while transaction was in
    // flight
    REQUIRE(tx.commit() == ccf::kv::CommitResult::FAIL_CONFLICT);

    // Try again
    auto tx2 = new_store.create_tx();
    auto handle2 = tx2.rw<MapTypes::StringString>("public:string_map");
    handle2->put("baz", "baz");
    REQUIRE(tx2.commit() == ccf::kv::CommitResult::SUCCESS);
  }
}

TEST_CASE("Commit hooks with snapshot" * doctest::test_suite("snapshot"))
{
  BackendStore store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  store.set_encryptor(encryptor);

  constexpr auto string_map_name = "public:string_map";
  constexpr auto string_value = "public:string_value";
  constexpr auto string_set = "public:string_set";

  ccf::kv::Version snapshot_version = ccf::kv::NoVersion;

  using MapWrite = MapTypes::StringString::Write;
  using ValueWrite = MapTypes::StringValue::Write;
  using SetWrite = MapTypes::StringSet::Write;
  std::vector<MapWrite> local_map_writes;
  std::vector<MapWrite> global_map_writes;
  std::vector<ValueWrite> local_value_writes;
  std::vector<ValueWrite> global_value_writes;
  std::vector<SetWrite> local_set_writes;
  std::vector<SetWrite> global_set_writes;

  auto map_hook =
    [&](ccf::kv::Version v, const MapWrite& w) -> ccf::kv::ConsensusHookPtr {
    local_map_writes.push_back(w);
    return ccf::kv::ConsensusHookPtr(nullptr);
  };
  auto global_map_hook = [&](ccf::kv::Version v, const MapWrite& w) {
    global_map_writes.push_back(w);
  };
  auto value_hook =
    [&](ccf::kv::Version v, const ValueWrite& w) -> ccf::kv::ConsensusHookPtr {
    local_value_writes.push_back(w);
    return ccf::kv::ConsensusHookPtr(nullptr);
  };
  auto global_value_hook = [&](ccf::kv::Version v, const ValueWrite& w) {
    global_value_writes.push_back(w);
  };
  auto set_hook =
    [&](ccf::kv::Version v, const SetWrite& w) -> ccf::kv::ConsensusHookPtr {
    local_set_writes.push_back(w);
    return ccf::kv::ConsensusHookPtr(nullptr);
  };
  auto global_set_hook = [&](ccf::kv::Version v, const SetWrite& w) {
    global_set_writes.push_back(w);
  };

  INFO("Apply transactions to original store");
  {
    {
      auto tx = store.create_tx();
      auto map_handle = tx.rw<MapTypes::StringString>(string_map_name);
      map_handle->put("foo", "foo");
      map_handle->put("bar", "bar");
      auto value_handle = tx.rw<MapTypes::StringValue>(string_value);
      value_handle->put("foo");
      auto set_handle = tx.rw<MapTypes::StringSet>(string_set);
      set_handle->insert("foo");
      set_handle->insert("bar");
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS); // Committed at 1
    }

    {
      // New transaction, deleting some content from the previous transaction
      auto tx = store.create_tx();
      auto map_handle = tx.rw<MapTypes::StringString>(string_map_name);
      map_handle->put("baz", "baz");
      map_handle->remove("bar");
      auto value_handle = tx.rw<MapTypes::StringValue>(string_value);
      value_handle->put("baz");
      auto set_handle = tx.rw<MapTypes::StringSet>(string_set);
      set_handle->insert("baz");
      set_handle->remove("bar");
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS); // Committed at 2
      snapshot_version = tx.commit_version();
    }
  }

  std::unique_ptr<ccf::kv::AbstractStore::AbstractSnapshot> snapshot = nullptr;
  {
    snapshot = ccf::kv::test::take_snapshot(store, snapshot_version);
  }
  auto serialised_snapshot = store.serialise_snapshot(std::move(snapshot));

  BackendStore new_store;
  new_store.set_encryptor(encryptor);

  MapTypes::StringString new_string_map(string_map_name);
  MapTypes::StringValue new_string_value(string_value);
  MapTypes::StringSet new_string_set(string_set);

  INFO("Set hooks on target store");
  {
    new_store.set_map_hook(
      string_map_name, new_string_map.wrap_map_hook(map_hook));
    new_store.set_global_hook(
      string_map_name, new_string_map.wrap_commit_hook(global_map_hook));
    new_store.set_map_hook(
      string_value, new_string_value.wrap_map_hook(value_hook));
    new_store.set_global_hook(
      string_value, new_string_value.wrap_commit_hook(global_value_hook));
    new_store.set_map_hook(string_set, new_string_set.wrap_map_hook(set_hook));
    new_store.set_global_hook(
      string_set, new_string_set.wrap_commit_hook(global_set_hook));
  }

  INFO("Apply snapshot with local hook on target store");
  {
    INFO("Deserialise snapshot");
    {
      ccf::kv::ConsensusHookPtrs hooks;
      new_store.deserialise_snapshot(
        serialised_snapshot.data(), serialised_snapshot.size(), hooks);
    }

    INFO("Verify content of snapshot");
    {
      auto tx = new_store.create_tx();
      auto map_handle = tx.ro<MapTypes::StringString>(string_map_name);
      REQUIRE(map_handle->get("foo").has_value());
      REQUIRE(!map_handle->get("bar").has_value());
      REQUIRE(map_handle->get("baz").has_value());
      auto value_handle = tx.ro<MapTypes::StringValue>(string_value);
      REQUIRE_EQ(value_handle->get().value(), "baz");
      auto set_handle = tx.rw<MapTypes::StringSet>(string_set);
      REQUIRE(set_handle->contains("foo"));
      REQUIRE(!set_handle->contains("bar"));
      REQUIRE(set_handle->contains("baz"));
    }

    INFO("Verify local hook execution");
    {
      {
        REQUIRE_EQ(local_map_writes.size(), 1);
        auto writes = local_map_writes.at(0);
        REQUIRE_EQ(writes.size(), 2);
        REQUIRE_EQ(writes.at("foo"), "foo");
        // Deletions are NOT passed to hook!
        REQUIRE_EQ(writes.find("bar"), writes.end());
        REQUIRE_EQ(writes.at("baz"), "baz");
        local_map_writes.clear();
      }

      {
        REQUIRE_EQ(local_value_writes.size(), 1);
        auto write = local_value_writes.at(0);
        REQUIRE(write.has_value());
        REQUIRE_EQ(write.value(), "baz");
        local_value_writes.clear();
      }

      {
        REQUIRE_EQ(local_set_writes.size(), 1);
        auto writes = local_set_writes.at(0);
        REQUIRE_EQ(writes.size(), 2);
        REQUIRE(writes.at("foo").has_value());
        // Deletions are NOT passed to hook!
        REQUIRE_EQ(writes.find("bar"), writes.end());
        REQUIRE(writes.at("baz").has_value());
        local_set_writes.clear();
      }
    }

    INFO("Verify global hook execution after compact");
    {
      new_store.compact(snapshot_version);

      {
        REQUIRE_EQ(global_map_writes.size(), 1);
        auto writes = global_map_writes.at(0);
        REQUIRE_EQ(writes.size(), 2);
        REQUIRE_EQ(writes.at("foo"), "foo");
        // Deletions are NOT passed to hook!
        REQUIRE_EQ(writes.find("bar"), writes.end());
        REQUIRE_EQ(writes.at("baz"), "baz");
        global_map_writes.clear();
      }

      {
        REQUIRE_EQ(global_value_writes.size(), 1);
        auto write = global_value_writes.at(0);
        REQUIRE(write.has_value());
        REQUIRE_EQ(write.value(), "baz");
        global_value_writes.clear();
      }

      {
        REQUIRE_EQ(global_set_writes.size(), 1);
        auto writes = global_set_writes.at(0);
        REQUIRE_EQ(writes.size(), 2);
        REQUIRE(writes.at("foo").has_value());
        // Deletions are NOT passed to hook!
        REQUIRE_EQ(writes.find("bar"), writes.end());
        REQUIRE(writes.at("baz").has_value());
        global_set_writes.clear();
      }
    }
  }

  INFO(
    "Remove all elements in source store and deserialise resulting snapshot");
  {
    auto tx = store.create_tx();
    auto map_handle = tx.rw<MapTypes::StringString>(string_map_name);
    map_handle->clear();
    auto value_handle = tx.rw<MapTypes::StringValue>(string_value);
    value_handle->clear();
    auto set_handle = tx.rw<MapTypes::StringSet>(string_set);
    set_handle->clear();
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    snapshot_version = tx.commit_version();
    {
      snapshot = ccf::kv::test::take_snapshot(store, snapshot_version);
    }
    serialised_snapshot = store.serialise_snapshot(std::move(snapshot));

    ccf::kv::ConsensusHookPtrs hooks;
    new_store.deserialise_snapshot(
      serialised_snapshot.data(), serialised_snapshot.size(), hooks);

    INFO("Verify content of snapshot");
    {
      auto verify_tx = new_store.create_tx();
      auto verify_map_handle =
        verify_tx.ro<MapTypes::StringString>(string_map_name);
      REQUIRE(!verify_map_handle->get("foo").has_value());
      REQUIRE(!verify_map_handle->get("bar").has_value());
      REQUIRE(!verify_map_handle->get("baz").has_value());
      auto verify_value_handle =
        verify_tx.ro<MapTypes::StringValue>(string_value);
      REQUIRE(!verify_value_handle->get().has_value());
      auto verify_set_handle = verify_tx.rw<MapTypes::StringSet>(string_set);
      REQUIRE(!verify_set_handle->contains("foo"));
      REQUIRE(!verify_set_handle->contains("bar"));
      REQUIRE(!verify_set_handle->contains("baz"));
    }

    INFO("Verify local hook execution");
    {
      {
        REQUIRE_EQ(local_map_writes.size(), 0);
        local_map_writes.clear();
      }

      {
        REQUIRE_EQ(local_value_writes.size(), 0);
        local_value_writes.clear();
      }

      {
        REQUIRE_EQ(local_set_writes.size(), 0);
        local_set_writes.clear();
      }
    }

    INFO("Verify global hook execution after compact");
    {
      new_store.compact(snapshot_version);

      {
        REQUIRE_EQ(global_map_writes.size(), 0);
        global_map_writes.clear();
      }

      {
        REQUIRE_EQ(global_value_writes.size(), 0);
        global_value_writes.clear();
      }

      {
        REQUIRE_EQ(global_set_writes.size(), 0);
        global_set_writes.clear();
      }
    }
  }
}

TEST_CASE(
  "Installing a snapshot sets the committable gap" *
  doctest::test_suite("snapshot"))
{
  BackendStore store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  store.set_encryptor(encryptor);

  constexpr size_t tx_count = 5;
  for (size_t i = 0; i < tx_count; ++i)
  {
    auto tx = store.create_tx();
    tx.rw(num_map)->put(i, i);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  // Snapshots are only generated at signature seqnos, so the version a
  // snapshot is installed at is always committable
  const auto snapshot_version = store.current_version();
  REQUIRE(snapshot_version == tx_count);

  std::unique_ptr<ccf::kv::AbstractStore::AbstractSnapshot> snapshot = nullptr;
  {
    snapshot = ccf::kv::test::take_snapshot(store, snapshot_version);
  }
  auto serialised_snapshot = store.serialise_snapshot(std::move(snapshot));

  BackendStore new_store;
  new_store.set_encryptor(encryptor);
  REQUIRE(new_store.committable_gap() == 0);

  INFO("A store which has just installed a snapshot has no committable gap");
  {
    ccf::kv::ConsensusHookPtrs hooks;
    REQUIRE_EQ(
      new_store.deserialise_snapshot(
        serialised_snapshot.data(), serialised_snapshot.size(), hooks),
      ccf::kv::ApplyResult::PASS);
    REQUIRE_EQ(new_store.current_version(), snapshot_version);
    REQUIRE_EQ(new_store.committable_gap(), 0);
  }

  INFO("Transactions committed after the snapshot are counted from it");
  for (size_t i = 1; i <= 3; ++i)
  {
    auto tx = new_store.create_tx();
    tx.rw(num_map)->put(snapshot_version + i, i);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    REQUIRE_EQ(new_store.current_version(), snapshot_version + i);
    REQUIRE_EQ(new_store.committable_gap(), i);
  }
}

static std::vector<uint8_t> serialise_current_snapshot(BackendStore& store)
{
  std::unique_ptr<ccf::kv::AbstractStore::AbstractSnapshot> snapshot;
  {
    snapshot = ccf::kv::test::take_snapshot(store, store.current_version());
  }
  return store.serialise_snapshot(std::move(snapshot));
}

static void commit_writes(BackendStore& store, const auto& write)
{
  auto tx = store.create_tx();
  write(tx);
  REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
}

static BackendStore::SnapshotPublicMaps capture_public_maps(
  const std::shared_ptr<ccf::kv::AbstractTxEncryptor>& encryptor,
  const std::vector<uint8_t>& entry)
{
  BackendStore public_store;
  public_store.set_encryptor(encryptor);
  ccf::kv::ConsensusHookPtrs hooks;
  std::optional<BackendStore::SnapshotPublicMaps> captured;
  REQUIRE(
    public_store.deserialise_public_snapshot_capturing(
      entry.data(), entry.size(), hooks, nullptr, captured) ==
    ccf::kv::ApplyResult::PASS);
  REQUIRE(captured.has_value());
  return std::move(captured.value());
}

TEST_CASE(
  "Snapshot decrypted in place with the ledger secret for its version" *
  doctest::test_suite("snapshot"))
{
  const auto first_secret = ccf::make_ledger_secret();
  const auto second_secret = ccf::make_ledger_secret();
  auto secrets = std::make_shared<ccf::LedgerSecrets>();
  secrets->init_from_map({{1, first_secret}});
  auto encryptor = std::make_shared<ccf::NodeEncryptor>(secrets);
  BackendStore store;
  store.set_encryptor(encryptor);
  ccf::kv::ConsensusHookPtrs hooks;

  MapTypes::StringString private_map("private_map");
  commit_writes(store, [&](auto& tx) {
    tx.rw(string_map)->put("public", "snapshotted");
    tx.rw(private_map)->put("private", "snapshotted");
  });
  const auto version = store.current_version();
  std::unique_ptr<ccf::kv::AbstractStore::AbstractSnapshot> snapshot;
  {
    snapshot = ccf::kv::test::take_snapshot(store, version);
  }

  // The service is rekeyed, and encrypts a later transaction with the new
  // ledger secret, before the snapshot is serialised
  secrets->set_secret(version + 1, ccf::LedgerSecretPtr(second_secret));
  commit_writes(
    store, [&](auto& tx) { tx.rw(private_map)->put("private", "later"); });
  const auto entry = store.serialise_snapshot(std::move(snapshot));

  INFO("A node with both ledger secrets uses the one for the snapshot");
  {
    auto node_secrets = std::make_shared<ccf::LedgerSecrets>();
    node_secrets->init_from_map(
      {{1, first_secret}, {version + 1, second_secret}});
    auto node_encryptor = std::make_shared<ccf::NodeEncryptor>(node_secrets);
    const auto captured = capture_public_maps(node_encryptor, entry);

    for (const auto* public_maps :
         {static_cast<const BackendStore::SnapshotPublicMaps*>(nullptr),
          &captured})
    {
      auto buffer = entry;
      BackendStore node_store;
      node_store.set_encryptor(node_encryptor);
      REQUIRE(
        node_store.deserialise_snapshot_in_place(
          buffer, hooks, nullptr, public_maps) == ccf::kv::ApplyResult::PASS);
      auto tx = node_store.create_read_only_tx();
      REQUIRE(tx.ro(string_map)->get("public") == "snapshotted");
      REQUIRE(tx.ro(private_map)->get("private") == "snapshotted");
    }
  }

  INFO("A node without that ledger secret leaves the snapshot untouched");
  {
    auto node_secrets = std::make_shared<ccf::LedgerSecrets>();
    node_secrets->init_from_map({{version + 1, second_secret}});
    BackendStore node_store;
    node_store.set_encryptor(
      std::make_shared<ccf::NodeEncryptor>(node_secrets));
    auto buffer = entry;
    REQUIRE(
      node_store.deserialise_snapshot_in_place(buffer, hooks) ==
      ccf::kv::ApplyResult::FAIL);
    REQUIRE(buffer == entry);
  }
}

TEST_CASE(
  "Captured public maps are bound to the snapshot and map versions" *
  doctest::test_suite("snapshot"))
{
  auto secrets = std::make_shared<ccf::LedgerSecrets>();
  secrets->init();
  auto encryptor = std::make_shared<ccf::NodeEncryptor>(secrets);
  ccf::kv::ConsensusHookPtrs hooks;
  MapTypes::StringString private_map("private_map");

  auto deserialise_reusing =
    [&](
      const std::vector<uint8_t>& entry,
      const BackendStore::SnapshotPublicMaps& captured) {
      auto buffer = entry;
      BackendStore store;
      store.set_encryptor(encryptor);
      return store.deserialise_snapshot_in_place(
        buffer, hooks, nullptr, &captured);
    };

  BackendStore store;
  store.set_encryptor(encryptor);
  commit_writes(store, [&](auto& tx) {
    tx.rw(string_map)->put("public", "value");
    tx.rw(private_map)->put("private", "secret");
  });
  const auto first = serialise_current_snapshot(store);
  commit_writes(
    store, [&](auto& tx) { tx.rw(private_map)->put("private", "later"); });
  const auto second = serialise_current_snapshot(store);
  REQUIRE(
    deserialise_reusing(first, capture_public_maps(encryptor, first)) ==
    ccf::kv::ApplyResult::PASS);
  REQUIRE(
    deserialise_reusing(second, capture_public_maps(encryptor, second)) ==
    ccf::kv::ApplyResult::PASS);

  INFO("A later snapshot, with the same public maps, is rejected");
  REQUIRE(
    deserialise_reusing(second, capture_public_maps(encryptor, first)) ==
    ccf::kv::ApplyResult::FAIL);

  INFO("Or one with the same public state, written at another version");
  BackendStore other_store;
  other_store.set_encryptor(encryptor);
  commit_writes(other_store, [&](auto& tx) {
    tx.rw(string_map)->put("public", "value");
    tx.rw(string_map)->put("removed", "value");
    tx.rw(private_map)->put("private", "secret");
  });
  commit_writes(other_store, [&](auto& tx) {
    tx.rw(string_map)->remove("removed");
    tx.rw(private_map)->put("private", "later");
  });
  const auto rewritten = serialise_current_snapshot(other_store);
  REQUIRE(
    deserialise_reusing(rewritten, capture_public_maps(encryptor, rewritten)) ==
    ccf::kv::ApplyResult::PASS);
  REQUIRE(
    deserialise_reusing(rewritten, capture_public_maps(encryptor, second)) ==
    ccf::kv::ApplyResult::FAIL);
}

TEST_CASE(
  "Snapshot with an empty private domain deserialised in place" *
  doctest::test_suite("snapshot"))
{
  auto secrets = std::make_shared<ccf::LedgerSecrets>();
  secrets->init();
  auto encryptor = std::make_shared<ccf::NodeEncryptor>(secrets);
  ccf::kv::ConsensusHookPtrs hooks;

  BackendStore store;
  store.set_encryptor(encryptor);
  commit_writes(store, [&](auto& tx) {
    tx.rw(string_map)->put("public", "value");
    tx.rw(num_map)->put(1, 2);
  });
  const auto entry = serialise_current_snapshot(store);
  const auto captured = capture_public_maps(encryptor, entry);

  for (const auto* public_maps :
       {static_cast<const BackendStore::SnapshotPublicMaps*>(nullptr),
        &captured})
  {
    auto buffer = entry;
    BackendStore recovery_store;
    recovery_store.set_encryptor(encryptor);
    REQUIRE(
      recovery_store.deserialise_snapshot_in_place(
        buffer, hooks, nullptr, public_maps) == ccf::kv::ApplyResult::PASS);
    auto tx = recovery_store.create_read_only_tx();
    REQUIRE(tx.ro(string_map)->get("public") == "value");
    REQUIRE(tx.ro(num_map)->get(1) == 2);
  }

  // The empty private domain's tag still authenticates the public domain
  auto tampered = entry;
  tampered
    [ccf::kv::RawKvStoreSerialiser::public_domain_offset(encryptor) + 20] ^= 1;
  BackendStore recovery_store;
  recovery_store.set_encryptor(encryptor);
  REQUIRE(
    recovery_store.deserialise_snapshot_in_place(tampered, hooks) ==
    ccf::kv::ApplyResult::FAIL);
}

// Implements only AbstractTxEncryptor's pure virtual members, so that its
// default span decrypt() and decrypt_in_place() are used
class VectorOnlyTxEncryptor : public ccf::kv::AbstractTxEncryptor
{
private:
  std::shared_ptr<ccf::kv::AbstractTxEncryptor> inner;

public:
  explicit VectorOnlyTxEncryptor(
    std::shared_ptr<ccf::kv::AbstractTxEncryptor> inner_) :
    inner(std::move(inner_))
  {}

  bool encrypt(
    const std::vector<uint8_t>& plain,
    const std::vector<uint8_t>& additional_data,
    std::vector<uint8_t>& serialised_header,
    std::vector<uint8_t>& cipher,
    const ccf::TxID& tx_id,
    ccf::kv::EntryType entry_type = ccf::kv::EntryType::WriteSet,
    bool historical_hint = false) override
  {
    return inner->encrypt(
      plain,
      additional_data,
      serialised_header,
      cipher,
      tx_id,
      entry_type,
      historical_hint);
  }

  bool decrypt(
    const std::vector<uint8_t>& cipher,
    const std::vector<uint8_t>& additional_data,
    const std::vector<uint8_t>& serialised_header,
    std::vector<uint8_t>& plain,
    ccf::kv::Version version,
    ccf::kv::Term& term,
    bool historical_hint = false) override
  {
    return inner->decrypt(
      cipher,
      additional_data,
      serialised_header,
      plain,
      version,
      term,
      historical_hint);
  }

  void rollback(ccf::kv::Version version) override
  {
    inner->rollback(version);
  }

  size_t get_header_length() override
  {
    return inner->get_header_length();
  }

  uint64_t get_term(const uint8_t* data, size_t size) override
  {
    return inner->get_term(data, size);
  }

  ccf::crypto::HashBytes get_commit_nonce(
    const ccf::TxID& tx_id, bool historical_hint = false) override
  {
    return inner->get_commit_nonce(tx_id, historical_hint);
  }
};

TEST_CASE(
  "Snapshot decrypted in place by the default implementation" *
  doctest::test_suite("snapshot"))
{
  auto secrets = std::make_shared<ccf::LedgerSecrets>();
  secrets->init();
  auto encryptor = std::make_shared<ccf::NodeEncryptor>(secrets);
  auto default_encryptor = std::make_shared<VectorOnlyTxEncryptor>(encryptor);
  ccf::kv::ConsensusHookPtrs hooks;
  MapTypes::StringString private_map("private_map");

  BackendStore store;
  store.set_encryptor(encryptor);
  commit_writes(store, [&](auto& tx) {
    tx.rw(string_map)->put("public", "value");
    tx.rw(private_map)->put("private", "secret");
  });
  const auto entry = serialise_current_snapshot(store);

  auto buffer = entry;
  BackendStore recovery_store;
  recovery_store.set_encryptor(default_encryptor);
  REQUIRE(
    recovery_store.deserialise_snapshot_in_place(buffer, hooks) ==
    ccf::kv::ApplyResult::PASS);
  auto tx = recovery_store.create_read_only_tx();
  REQUIRE(tx.ro(string_map)->get("public") == "value");
  REQUIRE(tx.ro(private_map)->get("private") == "secret");

  // If decryption fails, the snapshot is left untouched
  auto tampered = entry;
  tampered.back() ^= 1;
  buffer = tampered;
  BackendStore other_store;
  other_store.set_encryptor(default_encryptor);
  REQUIRE(
    other_store.deserialise_snapshot_in_place(buffer, hooks) ==
    ccf::kv::ApplyResult::FAIL);
  REQUIRE(buffer == tampered);
}

TEST_CASE(
  "Snapshot deserialised in place, reusing captured public maps" *
  doctest::test_suite("snapshot"))
{
  auto secrets = std::make_shared<ccf::LedgerSecrets>();
  secrets->init();
  auto encryptor = std::make_shared<ccf::NodeEncryptor>(secrets);
  ccf::kv::ConsensusHookPtrs hooks;

  MapTypes::StringString private_map("private_map");
  MapTypes::StringString other_public_map("public:other_map");

  // Each snapshot is of a single transaction, so all are at the same version
  const auto version = ccf::kv::Version{1};
  auto snapshot_of = [&](const auto& write) {
    BackendStore store;
    store.set_encryptor(encryptor);
    auto tx = store.create_tx();
    write(tx);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    std::unique_ptr<ccf::kv::AbstractStore::AbstractSnapshot> snapshot;
    {
      snapshot = ccf::kv::test::take_snapshot(store, store.current_version());
    }
    return store.serialise_snapshot(std::move(snapshot));
  };

  auto capture = [&](const std::vector<uint8_t>& entry) {
    BackendStore public_store;
    public_store.set_encryptor(encryptor);
    std::optional<BackendStore::SnapshotPublicMaps> captured;
    REQUIRE(
      public_store.deserialise_public_snapshot_capturing(
        entry.data(), entry.size(), hooks, nullptr, captured) ==
      ccf::kv::ApplyResult::PASS);
    REQUIRE(captured.has_value());
    // Rejections below are then due to contents, not versions
    REQUIRE(public_store.current_version() == version);
    return std::move(captured.value());
  };

  auto deserialise_reusing =
    [&](
      const std::vector<uint8_t>& entry,
      const BackendStore::SnapshotPublicMaps* captured) {
      auto buffer = entry;
      BackendStore store;
      store.set_encryptor(encryptor);
      return store.deserialise_snapshot_in_place(
        buffer, hooks, nullptr, captured);
    };

  const auto entry = snapshot_of([&](auto& tx) {
    tx.rw(string_map)->put("public", "value");
    tx.rw(num_map)->put(1, 2);
    tx.rw(private_map)->put("private", "secret");
  });

  // As during recovery: public domain first, before ledger secrets are known
  BackendStore public_store;
  public_store.set_encryptor(encryptor);
  std::optional<BackendStore::SnapshotPublicMaps> captured;
  REQUIRE(
    public_store.deserialise_public_snapshot_capturing(
      entry.data(), entry.size(), hooks, nullptr, captured) ==
    ccf::kv::ApplyResult::PASS);
  REQUIRE(captured.has_value());
  REQUIRE(public_store.current_version() == version);

  // Later writes to the public store are not visible through captured states
  {
    auto tx = public_store.create_tx();
    tx.rw(string_map)->put("public", "changed");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  INFO("Private domain decrypted in place, captured public maps installed");
  {
    auto buffer = entry;
    BackendStore recovery_store;
    recovery_store.set_encryptor(encryptor);
    REQUIRE(
      recovery_store.deserialise_snapshot_in_place(
        buffer, hooks, nullptr, &captured.value()) ==
      ccf::kv::ApplyResult::PASS);
    REQUIRE(recovery_store.current_version() == version);
    REQUIRE(buffer != entry);

    auto tx = recovery_store.create_read_only_tx();
    REQUIRE(tx.ro(string_map)->get("public") == "value");
    REQUIRE(tx.ro(num_map)->get(1) == 2);
    REQUIRE(tx.ro(private_map)->get("private") == "secret");
  }

  INFO("Without captured public maps, both domains are deserialised");
  REQUIRE(deserialise_reusing(entry, nullptr) == ccf::kv::ApplyResult::PASS);

  INFO("Public maps captured from a different snapshot are rejected");
  {
    const auto different = capture(snapshot_of([&](auto& tx) {
      tx.rw(string_map)->put("public", "other value");
      tx.rw(num_map)->put(1, 2);
      tx.rw(private_map)->put("private", "secret");
    }));
    REQUIRE(
      deserialise_reusing(entry, &different) == ccf::kv::ApplyResult::FAIL);

    const auto missing = capture(snapshot_of([&](auto& tx) {
      tx.rw(string_map)->put("public", "value");
      tx.rw(private_map)->put("private", "secret");
    }));
    REQUIRE(deserialise_reusing(entry, &missing) == ccf::kv::ApplyResult::FAIL);

    const auto extra = capture(snapshot_of([&](auto& tx) {
      tx.rw(string_map)->put("public", "value");
      tx.rw(num_map)->put(1, 2);
      tx.rw(other_public_map)->put("other", "value");
      tx.rw(private_map)->put("private", "secret");
    }));
    REQUIRE(deserialise_reusing(entry, &extra) == ccf::kv::ApplyResult::FAIL);
  }

  INFO("Tampering with either domain is detected");
  {
    auto public_tampered = entry;
    const auto offset =
      ccf::kv::RawKvStoreSerialiser::public_domain_offset(encryptor);
    public_tampered[offset + 20] ^= 1;
    REQUIRE(
      deserialise_reusing(public_tampered, &captured.value()) ==
      ccf::kv::ApplyResult::FAIL);

    auto private_tampered = entry;
    private_tampered.back() ^= 1;
    REQUIRE(
      deserialise_reusing(private_tampered, nullptr) ==
      ccf::kv::ApplyResult::FAIL);
  }

  INFO("A private domain which fails to decrypt is not left as plaintext");
  {
    auto buffer = entry;
    buffer.back() ^= 1;
    BackendStore store;
    store.set_encryptor(encryptor);
    REQUIRE(
      store.deserialise_snapshot_in_place(buffer, hooks) ==
      ccf::kv::ApplyResult::FAIL);
    const std::string_view private_map_name = "private_map";
    REQUIRE(
      std::search(
        buffer.begin(),
        buffer.end(),
        private_map_name.begin(),
        private_map_name.end()) == buffer.end());
  }
}
