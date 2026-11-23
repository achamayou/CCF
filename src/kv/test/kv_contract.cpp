// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf/kv/map.h"
#include "ccf/kv/set.h"
#include "ccf/kv/unit_value.h"
#include "ccf/kv/value.h"
#include "ds/internal_logger.h"
#include "kv/compacted_version_conflict.h"
#include "kv/test/kv_test_store.h"

#include <doctest/doctest.h>
#include <map>
#include <random>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace
{
  using TestStore = ccf::kv::test::TestStore;

  struct MapTypes
  {
    using StringString = ccf::kv::Map<std::string, std::string>;
    using NumNum = ccf::kv::Map<size_t, size_t>;
    using NumString = ccf::kv::Map<size_t, std::string>;
    using StringNum = ccf::kv::Map<std::string, size_t>;
    using UntypedMap = ccf::kv::untyped::Map;
  };
}

TEST_CASE("Zero-revision whole-map dependencies")
{
  using Result = ccf::kv::CommitResult;
  for (const std::string_view observation :
       {"foreach", "range", "size", "clear"})
  {
    INFO("Map-wide observation: ", observation);
    TestStore store;
    MapTypes::StringString empty("public:empty");
    MapTypes::StringString other("public:other");
    {
      auto tx = store.create_tx();
      // Register an empty map without advancing its initial revision.
      tx.rw(empty)->remove("missing");
      REQUIRE(tx.commit() == Result::SUCCESS);
      REQUIRE(tx.commit_version() == 1);
    }

    auto pending = store.create_tx();
    if (observation == "foreach")
    {
      auto* handle = pending.rw(empty);
      handle->put("own", "pending");
      size_t visited = 0;
      handle->foreach([&](const auto&, const auto&) {
        ++visited;
        return true;
      });
      REQUIRE(visited == 1);
    }
    else if (observation == "range")
    {
      auto* handle = pending.rw<MapTypes::UntypedMap>("public:empty");
      handle->put(
        ccf::kv::serialisers::JsonSerialiser<std::string>::to_serialised("own"),
        ccf::kv::serialisers::JsonSerialiser<std::string>::to_serialised(
          "pending"));
      size_t visited = 0;
      pending.rw<MapTypes::UntypedMap>(empty.get_name())
        ->range(
          [&](const auto&, const auto&) { ++visited; },
          std::nullopt,
          std::nullopt);
      REQUIRE(visited == 1);
    }
    else if (observation == "size")
    {
      auto* handle = pending.rw(empty);
      REQUIRE(handle->size() == 0);
    }
    else
    {
      auto* handle = pending.rw(empty);
      handle->clear();
    }
    pending.rw(other)->put("must_not_apply", "pending");
    {
      auto tx = store.create_tx();
      tx.rw(empty)->put("concurrent", "committed");
      REQUIRE(tx.commit() == Result::SUCCESS);
    }
    CHECK(pending.commit() == Result::FAIL_CONFLICT);
    auto check = store.create_tx();
    CHECK_FALSE(check.ro(other)->has("must_not_apply"));
    CHECK_FALSE(check.ro(empty)->has("own"));
    REQUIRE(check.ro(empty)->get("concurrent") == "committed");
  }
}

TEST_CASE("Zero-revision whole-map non-conflicts")
{
  using Result = ccf::kv::CommitResult;
  TestStore store;
  MapTypes::StringString empty("public:empty");
  MapTypes::StringString other("public:other");
  {
    auto tx = store.create_tx();
    tx.rw(empty)->remove("missing");
    REQUIRE(tx.commit() == Result::SUCCESS);
  }
  {
    auto tx = store.create_tx();
    REQUIRE(tx.ro(empty)->size() == 0);
    tx.rw(other)->put("unchanged", "accepted");
    REQUIRE(tx.commit() == Result::SUCCESS);
  }
  {
    auto reader = store.create_tx();
    REQUIRE(reader.ro(empty)->size() == 0);
    auto writer = store.create_tx();
    writer.wo(empty)->put("key", "value");
    auto blind = store.create_tx();
    blind.wo(empty)->put("blind", "value");
    REQUIRE(writer.commit() == Result::SUCCESS);
    REQUIRE(reader.commit() == Result::SUCCESS);
    REQUIRE(reader.commit_version() == ccf::kv::NoVersion);
    REQUIRE(blind.commit() == Result::SUCCESS);
  }
  auto check = store.create_tx();
  REQUIRE(check.ro(other)->get("unchanged") == "accepted");
  REQUIRE(check.ro(empty)->get("key") == "value");
  REQUIRE(check.ro(empty)->get("blind") == "value");
}

TEST_CASE("Reads/writes and deletions")
{
  TestStore kv_store;

  MapTypes::StringString map("public:map");

  constexpr auto k = "key";
  constexpr auto invalid_key = "invalid_key";
  constexpr auto v1 = "value1";

  INFO("Start empty transaction");
  {
    auto tx = kv_store.create_tx();
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    REQUIRE_THROWS_AS(tx.commit(), std::logic_error);
  }

  INFO("Read own writes");
  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    REQUIRE(!handle->has(k));
    auto v = handle->get(k);
    REQUIRE(!v.has_value());
    REQUIRE(!handle->get_version_of_previous_write(k).has_value());
    handle->put(k, v1);
    REQUIRE(handle->has(k));
    auto va = handle->get(k);
    REQUIRE(va.has_value());
    REQUIRE(va.value() == v1);
    REQUIRE(!handle->get_version_of_previous_write(k).has_value());
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  const auto commit_v = kv_store.current_version();

  INFO("Read previous writes");
  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    REQUIRE(handle->has(k));
    auto v = handle->get(k);
    REQUIRE(v.has_value());
    REQUIRE(v.value() == v1);
    const auto ver = handle->get_version_of_previous_write(k);
    REQUIRE(ver.has_value());
    REQUIRE(ver.value() == commit_v);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  INFO("Remove keys");
  {
    {
      auto tx = kv_store.create_tx();
      auto handle = tx.rw(map);
      handle->put(k, v1);

      REQUIRE(!handle->has(invalid_key));
      handle->remove(invalid_key);
      REQUIRE(!handle->get_version_of_previous_write(invalid_key).has_value());
      REQUIRE(handle->get_version_of_previous_write(k).has_value());
      REQUIRE(handle->get_version_of_previous_write(k).value() == commit_v);
      handle->remove(k);
      REQUIRE(handle->get_version_of_previous_write(k).has_value());
      REQUIRE(handle->get_version_of_previous_write(k).value() == commit_v);
      REQUIRE(!handle->has(k));
      auto va = handle->get(k);
      REQUIRE(!va.has_value());

      handle->put(k, v1);
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    {
      auto tx2 = kv_store.create_tx();
      auto handle2 = tx2.rw(map);
      REQUIRE(handle2->has(k));
      handle2->remove(k);
    }
  }

  INFO("Remove key that was deleted from state");
  {
    {
      auto tx = kv_store.create_tx();
      auto handle = tx.rw(map);
      handle->put(k, v1);
      auto va = handle->get_globally_committed(k);
      REQUIRE(!va.has_value());
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    {
      auto tx2 = kv_store.create_tx();
      auto handle2 = tx2.rw(map);
      REQUIRE(handle2->has(k));
      handle2->remove(k);
      REQUIRE(!handle2->has(k));
      REQUIRE(tx2.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    {
      auto tx3 = kv_store.create_tx();
      auto handle3 = tx3.rw(map);
      REQUIRE(!handle3->has(k));
      auto vc = handle3->get(k);
      REQUIRE(!vc.has_value());
    }
  }
}

TEST_CASE("multiple handles")
{
  TestStore kv_store;

  MapTypes::NumString map("public:map");

  constexpr auto k = 42;
  constexpr auto v1 = "hello";
  constexpr auto v2 = "saluton";

  auto tx = kv_store.create_tx();

  auto h1 = tx.ro(map);
  auto h2 = tx.rw(map);
  auto h3 = tx.wo(map);

  REQUIRE(!h1->has(k));
  REQUIRE(!h2->has(k));

  h2->put(k, v1);

  REQUIRE(h1->has(k));
  REQUIRE(*h1->get(k) == v1);
  REQUIRE(h2->has(k));
  REQUIRE(*h2->get(k) == v1);

  h3->put(k, v2);

  REQUIRE(h1->has(k));
  REQUIRE(*h1->get(k) == v2);
  REQUIRE(h2->has(k));
  REQUIRE(*h2->get(k) == v2);
}

TEST_CASE("clear")
{
  TestStore kv_store;
  MapTypes::StringString map("public:map");

  const auto k1 = "k1";
  const auto k2 = "k2";

  const auto v = "v";

  {
    INFO("Setting committed state");
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    handle->put(k1, v);

    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  SUBCASE("Basic")
  {
    {
      INFO("Clear removes all entries");
      auto tx = kv_store.create_tx();
      auto handle = tx.rw(map);
      handle->put(k2, v);

      REQUIRE(handle->has(k1));
      REQUIRE(handle->has(k2));

      handle->clear();

      REQUIRE(!handle->has(k1));
      REQUIRE(!handle->has(k2));

      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    {
      INFO("Clear is committed");
      auto tx = kv_store.create_tx();
      auto handle = tx.rw(map);

      REQUIRE(!handle->has(k1));
      REQUIRE(!handle->has(k2));
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }
  }

  SUBCASE("Clear conflicts correctly")
  {
    auto tx1 = kv_store.create_tx();
    auto handle1 = tx1.rw(map);
    handle1->clear();

    INFO("Another transaction creates a key and commits");
    auto tx2 = kv_store.create_tx();
    auto handle2 = tx2.rw(map);
    handle2->put(k2, v);
    REQUIRE(tx2.commit() == ccf::kv::CommitResult::SUCCESS);

    INFO("clear() conflicts and must be retried");
    REQUIRE(tx1.commit() == ccf::kv::CommitResult::FAIL_CONFLICT);
  }
}

TEST_CASE("get_version_of_previous_write")
{
  TestStore kv_store;
  MapTypes::StringString map("public:map");

  const auto k1 = "k1";
  const auto k2 = "k2";
  const auto k3 = "k3";

  const auto v1 = "v1";
  const auto v2 = "v2";
  const auto v3 = "v3";

  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    handle->put(k1, v1);
    handle->put(k2, v1);

    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    handle->put(k1, v2);
    handle->remove(k2);

    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  const auto second_version = kv_store.current_version();

  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);

    {
      auto tx_other = kv_store.create_tx();
      auto handle_other = tx_other.rw(map);
      handle_other->put(k2, v3);
      tx_other.commit();
    }

    {
      // We don't see effects of tx_other because we started executing earlier.
      // k1 is at second_version
      const auto ver1 = handle->get_version_of_previous_write(k1);
      REQUIRE(ver1.has_value());
      REQUIRE(ver1.value() == second_version);

      // k2 was removed, so has no version...
      REQUIRE(!handle->get_version_of_previous_write(k2).has_value());

      // ...just like k3 which was never written
      REQUIRE(!handle->get_version_of_previous_write(k3).has_value());

      {
        INFO("Reading from these keys doesn't change this");
        handle->has(k1);
        handle->has(k2);
        handle->has(k3);

        REQUIRE(
          handle->get_version_of_previous_write(k1).value() == second_version);
        REQUIRE(!handle->get_version_of_previous_write(k2).has_value());
        REQUIRE(!handle->get_version_of_previous_write(k3).has_value());

        handle->get(k1);
        handle->get(k2);
        handle->get(k3);

        REQUIRE(
          handle->get_version_of_previous_write(k1).value() == second_version);
        REQUIRE(!handle->get_version_of_previous_write(k2).has_value());
        REQUIRE(!handle->get_version_of_previous_write(k3).has_value());
      }

      SUBCASE("Writing to these keys doesn't change this")
      {
        handle->put(k1, v3);
        handle->put(k2, v3);
        handle->put(k3, v3);

        REQUIRE(
          handle->get_version_of_previous_write(k1).value() == second_version);
        REQUIRE(!handle->get_version_of_previous_write(k2).has_value());
        REQUIRE(!handle->get_version_of_previous_write(k3).has_value());

        handle->remove(k1);
        handle->remove(k2);
        handle->remove(k3);

        REQUIRE(
          handle->get_version_of_previous_write(k1).value() == second_version);
        REQUIRE(!handle->get_version_of_previous_write(k2).has_value());
        REQUIRE(!handle->get_version_of_previous_write(k3).has_value());
      }

      // This conflicts with tx_other so is not committed
      REQUIRE(tx.commit() == ccf::kv::CommitResult::FAIL_CONFLICT);
    }
  }

  const auto third_version = kv_store.current_version();

  {
    INFO("Version is per-key");
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);

    const auto ver1 = handle->get_version_of_previous_write(k1);
    const auto ver2 = handle->get_version_of_previous_write(k2);

    REQUIRE(ver1.has_value());
    REQUIRE(ver2.has_value());

    REQUIRE(ver1.value() == second_version);
    REQUIRE(ver2.value() == third_version);
  }
}

TEST_CASE("size")
{
  TestStore kv_store;
  MapTypes::StringString map("public:map");

  const auto k1 = "k1";
  const auto k2 = "k2";
  const auto k3 = "k3";

  const auto v = "v";
  const auto vv = "vv";

  {
    INFO("Only local modifications");
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);

    REQUIRE(handle->size() == 0);
    handle->put(k1, v);
    REQUIRE(handle->size() == 1);
    handle->remove(k2);
    REQUIRE(handle->size() == 1);
    handle->remove(k1);
    REQUIRE(handle->size() == 0);
    handle->put(k2, v);
    REQUIRE(handle->size() == 1);
    handle->put(k2, vv);
    REQUIRE(handle->size() == 1);
    handle->put(k1, v);
    REQUIRE(handle->size() == 2);

    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  {
    INFO("Combined with committed state");
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);

    REQUIRE(handle->size() == 2);
    handle->put(k2, v);
    REQUIRE(handle->size() == 2);
    handle->put(k3, v);
    REQUIRE(handle->size() == 3);
    handle->remove(k1);
    REQUIRE(handle->size() == 2);
    handle->remove(k2);
    REQUIRE(handle->size() == 1);
    handle->remove(k3);
    REQUIRE(handle->size() == 0);

    {
      INFO("size() is only affected by current transaction");
      auto tx2 = kv_store.create_tx();
      auto handle2 = tx2.rw(map);

      REQUIRE(handle2->size() == 2);
      handle2->remove(k2);
      REQUIRE(handle2->size() == 1);
    }

    REQUIRE(handle->size() == 0);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  {
    INFO("Sanity check");
    for (size_t i = 0; i < 20; ++i)
    {
      auto tx = kv_store.create_tx();
      auto handle = tx.rw(map);
      for (size_t j = 0; j < 1'000; ++j)
      {
        const auto key = std::to_string(rand() % 10'000);
        if (rand() % 4 == 0)
        {
          handle->remove(key);
        }
        else
        {
          handle->put(key, v);
        }
      }

      const auto claimed_size = handle->size();
      size_t manual_size = 0;
      handle->foreach([&manual_size](const auto&, const auto&) {
        ++manual_size;
        return true;
      });

      REQUIRE(claimed_size == manual_size);
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }
  }
}

TEST_CASE("foreach")
{
  TestStore kv_store;
  MapTypes::StringString map("public:map");

  std::map<std::string, std::string> iterated_entries;

  auto store_iterated =
    [&iterated_entries](const auto& key, const auto& value) {
      auto it = iterated_entries.find(key);
      REQUIRE(it == iterated_entries.end());
      iterated_entries[key] = value;
      return true;
    };

  SUBCASE("Empty map")
  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    handle->foreach(store_iterated);
    REQUIRE(iterated_entries.empty());
  }

  SUBCASE("Reading own writes")
  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    handle->put("key1", "value1");
    handle->put("key2", "value2");
    handle->foreach(store_iterated);
    REQUIRE(iterated_entries.size() == 2);
    REQUIRE(iterated_entries["key1"] == "value1");
    REQUIRE(iterated_entries["key2"] == "value2");

    iterated_entries.clear();

    INFO("Uncommitted writes from other txs are not visible");
    auto tx2 = kv_store.create_tx();
    auto handle2 = tx2.rw(map);
    handle2->foreach(store_iterated);
    REQUIRE(iterated_entries.empty());
  }

  SUBCASE("Reading committed writes")
  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    handle->put("key1", "value1");
    handle->put("key2", "value2");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

    auto tx2 = kv_store.create_tx();
    auto handle2 = tx2.rw(map);
    handle2->foreach(store_iterated);
    REQUIRE(iterated_entries.size() == 2);
    REQUIRE(iterated_entries["key1"] == "value1");
    REQUIRE(iterated_entries["key2"] == "value2");
  }

  SUBCASE("Mix of committed and own writes")
  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    handle->put("key1", "value1");
    handle->put("key2", "value2");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

    auto tx2 = kv_store.create_tx();
    auto handle2 = tx2.rw(map);
    handle2->put("key2", "replaced2");
    handle2->put("key3", "value3");
    handle2->foreach(store_iterated);
    REQUIRE(iterated_entries.size() == 3);
    REQUIRE(iterated_entries["key1"] == "value1");
    REQUIRE(iterated_entries["key2"] == "replaced2");
    REQUIRE(iterated_entries["key3"] == "value3");
  }

  SUBCASE("Deletions")
  {
    {
      auto tx = kv_store.create_tx();
      auto handle = tx.rw(map);
      handle->put("key1", "value1");
      handle->put("key2", "value2");
      handle->put("key3", "value3");
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    {
      auto tx = kv_store.create_tx();
      auto handle = tx.rw(map);
      handle->remove("key1");
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    {
      auto tx = kv_store.create_tx();
      auto handle = tx.rw(map);
      handle->foreach(store_iterated);
      REQUIRE(iterated_entries.size() == 2);
      REQUIRE(iterated_entries["key2"] == "value2");
      REQUIRE(iterated_entries["key3"] == "value3");

      iterated_entries.clear();

      handle->remove("key2");
      handle->foreach(store_iterated);
      REQUIRE(iterated_entries.size() == 1);
      REQUIRE(iterated_entries["key3"] == "value3");

      iterated_entries.clear();

      handle->put("key1", "value1");
      handle->put("key2", "value2");
      handle->foreach(store_iterated);
      REQUIRE(iterated_entries.size() == 3);
      REQUIRE(iterated_entries["key1"] == "value1");
      REQUIRE(iterated_entries["key2"] == "value2");
      REQUIRE(iterated_entries["key3"] == "value3");
    }
  }

  SUBCASE("Early termination")
  {
    {
      auto tx = kv_store.create_tx();
      auto handle = tx.rw(map);
      handle->put("key1", "value1");
      handle->put("key2", "value2");
      handle->put("key3", "value3");
      size_t ctr = 0;
      handle->foreach([&ctr](const auto& key, const auto& value) {
        ++ctr;
        return ctr < 2; // Continue after the first, but not the second (so
                        // never see the third)
      });
      REQUIRE(ctr == 2);
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    {
      auto tx = kv_store.create_tx();
      auto handle = tx.rw(map);
      handle->put("key4", "value4");
      handle->put("key5", "value5");

      {
        size_t ctr = 0;
        handle->foreach([&ctr](const auto&, const auto&) {
          ++ctr;
          return ctr < 2; //< See only committed state
        });
        REQUIRE(ctr == 2);
      }

      {
        size_t ctr = 0;
        handle->foreach([&ctr](const auto&, const auto&) {
          ++ctr;
          return ctr < 4; //< See mix of old state and new writes
        });
        REQUIRE(ctr == 4);
      }

      {
        size_t ctr = 0;
        handle->foreach([&ctr](const auto&, const auto&) {
          ++ctr;
          return ctr < 100; //< See as much as possible
        });
        REQUIRE(ctr == 5);
      }
    }
  }
}

// The purpose of foreach_key and foreach_value is avoiding deserialisation of
// values/keys (respectively) when they're not needed. To confirm that they're
// not deserialised, we use a custom serialiser which will throw if ever asked
// to deserialise.
template <typename T>
struct NoDeserialise
{
  static ccf::kv::serialisers::SerialisedEntry to_serialised(const T& t)
  {
    return ccf::kv::serialisers::JsonSerialiser<T>::to_serialised(t);
  }

  static T from_serialised(const ccf::kv::serialisers::SerialisedEntry& s)
  {
    throw std::logic_error("This deserialiser should not be called");
  }
};

TEST_CASE("foreach_key")
{
  TestStore kv_store;

  ccf::kv::MapSerialisedWith<
    std::string,
    std::string,
    ccf::kv::serialisers::JsonSerialiser,
    NoDeserialise>
    map("public:map");

  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    handle->put("k1", "v1");
    handle->put("k2", "v2");
    handle->put("k3", "v3");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    REQUIRE_NOTHROW(handle->foreach_key([](const std::string& k) {
      REQUIRE(k.contains('k'));
      return true;
    }));

    // Sanity check: Confirm that deserialising any value would throw
    REQUIRE_THROWS(handle->foreach(
      [](const std::string& k, const std::string& v) { return true; }));
    REQUIRE_THROWS(handle->get("k1"));
  }
}

TEST_CASE("foreach_value")
{
  TestStore kv_store;

  ccf::kv::MapSerialisedWith<
    std::string,
    std::string,
    NoDeserialise,
    ccf::kv::serialisers::JsonSerialiser>
    map("public:map");

  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    handle->put("k1", "v1");
    handle->put("k2", "v2");
    handle->put("k3", "v3");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    REQUIRE_NOTHROW(handle->foreach_value([](const std::string& v) {
      REQUIRE(v.contains('v'));
      return true;
    }));

    // Sanity check: Confirm that deserialising any key would throw
    REQUIRE_THROWS(handle->foreach(
      [](const std::string& k, const std::string& v) { return true; }));
  }
}

TEST_CASE("Modifications during foreach iteration")
{
  TestStore kv_store;
  MapTypes::NumString map("public:map");

  const auto value1 = "foo";
  const auto value2 = "bar";

  std::set<size_t> keys;
  {
    INFO("Insert initial keys");

    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    for (size_t i = 0; i < 60; ++i)
    {
      keys.insert(i);
      handle->put(i, value1);
    }

    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  auto tx = kv_store.create_tx();
  auto handle = tx.rw(map);

  // 5 types of key:
  // 1) previously committed and unmodified
  const auto initial_keys_size = keys.size();
  const auto keys_per_category = keys.size() / 3;
  // We do nothing to the first keys_per_category keys

  // 2) previously committed and had their values changed
  for (size_t i = keys_per_category; i < 2 * keys_per_category; ++i)
  {
    keys.insert(i);
    handle->put(i, value2);
  }

  // 3) previously committed and now removed
  for (size_t i = 2 * keys_per_category; i < initial_keys_size; ++i)
  {
    keys.erase(i);
    handle->remove(i);
  }

  // 4) newly written
  for (size_t i = initial_keys_size; i < initial_keys_size + keys_per_category;
       ++i)
  {
    keys.insert(i);
    handle->put(i, value2);
  }

  // 5) newly written and then removed
  for (size_t i = initial_keys_size + keys_per_category;
       i < initial_keys_size + 2 * keys_per_category;
       ++i)
  {
    keys.insert(i);
    handle->put(i, value2);

    keys.erase(i);
    handle->remove(i);
  }

  size_t keys_seen = 0;
  const auto expected_keys_seen = keys.size();

  SUBCASE("Removing current key while iterating")
  {
    auto should_remove = [](size_t n) { return n % 3 == 0 || n % 5 == 0; };

    handle->foreach(
      [&handle, &keys, &keys_seen, should_remove](const auto& k, const auto&) {
        ++keys_seen;
        const auto it = keys.find(k);
        REQUIRE(it != keys.end());

        // Remove a 'random' set of keys while iterating
        if (should_remove(k))
        {
          handle->remove(k);
          keys.erase(it);
        }

        return true;
      });

    REQUIRE(keys_seen == expected_keys_seen);

    // Check all expected keys are still there...
    handle->foreach([&keys, should_remove](const auto& k, const auto&) {
      REQUIRE(!should_remove(k));
      const auto it = keys.find(k);
      REQUIRE(it != keys.end());
      keys.erase(it);
      return true;
    });

    // ...and nothing else
    REQUIRE(keys.empty());
  }

  SUBCASE("Removing other keys while iterating")
  {
    auto should_remove = [](size_t n) { return n % 3 == 0 || n % 5 == 0; };

    std::optional<size_t> removal_trigger = std::nullopt;

    handle->foreach(
      [&handle, &keys, &keys_seen, &removal_trigger, should_remove](
        const auto& k, const auto&) {
        ++keys_seen;

        // The first time we find a removable, remove _all the others_ (not
        // ourself!)
        if (should_remove(k) && !removal_trigger.has_value())
        {
          REQUIRE(!removal_trigger.has_value());
          removal_trigger = k;

          auto remove_it = keys.begin();
          while (remove_it != keys.end())
          {
            const auto n = *remove_it;
            if (should_remove(n) && n != k)
            {
              handle->remove(n);
              remove_it = keys.erase(remove_it);
            }
            else
            {
              ++remove_it;
            }
          }
        }

        return true;
      });

    REQUIRE(keys_seen == expected_keys_seen);

    REQUIRE(removal_trigger.has_value());

    // Check all expected keys are still there...
    handle->foreach(
      [&keys, removal_trigger, should_remove](const auto& k, const auto&) {
        const auto should_be_here =
          !should_remove(k) || k == removal_trigger.value();
        REQUIRE(should_be_here);
        const auto it = keys.find(k);
        REQUIRE(it != keys.end());
        keys.erase(it);
        return true;
      });

    // ...and nothing else
    REQUIRE(keys.empty());
  }

  static constexpr auto value3 = "baz";

  SUBCASE("Modifying and adding other keys while iterating")
  {
    auto should_modify = [](size_t n) { return n % 3 == 0 || n % 5 == 0; };

    std::set<size_t> updated_keys;

    handle->foreach([&handle, &keys, &keys_seen, &updated_keys, should_modify](
                      const auto& k, const auto& v) {
      ++keys_seen;

      if (should_modify(k))
      {
        // Modify ourselves
        handle->put(k, value3);
        updated_keys.insert(k);

        // Modify someone else ('before' and 'after' are guesses - iteration
        // order is undefined!)
        const auto before = k / 2;
        handle->put(before, value3);
        keys.insert(before);
        updated_keys.insert(before);

        const auto after = k * 2;
        handle->put(after, value3);
        keys.insert(after);
        updated_keys.insert(after);

        // Note discrepancy with externally visible value
        const auto visible_v = handle->get(k);
        REQUIRE(visible_v.has_value());
        REQUIRE(visible_v.value() == value3);
        REQUIRE(visible_v.value() != v); // !!
      }

      return true;
    });

    REQUIRE(keys_seen == expected_keys_seen);

    // Check all expected keys are still there...
    handle->foreach([&keys, &updated_keys](const auto& k, const auto& v) {
      const auto updated_it = updated_keys.find(k);
      if (updated_it != updated_keys.end())
      {
        REQUIRE(v == value3);
        updated_keys.erase(updated_it);
      }
      else
      {
        REQUIRE(v != value3);
      }

      const auto it = keys.find(k);
      if (it != keys.end())
      {
        keys.erase(it);
      }

      return true;
    });

    // ...and nothing else
    REQUIRE(keys.empty());
    REQUIRE(updated_keys.empty());
  }

  SUBCASE("Rewriting to new keys")
  {
    // Rewrite map, placing each value at a new key
    handle->foreach([&handle, &keys_seen](const auto& k, const auto& v) {
      ++keys_seen;

      handle->remove(k);

      const auto new_key = k + 1000;
      REQUIRE(!handle->has(new_key));
      handle->put(new_key, v);

      return true;
    });

    REQUIRE(keys_seen == expected_keys_seen);

    // Check map contains only new keys, and the same count
    keys_seen = 0;
    handle->foreach([&keys, &keys_seen](const auto& k, const auto& v) {
      ++keys_seen;

      REQUIRE(keys.find(k) == keys.end());

      return true;
    });

    REQUIRE(keys_seen == expected_keys_seen);
  }
}

TEST_CASE("Read-only tx")
{
  TestStore kv_store;
  MapTypes::StringString map("public:map");

  constexpr auto k = "key";
  constexpr auto invalid_key = "invalid_key";
  constexpr auto v1 = "value1";

  INFO("Write some keys");
  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    auto v = handle->get(k);
    REQUIRE(!v.has_value());
    handle->put(k, v1);
    auto va = handle->get(k);
    REQUIRE(va.has_value());
    REQUIRE(va.value() == v1);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  INFO("Do only reads with an overpowered Tx");
  {
    auto tx = kv_store.create_tx();
    auto handle = tx.ro(map);
    REQUIRE(handle->has(k));
    const auto v = handle->get(k);
    REQUIRE(v.has_value());
    REQUIRE(v.value() == v1);

    REQUIRE(!handle->has(invalid_key));
    const auto invalid_v = handle->get(invalid_key);
    REQUIRE(!invalid_v.has_value());

    // The following won't compile:
    // handle->put(k, v1);
    // handle->remove(k);
  }

  INFO("Read with read-only tx");
  {
    auto tx = kv_store.create_read_only_tx();
    auto handle = tx.ro(map);
    REQUIRE(handle->has(k));
    const auto v = handle->get(k);
    REQUIRE(v.has_value());
    REQUIRE(v.value() == v1);

    REQUIRE(!handle->has(invalid_key));
    const auto invalid_v = handle->get(invalid_key);
    REQUIRE(!invalid_v.has_value());

    // The following won't compile:
    // handle->put(k, v1);
    // handle->remove(k);
  }

  INFO("Write-only handles");
  {
    auto tx = kv_store.create_tx();
    auto handle = tx.wo(map);

    handle->put(k, v1);
    handle->remove(k);

    // The following won't compile:
    // handle->has(k);
    // handle->get(k);
    // handle->foreach([](const auto&, const auto&) {});
  }
}

TEST_CASE("Conflict resolution")
{
  TestStore kv_store;
  MapTypes::StringString map("public:map");

  {
    // Ensure this map already exists, by making a prior write to it
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    handle->put("foo", "initial");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  auto try_write = [&](auto& tx, const std::string& s) {
    auto handle = tx.rw(map);

    // Introduce read-dependency
    handle->get("foo");
    handle->put("foo", s);

    handle->put(s, s);
  };

  auto confirm_state = [&](
                         const std::vector<std::string>& present,
                         const std::vector<std::string>& missing) {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);

    for (const auto& s : present)
    {
      const auto it = handle->get(s);
      REQUIRE(it.has_value());
      REQUIRE(handle->has(s));
      REQUIRE(it.value() == s);
    }

    for (const auto& s : missing)
    {
      const auto it = handle->get(s);
      REQUIRE(!it.has_value());
      REQUIRE(!handle->has(s));
    }
  };

  // Simulate parallel execution by interleaving tx steps
  auto tx1 = kv_store.create_tx();
  auto tx2 = kv_store.create_tx();

  // First transaction tries to write a value, depending on initial version
  try_write(tx1, "bar");

  {
    // A second transaction is committed, conflicting with the first
    try_write(tx2, "baz");
    const auto res2 = tx2.commit();
    REQUIRE(res2 == ccf::kv::CommitResult::SUCCESS);

    confirm_state({"baz"}, {"bar"});
  }

  // Trying to commit first transaction produces a conflict
  auto res1 = tx1.commit();
  REQUIRE(res1 == ccf::kv::CommitResult::FAIL_CONFLICT);
  confirm_state({"baz"}, {"bar"});

  // A third transaction just wants to read the value
  auto tx3 = kv_store.create_tx();
  auto handle3 = tx3.ro(map);
  REQUIRE(handle3->has("foo"));

  // First transaction is rerun on new object, producing different result
  tx1 = kv_store.create_tx();
  try_write(tx1, "buzz");

  // Expected results are committed
  res1 = tx1.commit();
  REQUIRE(res1 == ccf::kv::CommitResult::SUCCESS);
  confirm_state({"baz", "buzz"}, {"bar"});

  // Third transaction completes later, has no conflicts but reports the earlier
  // version it read
  auto res3 = tx3.commit();
  REQUIRE(res3 == ccf::kv::CommitResult::SUCCESS);

  REQUIRE(tx1.commit_version() > tx2.commit_version());
  REQUIRE(tx3.get_txid()->seqno >= tx2.get_txid()->seqno);

  // Re-running a _committed_ transaction is exceptionally bad
  REQUIRE_THROWS(tx1.commit());
  REQUIRE_THROWS(tx2.commit());
}

TEST_CASE("Conflict resolution - removals")
{
  enum class Cases : size_t
  {
    NoReads = 0,
    ReadSameKey,
    ReadOtherKey,
    WriteSameKey,
    WriteOtherKey,
    MAX
  };

  for (size_t i = 0; i < (size_t)Cases::MAX; ++i)
  {
    auto c = Cases(i);
    INFO("Considering case " << c);

    TestStore kv_store;
    MapTypes::StringString map("public:map");

    {
      // Ensure maps already exist, by making prior writes
      auto tx = kv_store.create_tx();
      tx.rw(map)->put("", "");
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    // Simulate parallel execution by interleaving tx steps
    auto tx1 = kv_store.create_tx();
    auto tx2 = kv_store.create_tx();

    constexpr auto k = "key";

    auto handle_1 = tx1.rw(map);

    switch (c)
    {
      case Cases::NoReads:
      {
        break;
      }
      case Cases::ReadSameKey:
      {
        handle_1->has(k);
        break;
      }
      case Cases::ReadOtherKey:
      {
        handle_1->has("unrelated");
        break;
      }
      case Cases::WriteSameKey:
      {
        handle_1->put(k, "saluton");
        break;
      }
      case Cases::WriteOtherKey:
      {
        handle_1->put("unrelated", "saluton");
        break;
      }
      case Cases::MAX:
      default:
      {
        throw std::logic_error("Unhandled");
        break;
      }
    }

    handle_1->remove(k);

    {
      auto handle = tx2.rw(map);
      handle->put(k, "hello");
      REQUIRE(tx2.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    const auto expected = c == Cases::ReadSameKey ?
      ccf::kv::CommitResult::FAIL_CONFLICT :
      ccf::kv::CommitResult::SUCCESS;

    CHECK_EQ(tx1.commit(), expected);

    auto tx3 = kv_store.create_tx();
    auto handle = tx3.rw(map);
    if (c == Cases::ReadSameKey)
    {
      const auto v = handle->get(k);
      CHECK(v.has_value());
      CHECK_EQ(v.value(), "hello");
    }
    else
    {
      // NB: In all of these cases, this remove has been applied _after_ tx2,
      // though it executed 'before'. This is because it has no
      // dependencies/conflicts with tx2, so it is safe to apply its removes on
      // the later state.
      CHECK(!handle->has(k));
      CHECK_GT(tx1.commit_version(), tx2.commit_version());
    }
  }
}

TEST_CASE("Cross-map conflicts")
{
  TestStore kv_store;
  MapTypes::StringString source("public:source");
  MapTypes::StringString dest("public:dest");

  {
    INFO("Set initial state");

    auto tx = kv_store.create_tx();
    auto source_handle = tx.wo(source);
    source_handle->put("hello", "world");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  {
    INFO("Start an operation copying a value across tables");
    auto copy_tx = kv_store.create_tx();
    {
      auto src_handle = copy_tx.ro(source);
      auto dst_handle = copy_tx.wo(dest);
      const auto v = src_handle->get("hello");
      REQUIRE(v.has_value());
      dst_handle->put("hello", v.value());
    }

    INFO(
      "Before the copy commits, another operation changes the source, and "
      "commits");
    {
      auto interfere_tx = kv_store.create_tx();
      auto src_handle = interfere_tx.wo(source);
      src_handle->put("hello", "alice");
      REQUIRE(interfere_tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    INFO("Copying operation should conflict on commit");
    REQUIRE(copy_tx.commit() == ccf::kv::CommitResult::FAIL_CONFLICT);
  }

  {
    INFO("Start an operation moving a value across tables");
    auto move_tx = kv_store.create_tx();
    {
      auto src_handle = move_tx.rw(source);
      auto dst_handle = move_tx.wo(dest);
      const auto v = src_handle->get("hello");
      REQUIRE(v.has_value());
      dst_handle->put("hello", v.value());

      // Unlike copy, this operation destroys the source! That should not change
      // its conflict set
      src_handle->remove("hello");
    }

    INFO(
      "Before the move commits, another operation changes the source, and "
      "commits");
    {
      auto interfere_tx = kv_store.create_tx();
      auto src_handle = interfere_tx.wo(source);
      src_handle->put("hello", "bob");
      REQUIRE(interfere_tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    INFO("Moving operation should conflict on commit");
    REQUIRE(move_tx.commit() == ccf::kv::CommitResult::FAIL_CONFLICT);
  }
}

TEST_CASE("Mid-tx compaction")
{
  TestStore kv_store;
  MapTypes::StringNum map_a("public:A");
  MapTypes::StringNum map_b("public:B");

  constexpr auto key_a = "a";
  constexpr auto key_b = "b";

  auto increment_vals = [&]() {
    auto tx = kv_store.create_tx();
    auto handle_a = tx.rw(map_a);
    auto handle_b = tx.rw(map_b);

    auto a_opt = handle_a->get(key_a);
    auto b_opt = handle_b->get(key_b);

    REQUIRE(a_opt == b_opt);

    const auto new_val = a_opt.has_value() ? *a_opt + 1 : 0;

    handle_a->put(key_a, new_val);
    handle_b->put(key_b, new_val);

    const auto result = tx.commit();
    REQUIRE(result == ccf::kv::CommitResult::SUCCESS);
  };

  increment_vals();

  {
    INFO("Compaction before get_handles");
    auto tx = kv_store.create_tx();

    increment_vals();
    kv_store.compact(kv_store.current_version());

    auto handle_a = tx.rw(map_a);
    auto handle_b = tx.rw(map_b);

    auto a_opt = handle_a->get(key_a);
    auto b_opt = handle_b->get(key_b);

    REQUIRE(a_opt == b_opt);

    const auto result = tx.commit();
    REQUIRE(result == ccf::kv::CommitResult::SUCCESS);
  }

  {
    INFO("Compaction after get_handles");
    auto tx = kv_store.create_tx();

    auto handle_a = tx.rw(map_a);
    increment_vals();
    auto handle_b = tx.rw(map_b);
    kv_store.compact(kv_store.current_version());

    auto a_opt = handle_a->get(key_a);
    auto b_opt = handle_b->get(key_b);

    REQUIRE(a_opt == b_opt);

    const auto result = tx.commit();
    REQUIRE(result == ccf::kv::CommitResult::SUCCESS);
  }

  {
    INFO("Compaction between get_handles");
    bool threw = false;

    try
    {
      auto tx = kv_store.create_tx();

      auto handle_a = tx.rw(map_a);
      // This transaction does something slow. Meanwhile...

      // ...another transaction commits...
      increment_vals();
      // ...and is compacted...
      kv_store.compact(kv_store.current_version());

      // ...then the original transaction proceeds, expecting to read a single
      // version
      // This should throw a CompactedVersionConflict error
      auto handle_b = tx.rw(map_b);

      auto a_opt = handle_a->get(key_a);
      auto b_opt = handle_b->get(key_b);

      REQUIRE(a_opt == b_opt);

      const auto result = tx.commit();
      REQUIRE(result == ccf::kv::CommitResult::SUCCESS);
    }
    catch (const ccf::kv::CompactedVersionConflict& e)
    {
      threw = true;
    }

    REQUIRE(threw);
    // In real operation, this transaction would be re-executed and hope to not
    // intersect a compaction
  }
}

template <typename T>
std::map<T, T> std_map_range(
  const std::map<T, T>& map, std::optional<T> from, std::optional<T> to)
{
  if (
    from.has_value() && to.has_value() &&
    (from.value() == to.value() || to.value() < from.value()))
  {
    return {};
  }

  auto f = map.begin();
  if (from.has_value())
  {
    f = map.lower_bound(from.value());
  }
  auto t = map.end();
  if (to.has_value())
  {
    t = map.lower_bound(to.value());
  }

  std::map<T, T> ret = {};
  for (auto it = f; it != t; it++)
  {
    ret.emplace(*it);
  }

  return ret;
}

template <typename T>
T get_map_get_factor(const std::map<T, T>& map, size_t factor)
{
  auto middle_it = map.begin();
  std::advance(middle_it, map.size() / factor);
  return middle_it->first;
}

template <class H, class T>
std::map<T, T> kv_map_range(H& h, std::optional<T> from, std::optional<T> to)
{
  std::map<T, T> range;
  auto f = [&range](const T& k, const T& v) { range.emplace(k, v); };
  h->range(f, from, to);
  return range;
}

TEST_CASE("Range")
{
  using KVMap = ccf::kv::untyped::Map;
  using KeyType = ccf::kv::untyped::MapHandle::KeyType;
  using ValueType = ccf::kv::untyped::MapHandle::ValueType;
  using RefMap = std::map<KeyType, ValueType>;
  using Serialiser = ccf::kv::serialisers::JsonSerialiser<size_t>;

  size_t size = 100;
  size_t entries_space_size = size * 10;
  const auto map_name = "public:map";
  const ValueType empty_value = {};

  TestStore kv_store;
  RefMap ref;

  INFO("Populate map randomly");
  {
    std::random_device rand_dev;
    auto seed = rand_dev();
    LOG_INFO_FMT("Seed: {}", seed);
    std::mt19937 gen(seed);
    std::uniform_int_distribution<> distrib(0, entries_space_size);

    auto tx = kv_store.create_tx();
    auto h = tx.rw<KVMap>(map_name);

    for (size_t i = 0; i < size; i++)
    {
      auto key = distrib(gen);
      auto serialised_key = Serialiser::to_serialised(key);
      h->put(serialised_key, empty_value);
      ref[serialised_key] = empty_value;
    }
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  INFO("Compare ranges between KV map and reference");
  {
    auto tx = kv_store.create_tx();
    auto h = tx.rw<KVMap>(map_name);

    // Test variety of ranges, with some expected to return nothing
    auto first = ref.begin()->first;
    auto last = ref.rbegin()->first;
    auto middle = get_map_get_factor(ref, 2);
    std::vector<std::pair<std::optional<KeyType>, std::optional<KeyType>>>
      ranges = {
        {first, first},
        {last, last},
        {last, first},
        {last, middle},
        {first, last},
        {first, middle},
        {middle, last},
        {first, last},
        {std::nullopt, first},
        {std::nullopt, middle},
        {std::nullopt, last},
        {first, std::nullopt},
        {middle, std::nullopt},
        {last, std::nullopt},
        {std::nullopt, std::nullopt}};

    for (const auto& range : ranges)
    {
      auto std_range = std_map_range(ref, range.first, range.second);
      auto kv_range = kv_map_range(h, range.first, range.second);
      REQUIRE(std_range == kv_range);
    }
  }

  auto key_to_remove = get_map_get_factor(ref, 2);

  INFO("Deleted keys are not returned");
  {
    INFO("Remove key");
    {
      auto tx = kv_store.create_tx();
      auto h = tx.rw<KVMap>(map_name);

      // Check key exists before deletion
      std::optional<KeyType> from = ref.begin()->first;
      std::optional<KeyType> to = ref.rbegin()->first;
      REQUIRE_NOTHROW(kv_map_range(h, from, to).at(key_to_remove));

      {
        h->remove(key_to_remove);
        REQUIRE(ref.erase(key_to_remove) == 1);
      }
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    INFO("Range does not include key");
    {
      // Fresh tx/handle
      auto tx = kv_store.create_tx();
      auto h = tx.rw<KVMap>(map_name);

      std::optional<KeyType> from = ref.begin()->first;
      std::optional<KeyType> to = ref.rbegin()->first;
      auto kv_range = kv_map_range(h, from, to);
      REQUIRE_THROWS_AS(kv_range.at(key_to_remove), std::out_of_range);
    }
  }

  INFO("Return own writes too");
  {
    auto tx = kv_store.create_tx();
    auto h = tx.rw<KVMap>(map_name);

    INFO("Re-insert removed key");
    {
      REQUIRE(!h->get(key_to_remove).has_value());
      h->put(key_to_remove, empty_value);
      ref[key_to_remove] = empty_value;
      REQUIRE(h->get(key_to_remove).has_value());
    }

    ValueType well_known_value = {42};
    auto existing_key = get_map_get_factor(ref, 4);

    INFO("Modify existing key");
    {
      h->put(existing_key, well_known_value);
      ref[existing_key] = well_known_value;
    }

    // Do not commit transaction

    std::optional<KeyType> first = ref.begin()->first;
    std::optional<KeyType> last = ref.rbegin()->first;
    auto std_range = std_map_range(ref, first, last);
    auto kv_range = kv_map_range(h, first, last);
    REQUIRE(std_range == kv_range);
    REQUIRE(kv_range.at(existing_key) == well_known_value);
  }
}

TEST_CASE("Basic dynamic table" * doctest::test_suite("dynamic"))
{
  TestStore kv_store;

  constexpr auto map_name = "mapA";

  INFO("Dynamically created maps can be used like normal maps");

  {
    auto tx = kv_store.create_tx();

    auto handle = tx.rw<MapTypes::StringString>(map_name);
    handle->put("foo", "bar");

    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  {
    INFO("New style access");
    auto tx = kv_store.create_tx();

    auto handle = tx.rw<MapTypes::StringString>(map_name);
    const auto it = handle->get("foo");
    REQUIRE(it.has_value());
    REQUIRE(it.value() == "bar");
  }

  {
    INFO("Dynamic tables remain through compaction");
    kv_store.compact(kv_store.current_version());

    auto tx = kv_store.create_tx();

    auto handle = tx.rw<MapTypes::StringString>(map_name);
    const auto it = handle->get("foo");
    REQUIRE(it.has_value());
    REQUIRE(it.value() == "bar");
  }

  const auto txid_before = kv_store.current_txid();

  constexpr auto new_map1 = "new_map1";
  constexpr auto new_map2 = "new_map2";
  constexpr auto new_map3 = "new_map3";

  {
    INFO("Multiple dynamic tables can be created in a single tx");
    auto tx = kv_store.create_tx();

    auto v1 = tx.rw<MapTypes::StringString>(new_map1);
    auto v2 = tx.rw<MapTypes::StringNum>(new_map2);
    auto v2a = tx.rw<MapTypes::StringNum>(new_map2);
    auto v3 = tx.rw<MapTypes::NumString>(new_map3);

    REQUIRE(v2 == v2a);

    v1->put("foo", "bar");
    v3->put(42, "hello");

    auto a = tx.rw<MapTypes::StringString>(map_name);
    a->put("foo", "baz");

    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

    {
      auto check_tx = kv_store.create_tx();
      auto check_va = check_tx.rw<MapTypes::StringString>(map_name);
      const auto v = check_va->get("foo");
      REQUIRE(v.has_value());
      REQUIRE(v.value() == "baz");
    }
  }

  {
    INFO("Rollback can delete dynamic tables");
    kv_store.rollback(txid_before, kv_store.commit_view());

    {
      auto tx = kv_store.create_tx();
      auto v1 = tx.rw<MapTypes::StringString>(new_map1);
      auto v2 = tx.rw<MapTypes::StringNum>(new_map2);
      auto v3 = tx.rw<MapTypes::NumString>(new_map3);

      REQUIRE(!v1->has("foo"));
      REQUIRE(!v2->has("foo"));
      REQUIRE(!v3->has(42));
    }

    {
      INFO("Retained dynamic maps have their state rolled back");
      auto check_tx = kv_store.create_tx();
      auto check_va = check_tx.rw<MapTypes::StringString>(map_name);
      const auto v = check_va->get("foo");
      REQUIRE(v.has_value());
      REQUIRE(v.value() == "bar");
    }
  }
}

TEST_CASE("Dynamic table opacity" * doctest::test_suite("dynamic"))
{
  TestStore kv_store;

  constexpr auto map_name = "dynamic_map";

  auto tx1 = kv_store.create_tx();
  auto tx2 = kv_store.create_tx();

  auto handle1 = tx1.rw<MapTypes::StringString>(map_name);
  handle1->put("foo", "bar");
  REQUIRE(handle1->get("foo").value() == "bar");

  auto handle2 = tx2.rw<MapTypes::StringString>(map_name);
  handle2->put("foo", "baz");
  REQUIRE(handle2->get("foo").value() == "baz");

  {
    INFO("First transaction commits successfully");
    REQUIRE(tx1.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  {
    INFO("Committed transaction results are persisted");
    auto txx = kv_store.create_tx();
    auto handle = txx.rw<MapTypes::StringString>(map_name);
    const auto v = handle->get("foo");
    REQUIRE(v.has_value());
    REQUIRE(v.value() == "bar");
  }

  {
    INFO("Second transaction conflicts");
    REQUIRE(tx2.commit() == ccf::kv::CommitResult::FAIL_CONFLICT);
  }

  {
    INFO("Conflicting transaction can be rerun, on existing map");
    auto tx3 = kv_store.create_tx();
    auto handle3 = tx3.rw<MapTypes::StringString>(map_name);
    const auto v = handle3->get("foo");
    REQUIRE(v.has_value());
    handle3->put("foo", "baz");
    REQUIRE(handle3->get("foo").value() == "baz");

    REQUIRE(tx3.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  {
    INFO("Subsequent transactions over dynamic map are persisted");
    auto tx4 = kv_store.create_tx();
    auto handle4 = tx4.rw<MapTypes::StringString>(map_name);
    const auto v = handle4->get("foo");
    REQUIRE(v.has_value());
    REQUIRE(v.value() == "baz");
  }
}

TEST_CASE(
  "Dynamic table visibility by version" * doctest::test_suite("dynamic"))
{
  TestStore kv_store;

  constexpr auto map_name = "dynamic_map";
  constexpr auto other_map = "other_map";

  auto tx1 = kv_store.create_tx();
  auto tx2 = kv_store.create_tx();
  auto tx3 = kv_store.create_tx();
  auto tx4 = kv_store.create_tx();

  auto handle1 = tx1.rw<MapTypes::StringString>(map_name);
  handle1->put("foo", "bar");

  // Map created in tx1 is not visible
  auto handle2 = tx2.rw<MapTypes::StringString>(map_name);
  REQUIRE(!handle2->get("foo").has_value());

  // tx3 takes a read dependency at an early version, before the map is visible
  tx3.rw<MapTypes::StringString>(other_map);

  REQUIRE(tx1.commit() == ccf::kv::CommitResult::SUCCESS);

  // Even after commit, the new map is not visible to tx3 because it is reading
  // from an earlier version
  auto handle3 = tx3.rw<MapTypes::StringString>(map_name);
  REQUIRE(!handle3->get("foo").has_value());

  // Map created in tx1 is visible, because tx4 first _reads_ (creates a
  // handle) after tx1 has committed
  auto handle4 = tx4.rw<MapTypes::StringString>(map_name);
  REQUIRE(handle4->get("foo").has_value());
}

TEST_CASE("Read only handles" * doctest::test_suite("dynamic"))
{
  TestStore kv_store;

  constexpr auto dynamic_map_a = "dynamic_map_a";
  constexpr auto dynamic_map_b = "dynamic_map_b";

  {
    auto tx = kv_store.create_read_only_tx();
    auto a = tx.ro<MapTypes::StringString>(dynamic_map_a);
    auto aa = tx.ro<MapTypes::StringString>(dynamic_map_a);
    auto b = tx.ro<MapTypes::StringString>(dynamic_map_b);
    auto bb = tx.ro<MapTypes::StringString>(dynamic_map_b);

    REQUIRE(a != nullptr);
    REQUIRE(aa != nullptr);
    REQUIRE(b != nullptr);
    REQUIRE(bb != nullptr);

    REQUIRE(a == aa);
    REQUIRE(b == bb);

    REQUIRE(!a->get("foo").has_value());
    REQUIRE(!b->get("foo").has_value());
  }

  {
    auto tx = kv_store.create_tx();
    auto a = tx.rw<MapTypes::StringString>(dynamic_map_a);
    auto b = tx.rw<MapTypes::StringString>(dynamic_map_b);

    a->put("foo", "bar");
    b->put("foo", "baz");

    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  {
    auto tx = kv_store.create_read_only_tx();
    auto a = tx.ro<MapTypes::StringString>(dynamic_map_a);
    auto b = tx.ro<MapTypes::StringString>(dynamic_map_b);

    const auto foo_a = a->get("foo");
    REQUIRE(foo_a.has_value());
    REQUIRE(*foo_a == "bar");

    const auto foo_b = b->get("foo");
    REQUIRE(foo_b.has_value());
    REQUIRE(*foo_b == "baz");
  }
}

TEST_CASE("Mixed map dependencies" * doctest::test_suite("dynamic"))
{
  TestStore kv_store;

  constexpr auto key = "foo";

  MapTypes::StringString prior_map("prior_map");
  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(prior_map);
    handle->put(key, "bar");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  constexpr auto dynamic_map_a = "dynamic_map_a";
  constexpr auto dynamic_map_b = "dynamic_map_b";

  SUBCASE("Parallel independent map creation")
  {
    auto tx1 = kv_store.create_tx();
    auto tx2 = kv_store.create_tx();

    auto handle1 = tx1.rw<MapTypes::NumString>(dynamic_map_a);
    auto handle2 = tx2.rw<MapTypes::StringNum>(dynamic_map_b);

    handle1->put(42, "hello");
    handle2->put("hello", 42);

    REQUIRE(tx1.commit() == ccf::kv::CommitResult::SUCCESS);
    REQUIRE(tx2.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  SUBCASE("Map creation blocked by standard conflict")
  {
    auto tx1 = kv_store.create_tx();
    {
      auto handle1 = tx1.rw(prior_map);
      const auto v = handle1->get(key); // Introduce read-dependency
      handle1->put(key, "bar");
      auto dynamic_handle = tx1.rw<MapTypes::NumString>(dynamic_map_a);
      dynamic_handle->put(42, "hello world");
    }

    auto tx2 = kv_store.create_tx();
    {
      auto handle2 = tx2.rw(prior_map);
      const auto v = handle2->get(key); // Introduce read-dependency
      handle2->put(key, "bar");
      auto dynamic_handle = tx2.rw<MapTypes::StringNum>(dynamic_map_b);
      dynamic_handle->put("hello world", 42);
    }

    REQUIRE(tx1.commit() == ccf::kv::CommitResult::SUCCESS);
    REQUIRE(tx2.commit() == ccf::kv::CommitResult::FAIL_CONFLICT);

    tx2 = kv_store.create_tx();

    {
      auto tx3 = kv_store.create_tx();

      auto handle1 = tx1.rw<MapTypes::NumString>(dynamic_map_a);
      auto handle2 = tx2.rw<MapTypes::StringNum>(dynamic_map_b);

      const auto v1 = handle1->get(42);
      REQUIRE(v1.has_value());
      REQUIRE(v1.value() == "hello world");

      const auto v2 = handle2->get("hello world");
      REQUIRE_FALSE(v2.has_value());
    }
  }
}

TEST_CASE("Mid rollback safety" * doctest::test_suite("dynamic"))
{
  TestStore kv_store;

  constexpr auto map_name = "my_new_map";

  const auto txid_before = kv_store.current_txid();

  {
    auto tx = kv_store.create_tx();

    auto handle = tx.rw<MapTypes::StringString>(map_name);
    handle->put("foo", "bar");

    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw<MapTypes::StringString>(map_name);
    const auto v_0 = handle->get("foo");
    REQUIRE(v_0.has_value());
    REQUIRE(v_0.value() == "bar");

    // Rollbacks may happen while a tx is executing, and these can delete the
    // maps this tx is executing over
    kv_store.rollback(txid_before, kv_store.commit_view());

    const auto v_1 = handle->get("foo");
    REQUIRE(v_0.has_value());
    REQUIRE(v_0.value() == "bar");

    auto handle_after = tx.rw<MapTypes::StringString>(map_name);
    REQUIRE(handle_after == handle);

    handle->put("foo", "baz");

    const auto result = tx.commit();
    REQUIRE(result == ccf::kv::CommitResult::FAIL_CONFLICT);
  }
}

TEST_CASE(
  "Security domain is determined by map name" * doctest::test_suite("dynamic"))
{
  TestStore kv_store;

  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw<MapTypes::StringString>("public:foo");
    handle->put("foo", "bar");

    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw<MapTypes::StringString>("foo");
    handle->put("hello", "world");

    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  {
    auto tx = kv_store.create_tx();

    auto public_handle = tx.rw<MapTypes::StringString>("public:foo");
    auto private_handle = tx.rw<MapTypes::StringString>("foo");

    // These are _different handles_ over _different maps_
    REQUIRE(public_handle != private_handle);

    const auto pub_v = public_handle->get("foo");
    REQUIRE(pub_v.has_value());
    REQUIRE(pub_v.value() == "bar");

    const auto priv_v = private_handle->get("hello");
    REQUIRE(priv_v.has_value());
    REQUIRE(priv_v.value() == "world");
  }
}

TEST_CASE("Local commit hooks")
{
  using Write = MapTypes::StringString::Write;
  std::vector<Write> local_writes;
  std::vector<Write> global_writes;

  auto map_hook =
    [&](ccf::kv::Version v, const Write& w) -> ccf::kv::ConsensusHookPtr {
    local_writes.push_back(w);
    return ccf::kv::ConsensusHookPtr(nullptr);
  };
  auto global_hook = [&](ccf::kv::Version v, const Write& w) {
    global_writes.push_back(w);
  };

  TestStore kv_store;
  constexpr auto map_name = "public:map";
  MapTypes::StringString map(map_name);
  kv_store.set_map_hook(map_name, map.wrap_map_hook(map_hook));
  kv_store.set_global_hook(map_name, map.wrap_commit_hook(global_hook));

  INFO("Write with hooks");
  {
    {
      auto tx = kv_store.create_tx();
      auto handle = tx.rw(map);
      handle->put("key1", "value1");
      handle->put("key2", "value2");
      handle->remove("key2");
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

      REQUIRE(global_writes.size() == 0);
      REQUIRE(local_writes.size() == 1);
      const auto& latest_writes = local_writes.back();
      REQUIRE(latest_writes.at("key1").has_value());
      REQUIRE(latest_writes.at("key1").value() == "value1");
      REQUIRE(!latest_writes.at("key2").has_value());
      REQUIRE(latest_writes.size() == 2);
      local_writes.clear();
    }

    {
      REQUIRE(local_writes.size() == 0);
      auto tx = kv_store.create_tx();
      auto handle = tx.rw(map);
      handle->remove("key1");
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

      REQUIRE(global_writes.size() == 0);
      REQUIRE(local_writes.size() == 1);
      const auto& latest_writes = local_writes.back();
      INFO("Removals are seen");
      REQUIRE(latest_writes.find("key1") != latest_writes.end());
      REQUIRE(latest_writes.at("key1") == std::nullopt);

      local_writes.clear();
    }
  }

  INFO("Write without hooks");
  {
    kv_store.unset_map_hook(map_name);
    kv_store.unset_global_hook(map_name);

    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    handle->put("key2", "value2");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

    REQUIRE(local_writes.size() == 0);
    REQUIRE(global_writes.size() == 0);
  }

  INFO("Write with hook again");
  {
    kv_store.set_map_hook(map_name, map.wrap_map_hook(map_hook));
    kv_store.set_global_hook(map_name, map.wrap_commit_hook(global_hook));

    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    handle->remove("key2");
    handle->put("key3", "value3");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

    REQUIRE(global_writes.size() == 0);
    REQUIRE(local_writes.size() == 1);
    const auto& latest_writes = local_writes.front();
    INFO("Old writes are not included");
    REQUIRE(latest_writes.find("key1") == latest_writes.end());
    INFO("Visible removals are included");
    const auto it2 = latest_writes.find("key2");
    REQUIRE(it2 != latest_writes.end());
    REQUIRE(!it2->second.has_value());
    const auto it3 = latest_writes.find("key3");
    REQUIRE(it3 != latest_writes.end());
    REQUIRE(it3->second.has_value());
    REQUIRE(it3->second.value() == "value3");
    REQUIRE(latest_writes.size() == 2);

    local_writes.clear();
  }
}

TEST_CASE("Global commit hooks")
{
  using Write = MapTypes::StringString::Write;

  struct GlobalHookInput
  {
    ccf::kv::Version version;
    Write writes;
  };

  std::vector<GlobalHookInput> global_writes;

  auto global_hook = [&](ccf::kv::Version v, const Write& w) {
    global_writes.emplace_back(GlobalHookInput({v, w}));
  };

  TestStore kv_store;
  using MapT = ccf::kv::Map<std::string, std::string>;
  MapT map_with_hook("public:map_with_hook");
  kv_store.set_global_hook(
    map_with_hook.get_name(), map_with_hook.wrap_commit_hook(global_hook));

  MapT map_no_hook("public:map_no_hook");

  INFO("Compact an empty store");
  {
    kv_store.compact(0);

    REQUIRE(global_writes.size() == 0);
  }

  SUBCASE("Compact one transaction")
  {
    auto tx1 = kv_store.create_tx();
    auto handle_hook = tx1.rw(map_with_hook);
    handle_hook->put("key1", "value1");
    REQUIRE(tx1.commit() == ccf::kv::CommitResult::SUCCESS);

    kv_store.compact(1);

    REQUIRE(global_writes.size() == 1);
    const auto& latest_writes = global_writes.front();
    REQUIRE(latest_writes.version == 1);
    const auto it1 = latest_writes.writes.find("key1");
    REQUIRE(it1 != latest_writes.writes.end());
    REQUIRE(it1->second.has_value());
    REQUIRE(it1->second.value() == "value1");
  }

  SUBCASE("Compact beyond the last map version")
  {
    auto tx1 = kv_store.create_tx();
    auto tx2 = kv_store.create_tx();
    auto tx3 = kv_store.create_tx();
    auto handle_hook = tx1.rw(map_with_hook);
    handle_hook->put("key1", "value1");
    REQUIRE(tx1.commit() == ccf::kv::CommitResult::SUCCESS);

    handle_hook = tx2.rw(map_with_hook);
    handle_hook->put("key2", "value2");
    REQUIRE(tx2.commit() == ccf::kv::CommitResult::SUCCESS);

    const auto compact_version = kv_store.current_version();

    // This does not affect map_with_hook but still increments the current
    // version of the store
    auto handle_no_hook = tx3.rw(map_no_hook);
    handle_no_hook->put("key3", "value3");
    REQUIRE(tx3.commit() == ccf::kv::CommitResult::SUCCESS);

    kv_store.compact(compact_version);

    // Only the changes made to map_with_hook should be passed to the global
    // hook
    REQUIRE(global_writes.size() == 2);
    REQUIRE(global_writes.at(0).version == 1);
    const auto it1 = global_writes.at(0).writes.find("key1");
    REQUIRE(it1 != global_writes.at(0).writes.end());
    REQUIRE(it1->second.has_value());
    REQUIRE(it1->second.value() == "value1");
    const auto it2 = global_writes.at(1).writes.find("key2");
    REQUIRE(it2 != global_writes.at(1).writes.end());
    REQUIRE(it2->second.has_value());
    REQUIRE(it2->second.value() == "value2");
  }

  SUBCASE("Compact in between two map versions")
  {
    auto tx1 = kv_store.create_tx();
    auto tx2 = kv_store.create_tx();
    auto tx3 = kv_store.create_tx();
    auto handle_hook = tx1.rw(map_with_hook);
    handle_hook->put("key1", "value1");
    REQUIRE(tx1.commit() == ccf::kv::CommitResult::SUCCESS);

    // This does not affect map_with_hook but still increments the current
    // version of the store
    auto handle_no_hook = tx2.rw(map_no_hook);
    handle_no_hook->put("key2", "value2");
    REQUIRE(tx2.commit() == ccf::kv::CommitResult::SUCCESS);

    const auto compact_version = kv_store.current_version();

    handle_hook = tx3.rw(map_with_hook);
    handle_hook->put("key3", "value3");
    REQUIRE(tx3.commit() == ccf::kv::CommitResult::SUCCESS);

    kv_store.compact(compact_version);

    // Only the changes made to map_with_hook should be passed to the global
    // hook
    REQUIRE(global_writes.size() == 1);
    REQUIRE(global_writes.at(0).version == 1);
    const auto it1 = global_writes.at(0).writes.find("key1");
    REQUIRE(it1 != global_writes.at(0).writes.end());
    REQUIRE(it1->second.has_value());
    REQUIRE(it1->second.value() == "value1");
  }

  SUBCASE("Compact twice")
  {
    auto tx1 = kv_store.create_tx();
    auto tx2 = kv_store.create_tx();
    auto handle_hook = tx1.rw(map_with_hook);
    handle_hook->put("key1", "value1");
    REQUIRE(tx1.commit() == ccf::kv::CommitResult::SUCCESS);

    kv_store.compact(kv_store.current_version());
    global_writes.clear();

    handle_hook = tx2.rw(map_with_hook);
    handle_hook->put("key2", "value2");
    REQUIRE(tx2.commit() == ccf::kv::CommitResult::SUCCESS);

    kv_store.compact(kv_store.current_version());

    // Only writes since the last compact are passed to the global hook
    REQUIRE(global_writes.size() == 1);
    REQUIRE(global_writes.at(0).version == 2);
    const auto it2 = global_writes.at(0).writes.find("key2");
    REQUIRE(it2 != global_writes.at(0).writes.end());
    REQUIRE(it2->second.has_value());
    REQUIRE(it2->second.value() == "value2");
  }
}

TEST_CASE("sets and values")
{
  ccf::kv::test::TestStoreBase kv_store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);

  {
    INFO("ccf::kv::Set");
    using Set = ccf::kv::Set<std::string>;
    Set set("public:set");
    constexpr auto k1 = "key1";
    constexpr auto k2 = "key2";

    {
      INFO("Read own writes");
      auto tx = kv_store.create_tx();
      auto set_handle = tx.rw(set);

      REQUIRE(!set_handle->contains(k1));
      REQUIRE(set_handle->size() == 0);

      set_handle->insert(k1);
      REQUIRE(set_handle->contains(k1));
      REQUIRE(set_handle->size() == 1);

      REQUIRE(!set_handle->contains(k2));
      set_handle->insert(k2);
      REQUIRE(set_handle->contains(k2));
      REQUIRE(set_handle->size() == 2);

      REQUIRE(!set_handle->contains_globally_committed(k1));
      REQUIRE(!set_handle->contains_globally_committed(k2));

      set_handle->remove(k2);
      REQUIRE(!set_handle->contains(k2));
      REQUIRE(set_handle->size() == 1);

      REQUIRE(!set_handle->contains_globally_committed(k1));
      REQUIRE(!set_handle->contains_globally_committed(k2));

      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    {
      INFO("Read previous writes");
      auto tx = kv_store.create_tx();
      auto set_handle = tx.ro(set);
      REQUIRE(set_handle->contains(k1));
      REQUIRE(!set_handle->contains(k2));

      // NB: Previous transaction committed locally, but not yet globally
      REQUIRE(!set_handle->contains_globally_committed(k1));
      REQUIRE(!set_handle->contains_globally_committed(k2));

      REQUIRE(set_handle->size() == 1);
      std::set<std::string> std_set;
      set_handle->foreach([&std_set](const std::string& entry) {
        std_set.insert(entry);
        return true;
      });
      REQUIRE(std_set.size() == 1);
      REQUIRE(std_set.find(k1) != std_set.end());
      REQUIRE(std_set.find(k2) == std_set.end());
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    {
      INFO("Read committed writes");
      kv_store.compact(kv_store.current_version());

      auto tx = kv_store.create_tx();
      auto set_handle = tx.rw(set);

      REQUIRE(set_handle->contains_globally_committed(k1));
      REQUIRE(!set_handle->contains_globally_committed(k2));

      // Local modifications do not affect globally_committed
      set_handle->remove(k1);
      set_handle->insert(k2);

      REQUIRE(set_handle->contains_globally_committed(k1));
      REQUIRE(!set_handle->contains_globally_committed(k2));

      // This tx is deliberately dropped, not committed
    }

    {
      INFO("Remove keys");
      auto tx = kv_store.create_tx();
      auto set_handle = tx.rw(set);

      REQUIRE(set_handle->contains(k1));
      REQUIRE(set_handle->size() == 1);

      set_handle->remove(k2);
      REQUIRE(set_handle->contains(k1));
      REQUIRE(set_handle->size() == 1);

      set_handle->remove(k1);
      REQUIRE(!set_handle->contains(k1));
      REQUIRE(set_handle->size() == 0);

      // Not even locally committed, so globally_committed is unaffected
      REQUIRE(set_handle->contains_globally_committed(k1));
      REQUIRE(!set_handle->contains_globally_committed(k2));

      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    {
      INFO("Read committed removals");
      {
        auto tx = kv_store.create_tx();
        auto set_handle = tx.ro(set);
        // Removal is still only locally committed
        REQUIRE(set_handle->contains_globally_committed(k1));
        REQUIRE(!set_handle->contains_globally_committed(k2));
      }
      kv_store.compact(kv_store.current_version());
      {
        auto tx = kv_store.create_tx();
        auto set_handle = tx.ro(set);
        // Removal is now globally committed
        REQUIRE(!set_handle->contains_globally_committed(k1));
        REQUIRE(!set_handle->contains_globally_committed(k2));
      }
    }

    {
      INFO("Hooks");

      kv_store.compact(kv_store.current_version()); // Flush global hook

      std::vector<Set::Write> local_writes;
      std::vector<Set::Write> global_writes;

      auto map_hook = [&](
                        ccf::kv::Version v,
                        const Set::Write& w) -> ccf::kv::ConsensusHookPtr {
        local_writes.push_back(w);
        return ccf::kv::ConsensusHookPtr(nullptr);
      };
      auto global_hook = [&](ccf::kv::Version v, const Set::Write& w) {
        global_writes.push_back(w);
      };

      kv_store.set_map_hook(set.get_name(), set.wrap_map_hook(map_hook));
      kv_store.set_global_hook(
        set.get_name(), set.wrap_commit_hook(global_hook));

      {
        INFO("Insertion only");

        auto tx = kv_store.create_tx();
        auto set_handle = tx.rw(set);
        set_handle->insert(k1);
        set_handle->insert(k2);
        set_handle->remove(k2);
        REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

        REQUIRE(global_writes.size() == 0);
        REQUIRE(local_writes.size() == 1);
        const auto& latest_writes = local_writes.front();
        REQUIRE(latest_writes.at(k1).has_value());
        REQUIRE(!latest_writes.at(k2).has_value());
        REQUIRE(latest_writes.size() == 2);

        local_writes.clear();
      }

      {
        INFO("Insertion and removal");

        auto tx = kv_store.create_tx();
        auto set_handle = tx.rw(set);
        set_handle->remove(k1);
        set_handle->insert(k2);
        REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

        REQUIRE(local_writes.size() == 1);
        const auto& latest_writes = local_writes.front();
        REQUIRE(latest_writes.size() == 2);
        REQUIRE(!latest_writes.at(k1).has_value());
        REQUIRE(latest_writes.at(k2).has_value());

        local_writes.clear();
      }

      {
        INFO("Global hook");

        auto tx = kv_store.create_tx();
        auto set_handle = tx.rw(set);
        set_handle->insert(k1);
        REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

        kv_store.compact(kv_store.current_version());

        REQUIRE(global_writes.size() == 4);
        REQUIRE(global_writes.at(0).size() == 2);
        REQUIRE(!global_writes.at(0).at(k1).has_value());
        REQUIRE(!global_writes.at(0).at(k2).has_value());
        REQUIRE(global_writes.at(1).size() == 2);
        REQUIRE(global_writes.at(1).at(k1).has_value());
        REQUIRE(!global_writes.at(1).at(k2).has_value());
        REQUIRE(global_writes.at(2).size() == 2);
        REQUIRE(!global_writes.at(2).at(k1).has_value());
        REQUIRE(global_writes.at(2).at(k2).has_value());
        REQUIRE(global_writes.at(3).size() == 1);
        REQUIRE(global_writes.at(3).at(k1).has_value());
      }
    }
  }

  {
    INFO("ccf::kv::Value");
    using Value = ccf::kv::Value<std::string>;
    Value val1("public:value1");
    Value val2("public:value2");

    const auto v1 = "hello";
    const auto v2 = "world";
    const auto v3 = "saluton";

    {
      INFO("Read own writes");
      auto tx = kv_store.create_tx();

      auto h1 = tx.rw(val1);
      REQUIRE(!h1->has());
      h1->put(v1);
      REQUIRE(h1->has());
      REQUIRE(*h1->get() == v1);

      auto h2 = tx.rw(val2);
      REQUIRE(!h2->has());
      h2->put(v2);
      REQUIRE(h2->has());
      REQUIRE(*h2->get() == v2);

      h2->put(v3);
      REQUIRE(h2->has());
      REQUIRE(*h2->get() == v3);

      h2->clear();
      REQUIRE(!h2->has());

      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    {
      INFO("Read previous writes");
      auto tx = kv_store.create_tx();

      auto h1 = tx.ro(val1);
      REQUIRE(h1->has());
      REQUIRE(*h1->get() == v1);

      auto h2 = tx.rw(val2);
      REQUIRE(!h2->has());

      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    {
      INFO("Remove previous writes");
      auto tx = kv_store.create_tx();

      auto h1 = tx.rw(val1);
      REQUIRE(h1->has());
      h1->clear();
      REQUIRE(!h1->has());

      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    {
      INFO("Hooks");

      kv_store.compact(kv_store.current_version()); // Flush global hook

      std::vector<Value::Write> local_writes;
      std::vector<Value::Write> global_writes;

      auto map_hook = [&](
                        ccf::kv::Version v,
                        const Value::Write& w) -> ccf::kv::ConsensusHookPtr {
        local_writes.push_back(w);
        return ccf::kv::ConsensusHookPtr(nullptr);
      };
      auto global_hook = [&](ccf::kv::Version v, const Value::Write& w) {
        global_writes.push_back(w);
      };

      kv_store.set_map_hook(val1.get_name(), val1.wrap_map_hook(map_hook));
      kv_store.set_global_hook(
        val1.get_name(), val1.wrap_commit_hook(global_hook));

      {
        INFO("Local hook");

        {
          auto tx = kv_store.create_tx();
          REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
          REQUIRE(local_writes.size() == 0); // Commit without puts
        }

        {
          auto tx = kv_store.create_tx();
          auto h1 = tx.rw(val1);
          h1->put(v1);
          h1->put(v2); // Override previous value
          REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

          REQUIRE(global_writes.size() == 0);
          REQUIRE(local_writes.size() == 1);
          auto latest_writes = local_writes.front();
          REQUIRE(latest_writes.value() == v2);
          local_writes.clear();
        }

        {
          auto tx = kv_store.create_tx();
          auto h1 = tx.rw(val1);
          h1->clear();
          REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

          REQUIRE(local_writes.size() == 1);
          auto latest_writes = local_writes.front();
          REQUIRE(!latest_writes.has_value());
          local_writes.clear();
        }
      }

      {
        INFO("Global hook");

        auto tx = kv_store.create_tx();
        auto h1 = tx.rw(val1);
        h1->put(v3);
        REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

        kv_store.compact(kv_store.current_version());

        REQUIRE(global_writes.size() == 4);
        REQUIRE(!global_writes.at(0).has_value());
        REQUIRE(global_writes.at(1).value() == v2);
        REQUIRE(!global_writes.at(2).has_value());
        REQUIRE(global_writes.at(3).value() == v3);
      }
    }
  }

  {
    INFO("ccf::kv::UnitValue");
    using UnitValue = ccf::kv::UnitValue<>;
    UnitValue unit1("public:unit1");
    UnitValue unit2("public:unit2");

    {
      INFO("Read own writes");
      auto tx = kv_store.create_tx();

      auto h1 = tx.rw(unit1);
      REQUIRE(!h1->has());
      h1->touch();
      REQUIRE(h1->has());

      auto h2 = tx.rw(unit2);
      REQUIRE(!h2->has());
      h2->touch();
      REQUIRE(h2->has());

      h2->clear();
      REQUIRE(!h2->has());

      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    ccf::kv::Version commit_v = ccf::kv::NoVersion;
    {
      INFO("Read previous writes");
      auto tx = kv_store.create_tx();

      auto h1 = tx.ro(unit1);
      REQUIRE(h1->has());
      const auto ver = h1->get_version_of_previous_write();
      REQUIRE(ver.has_value());
      commit_v = ver.value();

      auto h2 = tx.rw(unit2);
      REQUIRE(!h2->has());
      REQUIRE(!h2->get_version_of_previous_write().has_value());

      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    {
      INFO("Remove previous writes");
      auto tx = kv_store.create_tx();

      auto h1 = tx.rw(unit1);
      REQUIRE(h1->has());
      REQUIRE(h1->get_version_of_previous_write() == commit_v);
      h1->clear();
      REQUIRE(!h1->has());

      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    {
      INFO("Hooks");

      kv_store.compact(kv_store.current_version());

      struct UnitValueHookWrite
      {
        ccf::kv::Version version;
        UnitValue::Write write;
      };

      std::vector<UnitValueHookWrite> local_writes;
      std::vector<UnitValueHookWrite> global_writes;

      auto map_hook = [&](ccf::kv::Version v, const UnitValue::Write& w)
        -> ccf::kv::ConsensusHookPtr {
        local_writes.emplace_back(UnitValueHookWrite({v, w}));
        return ccf::kv::ConsensusHookPtr(nullptr);
      };
      auto global_hook = [&](ccf::kv::Version v, const UnitValue::Write& w) {
        global_writes.emplace_back(UnitValueHookWrite({v, w}));
      };

      kv_store.set_map_hook(unit1.get_name(), unit1.wrap_map_hook(map_hook));
      kv_store.set_global_hook(
        unit1.get_name(), unit1.wrap_commit_hook(global_hook));

      {
        INFO("Local hook");

        {
          auto tx = kv_store.create_tx();
          REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
          REQUIRE(local_writes.empty());
        }

        {
          auto tx = kv_store.create_tx();
          auto h1 = tx.rw(unit1);
          h1->touch();
          REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
          const auto touch_version = tx.commit_version();

          REQUIRE(global_writes.empty());
          REQUIRE(local_writes.size() == 1);
          REQUIRE(local_writes.front().version == touch_version);
          REQUIRE(local_writes.front().write.has_value());
          REQUIRE(
            local_writes.front().write.value() ==
            ccf::kv::serialisers::ZeroBlitUnitCreator::get());
          local_writes.clear();
        }

        {
          auto tx = kv_store.create_tx();
          auto h1 = tx.rw(unit1);
          h1->clear();
          REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
          const auto clear_version = tx.commit_version();

          REQUIRE(local_writes.size() == 1);
          REQUIRE(local_writes.front().version == clear_version);
          REQUIRE(!local_writes.front().write.has_value());
          local_writes.clear();
        }
      }

      {
        INFO("Global hook");

        const auto compacted_before = kv_store.current_version();
        auto tx = kv_store.create_tx();
        auto h1 = tx.rw(unit1);
        h1->touch();
        REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
        const auto touch_version = tx.commit_version();

        kv_store.compact(kv_store.current_version());

        REQUIRE(global_writes.size() == 4);
        REQUIRE(global_writes.at(0).version == compacted_before - 2);
        REQUIRE(!global_writes.at(0).write.has_value());
        REQUIRE(global_writes.at(1).version == compacted_before - 1);
        REQUIRE(global_writes.at(1).write.has_value());
        REQUIRE(global_writes.at(2).version == compacted_before);
        REQUIRE(!global_writes.at(2).write.has_value());
        REQUIRE(global_writes.at(3).version == touch_version);
        REQUIRE(global_writes.at(3).write.has_value());
      }
    }
  }

  {
    // Sanity check that transactions can handle a mix of maps, sets, and values
    INFO("Mixed");

    using TMap = ccf::kv::Map<std::string, size_t>;
    using TSet = ccf::kv::Set<size_t>;
    ccf::kv::Value<std::string> map_name_val("public:map_name");
    ccf::kv::Value<std::string> set_name_val("public:set_name");

    constexpr auto n_entries = 10;

    {
      INFO("Writing");
      auto tx = kv_store.create_tx();

      auto map_name_handle = tx.rw(map_name_val);
      map_name_handle->put("public:my_test_map");

      auto set_name_handle = tx.rw(set_name_val);
      set_name_handle->put("public:values_from_my_test_map");

      auto map_handle = tx.rw<TMap>(*map_name_handle->get());
      auto set_handle = tx.rw<TSet>(*set_name_handle->get());
      for (size_t i = 0; i < n_entries; ++i)
      {
        const auto n = i * i;
        const char c[2] = {(char)('A' + i), 0};
        map_handle->put(std::string(c), n);
        set_handle->insert(n);
      }

      REQUIRE(map_handle->size() == n_entries);
      REQUIRE(set_handle->size() == n_entries);

      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    {
      INFO("Read and modify");
      auto tx = kv_store.create_tx();

      auto map_name_handle = tx.rw(map_name_val);
      REQUIRE(map_name_handle->has());

      auto set_name_handle = tx.rw(set_name_val);
      REQUIRE(set_name_handle->has());

      auto map_handle = tx.rw<TMap>(*map_name_handle->get());
      auto set_handle = tx.rw<TSet>(*set_name_handle->get());

      REQUIRE(map_handle->size() == n_entries);
      REQUIRE(set_handle->size() == n_entries);

      map_handle->foreach(
        [&map_handle, &set_handle](const std::string& k, const size_t& v) {
          REQUIRE(set_handle->contains(v));

          if (k[0] % 3 == 0)
          {
            map_handle->remove(k);
            set_handle->remove(v);

            const auto s = k + k;
            const auto n = ~v;
            map_handle->put(s, n);
            set_handle->insert(n);
          }

          return true;
        });

      REQUIRE(map_handle->size() == n_entries);
      REQUIRE(set_handle->size() == n_entries);

      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }
  }
}

TEST_CASE("MapDiff")
{
  // Use a raw-copy-serialised map so that the untyped diff's keys/values
  // (raw byte SerialisedEntry) match the typed strings byte-for-byte,
  // letting the test use plain strings throughout (including for range(),
  // which is only exposed on the untyped diff).
  using StringStringMap =
    ccf::kv::RawCopySerialisedMap<std::string, std::string>;

  ccf::kv::test::TestStoreBase kv_store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);
  StringStringMap map("public:map");

  SUBCASE("Diff of a transaction with no changes on the map")
  {
    auto tx = kv_store.create_tx();
    // Touch a different map, so the transaction has changes but not on `map`
    StringStringMap other("public:other");
    tx.rw(other)->put("k", "v");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

    auto tx_diff = kv_store.create_tx_diff();
    auto* diff = tx_diff.diff(map);
    REQUIRE(diff->size() == 0);
    REQUIRE_FALSE(diff->get("anything").has_value());
    REQUIRE_FALSE(diff->has("anything"));
    REQUIRE_FALSE(diff->is_deleted("anything"));
  }

  SUBCASE("Write, overwrite and remove")
  {
    {
      auto tx = kv_store.create_tx();
      auto handle = tx.rw(map);
      handle->put("written", "value1");
      handle->put("overwritten", "before");
      handle->put("removed", "to_be_removed");
      handle->put("untouched", "unchanged");
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    handle->put("overwritten", "after");
    handle->remove("removed");
    // "untouched" is neither read nor written by this transaction
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

    auto tx_diff = kv_store.create_tx_diff();
    auto* diff = tx_diff.diff(map);

    INFO("get()");
    {
      // No change made in this diff at all -> nullopt
      REQUIRE_FALSE(diff->get("written").has_value());
      REQUIRE_FALSE(diff->get("untouched").has_value());

      // Overwritten -> optional<optional<V>> engaged, holding the new value
      const auto overwritten = diff->get("overwritten");
      REQUIRE(overwritten.has_value());
      REQUIRE(overwritten.value().has_value());
      REQUIRE(overwritten.value().value() == "after");

      // Removed -> optional<optional<V>> engaged, holding nullopt
      const auto removed = diff->get("removed");
      REQUIRE(removed.has_value());
      REQUIRE_FALSE(removed.value().has_value());

      // Never present -> nullopt
      REQUIRE_FALSE(diff->get("never_present").has_value());
    }

    INFO("has()");
    {
      REQUIRE(diff->has("overwritten"));
      REQUIRE_FALSE(diff->has("removed"));
      REQUIRE_FALSE(diff->has("untouched"));
      REQUIRE_FALSE(diff->has("never_present"));
    }

    INFO("is_deleted()");
    {
      REQUIRE(diff->is_deleted("removed"));
      REQUIRE_FALSE(diff->is_deleted("overwritten"));
      REQUIRE_FALSE(diff->is_deleted("untouched"));
      REQUIRE_FALSE(diff->is_deleted("never_present"));
    }

    INFO("size()");
    {
      // Only overwritten and removed were touched by this transaction
      REQUIRE(diff->size() == 2);
    }

    INFO("foreach() with early-out");
    {
      size_t visited = 0;
      diff->foreach([&visited](const auto&, const auto&) {
        ++visited;
        return false;
      });
      REQUIRE(visited == 1);

      std::map<std::string, std::optional<std::string>> entries;
      diff->foreach([&entries](const auto& k, const auto& v) {
        entries[k] = v;
        return true;
      });
      REQUIRE(
        entries ==
        std::map<std::string, std::optional<std::string>>{
          {"overwritten", "after"}, {"removed", std::nullopt}});
    }

    INFO("foreach_key() with early-out");
    {
      size_t visited = 0;
      diff->foreach_key([&visited](const auto&) {
        ++visited;
        return false;
      });
      REQUIRE(visited == 1);

      std::set<std::string> keys;
      diff->foreach_key([&keys](const auto& k) {
        keys.insert(k);
        return true;
      });
      REQUIRE(keys == std::set<std::string>{"overwritten", "removed"});
    }

    INFO("foreach_value() with early-out");
    {
      size_t visited = 0;
      diff->foreach_value([&visited](const auto&) {
        ++visited;
        return false;
      });
      REQUIRE(visited == 1);

      // A deleted key's value is visited as nullopt
      std::multiset<std::optional<std::string>> values;
      diff->foreach_value([&values](const auto& v) {
        values.insert(v);
        return true;
      });
      REQUIRE(
        values ==
        std::multiset<std::optional<std::string>>{"after", std::nullopt});
    }
  }

  SUBCASE("range() over the untyped diff")
  {
    {
      auto tx = kv_store.create_tx();
      auto handle = tx.rw(map);
      handle->put("c", "to_be_removed");
      handle->put("z", "untouched");
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    {
      auto tx = kv_store.create_tx();
      auto handle = tx.rw(map);
      handle->put("a", "1");
      handle->put("b", "2");
      handle->remove("c");
      handle->put("d", "4");
      handle->put("e", "5");
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    // range() is only exposed on the untyped::MapDiff, not the typed wrapper.
    // Its keys and values are raw bytes, which match the plain strings used
    // here since this map uses raw-copy serialisation.
    auto tx_diff = kv_store.create_tx_diff();
    auto* untyped_diff = tx_diff.diff<ccf::kv::untyped::Map>(map.get_name());

    using Entries = std::map<std::string, std::optional<std::string>>;
    auto range = [untyped_diff](
                   const std::optional<std::string>& from,
                   const std::optional<std::string>& to) {
      auto to_entry = [](const std::optional<std::string>& s)
        -> std::optional<ccf::kv::serialisers::SerialisedEntry> {
        if (!s.has_value())
        {
          return std::nullopt;
        }
        return ccf::kv::serialisers::SerialisedEntry(s->begin(), s->end());
      };

      Entries visited;
      untyped_diff->range(
        [&visited](
          const ccf::kv::serialisers::SerialisedEntry& k,
          const std::optional<ccf::kv::serialisers::SerialisedEntry>& v) {
          const std::string key(k.begin(), k.end());
          REQUIRE_FALSE(visited.contains(key));
          if (v.has_value())
          {
            visited[key] = std::string(v->begin(), v->end());
          }
          else
          {
            visited[key] = std::nullopt;
          }
        },
        to_entry(from),
        to_entry(to));
      return visited;
    };

    INFO("Unbounded");
    REQUIRE(
      range(std::nullopt, std::nullopt) ==
      Entries{
        {"a", "1"}, {"b", "2"}, {"c", std::nullopt}, {"d", "4"}, {"e", "5"}});

    INFO("from is included, to is excluded");
    REQUIRE(range("b", "d") == Entries{{"b", "2"}, {"c", std::nullopt}});

    INFO("Bounds need not be present in the diff");
    REQUIRE(range("bb", "dd") == Entries{{"c", std::nullopt}, {"d", "4"}});

    INFO("Only a lower bound");
    REQUIRE(
      range("c", std::nullopt) ==
      Entries{{"c", std::nullopt}, {"d", "4"}, {"e", "5"}});

    INFO("Only an upper bound");
    REQUIRE(range(std::nullopt, "c") == Entries{{"a", "1"}, {"b", "2"}});

    INFO("Empty ranges");
    REQUIRE(range("c", "c").empty());
    REQUIRE(range("d", "b").empty());
    REQUIRE(range("x", std::nullopt).empty());
  }
}

TEST_CASE("Store clear")
{
  ccf::kv::test::TestStoreBase kv_store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);
  kv_store.initialise_term(42);

  auto map_a_name = "public:A";
  auto map_b_name = "public:B";
  MapTypes::StringNum map_a(map_a_name);
  MapTypes::StringNum map_b(map_b_name);

  INFO("Apply transactions and compact store");
  {
    size_t tx_count = 10;
    for (size_t i = 0; i < tx_count; i++)
    {
      auto tx = kv_store.create_tx();
      auto handle_a = tx.rw(map_a);
      auto handle_b = tx.rw(map_b);

      handle_a->put("key" + std::to_string(i), 42);
      handle_b->put("key" + std::to_string(i), 42);
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    auto current_version = kv_store.current_version();
    kv_store.compact(current_version);

    REQUIRE(ccf::kv::test::has_map_at(kv_store, current_version, map_a_name));
    REQUIRE(ccf::kv::test::has_map_at(kv_store, current_version, map_b_name));

    REQUIRE(kv_store.current_version() != 0);
    REQUIRE(kv_store.compacted_version() != 0);
    auto tx_id = kv_store.current_txid();
    REQUIRE(tx_id.view != 0);
    REQUIRE(tx_id.seqno != 0);
  }

  INFO("Verify that store state is cleared");
  {
    kv_store.clear();
    auto current_version = kv_store.current_version();

    REQUIRE(!ccf::kv::test::has_map_at(kv_store, current_version, map_a_name));
    REQUIRE(!ccf::kv::test::has_map_at(kv_store, current_version, map_b_name));

    REQUIRE(kv_store.current_version() == 0);
    REQUIRE(kv_store.compacted_version() == 0);
    auto tx_id = kv_store.current_txid();
    REQUIRE(tx_id.view == 0);
    REQUIRE(tx_id.seqno == 0);
  }
}

TEST_CASE("Map swap between stores")
{
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  ccf::kv::test::TestStoreBase s1;
  s1.set_encryptor(encryptor);

  ccf::kv::test::TestStoreBase s2;
  s2.set_encryptor(encryptor);

  MapTypes::NumNum d("data");
  MapTypes::NumNum pd("public:data");

  {
    auto tx = s1.create_tx();
    auto v = tx.rw(d);
    v->put(42, 42);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  {
    auto tx = s1.create_tx();
    auto v = tx.rw(pd);
    v->put(14, 14);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  const auto target_version = s1.current_version();
  while (s2.current_version() < target_version)
  {
    auto tx = s2.create_tx();
    auto v = tx.rw(d);
    v->put(41, 41);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  s2.swap_private_maps(s1);

  {
    auto tx = s1.create_tx();
    auto v = tx.rw(d);
    auto val = v->get(41);
    REQUIRE_FALSE(v->get(42).has_value());
    REQUIRE(val.has_value());
    REQUIRE(val.value() == 41);
  }

  {
    auto tx = s1.create_tx();
    auto v = tx.rw(pd);
    auto val = v->get(14);
    REQUIRE(val.has_value());
    REQUIRE(val.value() == 14);
  }

  {
    auto tx = s2.create_tx();
    auto v = tx.rw(d);
    auto val = v->get(42);
    REQUIRE_FALSE(v->get(41).has_value());
    REQUIRE(val.has_value());
    REQUIRE(val.value() == 42);
  }

  {
    auto tx = s2.create_tx();
    auto v = tx.rw(pd);
    REQUIRE_FALSE(v->get(14).has_value());
  }
}

TEST_CASE("Private recovery map swap")
{
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  ccf::kv::test::TestStoreBase s1;
  s1.set_encryptor(encryptor);
  MapTypes::NumNum priv1("private");
  MapTypes::NumString pub1("public:data");

  ccf::kv::test::TestStoreBase s2;
  s2.set_encryptor(encryptor);
  MapTypes::NumNum priv2("private");
  MapTypes::NumString pub2("public:data");

  INFO("Populate s1 with public entries");
  // We compact twice, deliberately. A public KV during recovery
  // would have compacted some number of times.
  {
    auto tx = s1.create_tx();
    auto v = tx.rw(pub1);
    v->put(42, "42");
    tx.commit();
  }
  {
    auto tx = s1.create_tx();
    auto v = tx.rw(pub1);
    v->put(42, "43");
    tx.commit();
  }
  s1.compact(s1.current_version());
  {
    auto tx = s1.create_tx();
    auto v = tx.rw(pub1);
    v->put(44, "44");
    tx.commit();
  }
  s1.compact(s1.current_version());
  {
    auto tx = s1.create_tx();
    auto v = tx.rw(pub1);
    v->put(45, "45");
    tx.commit();
  }

  INFO("Populate s2 with private entries");
  // We compact only once, at a lower index than we did for the public
  // KV, which is what we expect during recovery of the private KV. We do expect
  // that the _entire_ private state is compacted
  {
    auto tx = s2.create_tx();
    auto v = tx.rw(priv2);
    v->put(12, 12);
    tx.commit();
  }
  {
    auto tx = s2.create_tx();
    auto v = tx.rw(priv2);
    v->put(13, 13);
    tx.commit();
  }
  s2.compact(s2.current_version());
  {
    auto tx = s2.create_tx();
    auto v = tx.rw(priv2);
    v->put(14, 14);
    tx.commit();
  }
  {
    auto tx = s2.create_tx();
    auto v = tx.rw(priv2);
    v->put(15, 15);
    tx.commit();
  }

  INFO("Swap in private maps");
  REQUIRE(s1.current_version() == s2.current_version());
  REQUIRE_NOTHROW(s1.swap_private_maps(s2));

  INFO("Check state looks as expected in s1");
  {
    auto tx = s1.create_tx();
    auto priv = tx.rw(priv1);
    auto pub = tx.rw(pub1);
    {
      auto val = pub->get(42);
      REQUIRE(val.has_value());
      REQUIRE(val.value() == "43");

      val = pub->get(44);
      REQUIRE(val.has_value());
      REQUIRE(val.value() == "44");

      val = pub->get(45);
      REQUIRE(val.has_value());
      REQUIRE(val.value() == "45");

      REQUIRE(s1.compacted_version() == 3);
    }
    {
      for (size_t i : {12, 13, 14, 15})
      {
        auto val = priv->get(i);
        REQUIRE(val.has_value());
        REQUIRE(val.value() == i);
      }
    }
  }

  INFO("Check committed state looks as expected in s1");
  {
    auto tx = s1.create_tx();
    auto priv = tx.rw(priv1);
    auto pub = tx.rw(pub1);
    {
      auto val = pub->get_globally_committed(42);
      REQUIRE(val.has_value());
      REQUIRE(val.value() == "43");

      val = pub->get_globally_committed(44);
      REQUIRE(val.has_value());
      REQUIRE(val.value() == "44");

      val = pub->get_globally_committed(45);
      REQUIRE_FALSE(val.has_value());
    }
    {
      auto val = priv->get_globally_committed(12);
      REQUIRE(val.has_value());
      REQUIRE(val.value() == 12);

      val = priv->get_globally_committed(13);
      REQUIRE(val.has_value());
      REQUIRE(val.value() == 13);

      // Uncompacted state is visible, which is expected, but isn't
      // something that would happen in recovery (only compacted state
      // would be swapped in). There is deliberately no check for compacted
      // state later than the compact level on the public KV, as this is
      // impossible during recovery.
    }
  }
}

TEST_CASE("Swapping dynamic maps" * doctest::test_suite("dynamic"))
{
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();

  ccf::kv::test::TestStoreBase s1;
  s1.set_encryptor(encryptor);

  {
    auto tx = s1.create_tx();
    auto v0 = tx.rw<MapTypes::StringString>("foo");
    auto v1 = tx.rw<MapTypes::NumString>("bar");
    v0->put("hello", "world");
    v1->put(42, "everything");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  {
    auto tx = s1.create_tx();
    auto v0 = tx.rw<MapTypes::StringString>("foo");
    auto v1 = tx.rw<MapTypes::StringNum>("baz");
    v0->put("hello", "goodbye");
    v1->put("saluton", 100);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  {
    // Create _public_ state in source store
    auto tx = s1.create_tx();
    auto v0 = tx.rw<MapTypes::StringString>("public:source_state");
    v0->put("store", "source");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  ccf::kv::test::TestStoreBase s2;
  s2.set_encryptor(encryptor);

  // Ensure source store is at _at least_ the same version as source store
  while (s2.current_version() < s1.current_version())
  {
    // Create public state in target store, to confirm it is unaffected
    auto tx = s2.create_tx();
    auto v0 = tx.rw<MapTypes::StringString>("public:target_state");
    v0->put("store", "target");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  s1.compact(s1.current_version());

  s2.swap_private_maps(s1);

  {
    INFO("Private state is transferred");
    auto tx = s2.create_tx();

    auto v0 = tx.rw<MapTypes::StringString>("foo");
    auto v1 = tx.rw<MapTypes::NumString>("bar");
    auto v2 = tx.rw<MapTypes::StringNum>("baz");

    const auto val0 = v0->get("hello");
    REQUIRE(val0.has_value());
    REQUIRE(val0.value() == "goodbye");

    const auto val1 = v1->get(42);
    REQUIRE(val1.has_value());
    REQUIRE(val1.value() == "everything");

    const auto val2 = v2->get("saluton");
    REQUIRE(val2.has_value());
    REQUIRE(val2.value() == 100);
  }

  {
    INFO("Public state is untouched");
    auto tx = s2.create_tx();

    auto v0 = tx.rw<MapTypes::StringString>("public:source_state");
    auto v1 = tx.rw<MapTypes::StringString>("public:target_state");

    const auto val0 = v0->get("store");
    REQUIRE_FALSE(val0.has_value());

    const auto val1 = v1->get("store");
    REQUIRE(val1.has_value());
    REQUIRE(val1.value() == "target");
  }
}
