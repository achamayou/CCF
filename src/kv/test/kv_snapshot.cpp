// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "kv/kv_serialiser.h"
#include "kv/null_encryptor.h"
#include "kv/store.h"
#include "node/encryptor.h"

#include <algorithm>
#include <cstring>
#include <doctest/doctest.h>
#include <functional>
#undef FAIL
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

struct MapTypes
{
  using StringString = ccf::kv::Map<std::string, std::string>;
  using NumNum = ccf::kv::Map<size_t, size_t>;
  using StringValue = ccf::kv::Value<std::string>;
  using StringSet = ccf::kv::Set<std::string>;
};

MapTypes::StringString string_map("public:string_map");
MapTypes::NumNum num_map("public:num_map");

namespace
{
  using MapSnapshots =
    std::vector<std::unique_ptr<ccf::kv::AbstractMap::Snapshot>>;

  MapSnapshots snapshot_maps(
    ccf::kv::Store& store,
    ccf::kv::Version version,
    const std::vector<std::string>& names)
  {
    ccf::kv::ScopedStoreMapsLock maps_lock(&store);
    MapSnapshots snapshots;
    for (const auto& name : names)
    {
      auto map = store.get_map_unsafe(version, name);
      REQUIRE(map != nullptr);
      snapshots.push_back(map->snapshot(version));
    }
    return snapshots;
  }

  // Serialises a snapshot's contents as StoreSnapshot::serialise() did before
  // snapshots were serialised in place: into a buffer for each domain, which
  // are then copied into the entry, encrypting the private domain (with
  // historical_hint, which StoreSnapshot::serialise() always sets)
  std::vector<uint8_t> serialise_buffered(
    const std::shared_ptr<ccf::kv::AbstractTxEncryptor>& encryptor,
    ccf::kv::Version version,
    const std::optional<std::vector<uint8_t>>& hash_at_snapshot,
    const std::optional<std::vector<ccf::kv::Version>>& view_history,
    const MapSnapshots& maps,
    bool historical_hint = true)
  {
    ccf::kv::RawKvStoreSerialiser serialiser(
      encryptor,
      {0, version},
      ccf::kv::EntryType::Snapshot,
      0,
      {},
      ccf::no_claims(),
      historical_hint);
    if (hash_at_snapshot.has_value())
    {
      serialiser.serialise_raw(hash_at_snapshot.value());
    }
    if (view_history.has_value())
    {
      serialiser.serialise_view_history(view_history.value());
    }
    for (const auto domain :
         {ccf::kv::SecurityDomain::PUBLIC, ccf::kv::SecurityDomain::PRIVATE})
    {
      for (const auto& map : maps)
      {
        if (map->get_security_domain() == domain)
        {
          map->serialise(serialiser);
        }
      }
    }
    return serialiser.get_raw_data();
  }

  // Requires that a snapshot of the given maps of store, at its current
  // version, is serialised in place exactly as it was through per-domain
  // buffers, and decodes to its contents
  void require_serialised_in_place(
    ccf::kv::Store& store,
    const std::shared_ptr<ccf::kv::AbstractTxEncryptor>& encryptor,
    const std::vector<std::string>& names,
    const std::optional<std::vector<uint8_t>>& hash_at_snapshot,
    const std::optional<std::vector<ccf::kv::Version>>& view_history)
  {
    const auto version = store.current_version();
    ccf::kv::StoreSnapshot snapshot(version);
    for (auto& map : snapshot_maps(store, version, names))
    {
      snapshot.add_map_snapshot(std::move(map));
    }
    if (hash_at_snapshot.has_value())
    {
      snapshot.add_hash_at_snapshot(
        std::vector<uint8_t>(hash_at_snapshot.value()));
    }
    if (view_history.has_value())
    {
      snapshot.add_view_history(
        std::vector<ccf::kv::Version>(view_history.value()));
    }
    const auto in_place = snapshot.serialise(encryptor);

    REQUIRE(
      in_place ==
      serialise_buffered(
        encryptor,
        version,
        hash_at_snapshot,
        view_history,
        snapshot_maps(store, version, names)));

    // The entry decodes to the snapshot's contents, in order
    ccf::kv::RawKvStoreDeserialiser d(encryptor);
    ccf::kv::Term term = 0;
    ccf::kv::EntryFlags flags = {};
    REQUIRE(
      d.init(in_place.data(), in_place.size(), term, flags, true) == version);
    if (hash_at_snapshot.has_value())
    {
      REQUIRE(d.deserialise_raw() == hash_at_snapshot.value());
    }
    if (view_history.has_value())
    {
      REQUIRE(d.deserialise_view_history() == view_history.value());
    }
    for (const auto& name : names)
    {
      REQUIRE(d.start_map() == name);
      REQUIRE(d.deserialise_entry_version() == version);
      REQUIRE_FALSE(d.deserialise_raw().empty());
    }
    REQUIRE_FALSE(d.start_map().has_value());
  }
}

TEST_CASE(
  "Snapshot serialised in place matches buffered serialisation" *
  doctest::test_suite("snapshot"))
{
  auto secrets = std::make_shared<ccf::LedgerSecrets>();
  secrets->init();
  const std::vector<
    std::pair<std::string, std::shared_ptr<ccf::kv::AbstractTxEncryptor>>>
    encryptors{
      {"none", nullptr},
      {"null", std::make_shared<ccf::kv::NullTxEncryptor>()},
      {"node", std::make_shared<ccf::NodeEncryptor>(secrets)}};
  const std::vector<uint8_t> hash_at_snapshot(32, 0x48);
  const std::vector<ccf::kv::Version> view_history{1, 5, 9};

  for (const auto& config : encryptors)
  {
    const auto& encryptor_name = config.first;
    const auto& encryptor = config.second;
    INFO(encryptor_name);
    // Private maps cannot be serialised without an encryptor
    const bool can_encrypt = encryptor != nullptr;

    ccf::kv::Store store;
    // Transactions cannot be committed without an encryptor, but snapshots
    // can be serialised without one
    store.set_encryptor(
      can_encrypt ? encryptor : std::make_shared<ccf::kv::NullTxEncryptor>());
    MapTypes::StringString private_map("private_map");
    {
      auto tx = store.create_tx();
      for (size_t i = 0; i < 100; ++i)
      {
        tx.rw(string_map)->put(fmt::format("pub{}", i), std::string(i, 'p'));
        if (can_encrypt)
        {
          tx.rw(private_map)
            ->put(fmt::format("priv{}", i), std::string(i, 's'));
        }
      }
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    // Snapshots of either domain, both or neither, with or without the
    // Merkle tree leaf and view history which a node adds to its snapshots
    for (const bool with_public : {false, true})
    {
      for (const bool with_private : {false, true})
      {
        if (with_private && !can_encrypt)
        {
          continue;
        }

        for (const bool with_history : {false, true})
        {
          INFO(with_public);
          INFO(with_private);
          INFO(with_history);
          std::vector<std::string> names;
          if (with_public)
          {
            names.emplace_back("public:string_map");
          }
          if (with_private)
          {
            names.emplace_back("private_map");
          }
          require_serialised_in_place(
            store,
            encryptor,
            names,
            with_history ? std::make_optional(hash_at_snapshot) : std::nullopt,
            with_history ? std::make_optional(view_history) : std::nullopt);
        }
      }
    }
  }
}

TEST_CASE(
  "Snapshot is encrypted with the ledger secret for its version" *
  doctest::test_suite("snapshot"))
{
  const auto first_secret = ccf::make_ledger_secret();
  const auto second_secret = ccf::make_ledger_secret();
  auto secrets = std::make_shared<ccf::LedgerSecrets>();
  secrets->init_from_map({{1, first_secret}});
  auto encryptor = std::make_shared<ccf::NodeEncryptor>(secrets);
  ccf::kv::Store store;
  store.set_encryptor(encryptor);

  MapTypes::StringString private_map("private_map");
  const auto write = [&](const std::string& value) {
    auto tx = store.create_tx();
    tx.rw(string_map)->put("public", value);
    tx.rw(private_map)->put("private", value);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    return tx.commit_version();
  };
  const auto version = write("snapshotted");
  const std::vector<std::string> names{"public:string_map", "private_map"};
  ccf::kv::StoreSnapshot snapshot(version);
  for (auto& map : snapshot_maps(store, version, names))
  {
    snapshot.add_map_snapshot(std::move(map));
  }
  const auto maps = snapshot_maps(store, version, names);

  // The service is rekeyed after the snapshot's version, and encrypts a later
  // transaction with the new ledger secret before the snapshot is serialised
  secrets->set_secret(version + 1, ccf::LedgerSecretPtr(second_secret));
  REQUIRE(write("later") == version + 1);

  // The snapshot is still encrypted with the ledger secret for its version,
  // rather than the one now used for new transactions
  const auto entry = snapshot.serialise(encryptor);
  REQUIRE(
    entry ==
    serialise_buffered(encryptor, version, std::nullopt, std::nullopt, maps));
  REQUIRE(
    entry !=
    serialise_buffered(
      encryptor, version, std::nullopt, std::nullopt, maps, false));

  // so that a node with both ledger secrets, e.g. joining or recovering the
  // service, can install it
  auto node_secrets = std::make_shared<ccf::LedgerSecrets>();
  node_secrets->init_from_map(
    {{1, first_secret}, {version + 1, second_secret}});
  ccf::kv::Store node_store;
  node_store.set_encryptor(std::make_shared<ccf::NodeEncryptor>(node_secrets));
  ccf::kv::ConsensusHookPtrs hooks;
  REQUIRE(
    node_store.deserialise_snapshot(entry.data(), entry.size(), hooks) ==
    ccf::kv::ApplyResult::PASS);
  auto tx = node_store.create_read_only_tx();
  REQUIRE(tx.ro(string_map)->get("public") == "snapshotted");
  REQUIRE(tx.ro(private_map)->get("private") == "snapshotted");
}

TEST_CASE(
  "Snapshot finalised in place cannot be encrypted again" *
  doctest::test_suite("snapshot"))
{
  auto secrets = std::make_shared<ccf::LedgerSecrets>();
  secrets->init();
  auto encryptor = std::make_shared<ccf::NodeEncryptor>(secrets);
  ccf::kv::Store store;
  store.set_encryptor(encryptor);

  MapTypes::StringString private_map("private_map");
  {
    auto tx = store.create_tx();
    tx.rw(string_map)->put("public", "value");
    tx.rw(private_map)->put("private", "secret");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }
  const auto version = store.current_version();
  const ccf::TxID tx_id{0, version};

  auto serialise_maps = [&](ccf::kv::KvStoreSerialiser& s) {
    for (const auto* name : {"public:string_map", "private_map"})
    {
      auto map = store.get_map_unsafe(version, name);
      REQUIRE(map != nullptr);
      map->snapshot(version)->serialise(s);
    }
  };

  // As StoreSnapshot::serialise(): measure, then serialise in place
  ccf::kv::SizeKvStoreSerialiser sizer(
    encryptor,
    tx_id,
    ccf::kv::EntryType::Snapshot,
    0,
    {},
    ccf::no_claims(),
    true);
  serialise_maps(sizer);
  const auto public_size = sizer.get_public_domain_size();
  const auto offset =
    ccf::kv::SpanKvStoreSerialiser::public_domain_offset(encryptor);
  const auto private_offset = offset + public_size;

  std::vector<uint8_t> entry(sizer.get_serialised_size());
  const auto entry_span = std::span<uint8_t>(entry);
  ccf::kv::SpanKvStoreSerialiser serialiser(
    ccf::kv::SpanWriter(entry_span.subspan(offset, public_size)),
    ccf::kv::SpanWriter(entry_span.subspan(private_offset)),
    encryptor,
    tx_id,
    ccf::kv::EntryType::Snapshot,
    0,
    {},
    ccf::no_claims(),
    true);
  serialise_maps(serialiser);

  auto private_domain = [&]() {
    const auto domain = entry_span.subspan(private_offset);
    return std::vector<uint8_t>(domain.begin(), domain.end());
  };
  const auto private_plaintext = private_domain();

  serialiser.finalise_in_place(entry_span);
  REQUIRE(private_domain() != private_plaintext);
  const auto finalised = entry;

  // The private domain was encrypted in place, with an IV determined by the
  // transaction ID, so encrypting it again would restore the plaintext
  REQUIRE_THROWS_AS(serialiser.finalise_in_place(entry_span), std::logic_error);
  REQUIRE_THROWS_AS(serialiser.get_raw_data(), std::logic_error);
  REQUIRE(entry == finalised);

  ccf::kv::Store new_store;
  new_store.set_encryptor(encryptor);
  ccf::kv::ConsensusHookPtrs hooks;
  REQUIRE(
    new_store.deserialise_snapshot(entry.data(), entry.size(), hooks) ==
    ccf::kv::ApplyResult::PASS);
  auto tx = new_store.create_read_only_tx();
  REQUIRE(tx.ro(string_map)->get("public") == "value");
  REQUIRE(tx.ro(private_map)->get("private") == "secret");
}

namespace
{
  // Writes a public and a private map's worth of data
  void serialise_test_maps(ccf::kv::KvStoreSerialiser& s)
  {
    s.start_map("public:map", ccf::kv::SecurityDomain::PUBLIC);
    s.serialise_raw(std::vector<uint8_t>(10, 0x11));
    s.start_map("map", ccf::kv::SecurityDomain::PRIVATE);
    s.serialise_raw(std::vector<uint8_t>(10, 0x22));
  }

  // An entry whose domains have been serialised in place, as by
  // StoreSnapshot::serialise(), but which has not been finalised. If
  // domain_elsewhere is set, that domain is serialised into elsewhere instead
  // of the entry.
  struct InPlaceEntry
  {
    std::vector<uint8_t> entry;
    std::vector<uint8_t> elsewhere;
    std::unique_ptr<ccf::kv::SpanKvStoreSerialiser> serialiser;

    InPlaceEntry(
      const std::shared_ptr<ccf::kv::AbstractTxEncryptor>& encryptor,
      size_t max_transaction_size = ccf::kv::max_serialised_entry_size,
      std::optional<ccf::kv::SecurityDomain> domain_elsewhere = std::nullopt)
    {
      const ccf::TxID tx_id{0, 1};
      ccf::kv::SizeKvStoreSerialiser sizer(
        encryptor, tx_id, ccf::kv::EntryType::Snapshot, 0);
      serialise_test_maps(sizer);
      const auto public_size = sizer.get_public_domain_size();
      const auto offset =
        ccf::kv::SpanKvStoreSerialiser::public_domain_offset(encryptor);
      entry.resize(sizer.get_serialised_size());
      const auto span = std::span<uint8_t>(entry);
      auto public_domain = span.subspan(offset, public_size);
      auto private_domain = span.subspan(offset + public_size);
      if (domain_elsewhere.has_value())
      {
        auto& moved = domain_elsewhere == ccf::kv::SecurityDomain::PUBLIC ?
          public_domain :
          private_domain;
        elsewhere.resize(moved.size());
        moved = elsewhere;
      }
      serialiser = std::make_unique<ccf::kv::SpanKvStoreSerialiser>(
        ccf::kv::SpanWriter(public_domain),
        ccf::kv::SpanWriter(private_domain),
        encryptor,
        tx_id,
        ccf::kv::EntryType::Snapshot,
        0,
        ccf::crypto::Sha256Hash{},
        ccf::no_claims(),
        true,
        max_transaction_size);
      serialise_test_maps(*serialiser);
    }
  };
}

TEST_CASE(
  "Snapshot finalised in place rejects invalid entries" *
  doctest::test_suite("snapshot"))
{
  auto secrets = std::make_shared<ccf::LedgerSecrets>();
  secrets->init();
  auto encryptor = std::make_shared<ccf::NodeEncryptor>(secrets);

  {
    // An entry of the wrong size is left as it was
    InPlaceEntry e(encryptor);
    const auto before = e.entry;
    REQUIRE_THROWS_WITH_AS(
      e.serialiser->finalise_in_place(
        std::span<uint8_t>(e.entry).first(e.entry.size() - 1)),
      doctest::Contains("does not match serialised size"),
      std::logic_error);
    REQUIRE(e.entry == before);

    // Finalisation is attempted at most once, even if it fails
    REQUIRE_THROWS_WITH_AS(
      e.serialiser->finalise_in_place(e.entry),
      doctest::Contains("already finalised"),
      std::logic_error);
    REQUIRE(e.entry == before);
  }

  {
    // An entry of the right size, other than the one which the domains were
    // serialised into, is left as it was, as is that one
    InPlaceEntry e(encryptor);
    const auto before = e.entry;
    std::vector<uint8_t> other(e.entry.size());
    REQUIRE_THROWS_WITH_AS(
      e.serialiser->finalise_in_place(other),
      doctest::Contains("not serialised in place"),
      std::logic_error);
    REQUIRE(other == std::vector<uint8_t>(e.entry.size()));
    REQUIRE(e.entry == before);
  }

  for (const auto domain :
       {ccf::kv::SecurityDomain::PUBLIC, ccf::kv::SecurityDomain::PRIVATE})
  {
    // An entry with either domain serialised elsewhere is left as it was, as
    // is that domain
    const auto* domain_name =
      domain == ccf::kv::SecurityDomain::PUBLIC ? "public" : "private";
    INFO(domain_name);
    InPlaceEntry e(encryptor, ccf::kv::max_serialised_entry_size, domain);
    const auto before = e.entry;
    const auto elsewhere_before = e.elsewhere;
    REQUIRE_THROWS_WITH_AS(
      e.serialiser->finalise_in_place(e.entry),
      doctest::Contains("not serialised in place"),
      std::logic_error);
    REQUIRE(e.entry == before);
    REQUIRE(e.elsewhere == elsewhere_before);
  }

  {
    // An entry larger than the maximum transaction size, which is inclusive
    const auto entry_size = InPlaceEntry(encryptor).entry.size();
    InPlaceEntry too_large(encryptor, entry_size - 1);
    const auto before = too_large.entry;
    REQUIRE_THROWS_AS(
      too_large.serialiser->finalise_in_place(too_large.entry),
      ccf::kv::KvSerialiserException);
    REQUIRE(too_large.entry == before);

    InPlaceEntry largest(encryptor, entry_size);
    REQUIRE_NOTHROW(largest.serialiser->finalise_in_place(largest.entry));
  }

  {
    // Encryption fails, as there is no ledger secret to encrypt with
    InPlaceEntry e(std::make_shared<ccf::NodeEncryptor>(
      std::make_shared<ccf::LedgerSecrets>()));
    REQUIRE_THROWS_AS(
      e.serialiser->finalise_in_place(e.entry), ccf::kv::KvSerialiserException);
  }

  {
    // Private data is never written unencrypted. start_map() prevents private
    // maps from being serialised without an encryptor, but a private writer
    // which already holds data may be supplied.
    const ccf::TxID tx_id{0, 1};
    ccf::kv::SizeKvStoreSerialiser sizer(
      nullptr, tx_id, ccf::kv::EntryType::Snapshot, 0);
    const auto public_size = sizer.get_public_domain_size();
    const auto offset =
      ccf::kv::SpanKvStoreSerialiser::public_domain_offset(nullptr);
    std::vector<uint8_t> entry(offset + public_size + 1);
    const auto span = std::span<uint8_t>(entry);
    ccf::kv::SpanWriter private_writer(span.subspan(offset + public_size));
    private_writer.append(uint8_t{0x22});
    ccf::kv::SpanKvStoreSerialiser serialiser(
      ccf::kv::SpanWriter(span.subspan(offset, public_size)),
      ccf::kv::SpanWriter(private_writer),
      nullptr,
      tx_id,
      ccf::kv::EntryType::Snapshot,
      0);
    const auto before = entry;
    REQUIRE_THROWS_WITH_AS(
      serialiser.finalise_in_place(entry),
      doctest::Contains("without an encryptor"),
      std::logic_error);
    REQUIRE(entry == before);
  }
}

namespace
{
  // A map snapshot whose serialised payload has the given size each time it
  // is serialised. A real map snapshot cannot change size between the passes
  // which measure and then write a snapshot: it is an immutable copy of the
  // map's state.
  class ResizingMapSnapshot : public ccf::kv::AbstractMap::Snapshot
  {
  private:
    ccf::kv::SecurityDomain domain;
    std::vector<size_t> payload_sizes;
    size_t serialisations = 0;

  public:
    ResizingMapSnapshot(
      ccf::kv::SecurityDomain domain_, std::vector<size_t> payload_sizes_) :
      domain(domain_),
      payload_sizes(std::move(payload_sizes_))
    {}

    static std::string map_name(ccf::kv::SecurityDomain map_domain)
    {
      return map_domain == ccf::kv::SecurityDomain::PUBLIC ? "public:map" :
                                                             "map";
    }

    void serialise(ccf::kv::KvStoreSerialiser& s) override
    {
      s.start_map(map_name(domain), domain);
      s.serialise_entry_version(1);
      s.serialise_raw_in_place(
        payload_sizes.at(serialisations++), [](std::span<uint8_t> payload) {
          std::ranges::fill(payload, uint8_t{0x42});
        });
    }

    [[nodiscard]] ccf::kv::SecurityDomain get_security_domain() const override
    {
      return domain;
    }
  };
}

TEST_CASE(
  "Snapshot serialisation rejects maps which change between passes" *
  doctest::test_suite("snapshot"))
{
  auto secrets = std::make_shared<ccf::LedgerSecrets>();
  secrets->init();
  auto encryptor = std::make_shared<ccf::NodeEncryptor>(secrets);
  constexpr ccf::kv::Version version = 1;

  const auto serialise =
    [&](ccf::kv::SecurityDomain domain, std::vector<size_t> payload_sizes) {
      ccf::kv::StoreSnapshot snapshot(version);
      snapshot.add_map_snapshot(std::make_unique<ResizingMapSnapshot>(
        domain, std::move(payload_sizes)));
      return snapshot.serialise(encryptor);
    };

  for (const auto domain :
       {ccf::kv::SecurityDomain::PUBLIC, ccf::kv::SecurityDomain::PRIVATE})
  {
    const auto name = ResizingMapSnapshot::map_name(domain);
    INFO(name);

    // A map which writes more than was measured cannot write beyond its
    // domain's region of the entry
    REQUIRE_THROWS_WITH_AS(
      serialise(domain, {16, 17}),
      doctest::Contains("capacity"),
      std::length_error);

    // and one which writes less cannot leave part of that region unwritten
    REQUIRE_THROWS_WITH_AS(
      serialise(domain, {16, 15}),
      doctest::Contains("but measured"),
      std::logic_error);

    // A map which writes what was measured is written in place
    const auto entry = serialise(domain, {16, 16});
    ccf::kv::RawKvStoreDeserialiser d(encryptor);
    ccf::kv::Term term = 0;
    ccf::kv::EntryFlags flags = {};
    REQUIRE(d.init(entry.data(), entry.size(), term, flags, true) == version);
    REQUIRE(d.start_map() == name);
    REQUIRE(d.deserialise_entry_version() == 1);
    REQUIRE(d.deserialise_raw() == std::vector<uint8_t>(16, 0x42));
    REQUIRE_FALSE(d.start_map().has_value());
  }
}
