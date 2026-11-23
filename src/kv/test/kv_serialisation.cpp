// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ds/internal_logger.h"
#include "kv/kv_serialiser.h"
#include "kv/null_encryptor.h"
#include "kv/raw_serialise.h"
#include "kv/store.h"
#include "kv/test/stub_consensus.h"
#include "node/encryptor.h"

#include <doctest/doctest.h>
#undef FAIL
#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <numeric>
#include <span>
#include <string>
#include <tuple>
#include <vector>

struct MapTypes
{
  using StringString = ccf::kv::Map<std::string, std::string>;
  using NumNum = ccf::kv::Map<size_t, size_t>;
  using NumString = ccf::kv::Map<size_t, std::string>;
  using StringNum = ccf::kv::Map<std::string, size_t>;
};

static std::vector<uint8_t> make_size_prefixed_bytes(
  size_t declared_size, size_t actual_size)
{
  std::vector<uint8_t> bytes(sizeof(size_t) + actual_size);
  std::memcpy(bytes.data(), &declared_size, sizeof(declared_size));
  return bytes;
}

TEST_CASE(
  "Raw reader rejects truncated entries" * doctest::test_suite("serialisation"))
{
  SUBCASE("Fixed-size integral")
  {
    std::vector<uint8_t> bytes(sizeof(uint64_t) - 1);
    ccf::kv::RawReader reader(bytes);
    REQUIRE_THROWS(reader.read_next<uint64_t>());
  }

  SUBCASE("Fixed-size array")
  {
    std::vector<uint8_t> bytes(ccf::crypto::Sha256Hash::SIZE - 1);
    ccf::kv::RawReader reader(bytes);
    REQUIRE_THROWS(reader.read_next<ccf::crypto::Sha256Hash::Representation>());
  }

  SUBCASE("Short size prefix")
  {
    std::vector<uint8_t> bytes(sizeof(size_t) - 1);
    ccf::kv::RawReader reader(bytes);
    REQUIRE_THROWS(reader.read_next<std::vector<uint8_t>>());
  }

  SUBCASE("Prefix without payload")
  {
    auto bytes = make_size_prefixed_bytes(1, 0);
    ccf::kv::RawReader reader(bytes);
    REQUIRE_THROWS(reader.read_next<std::vector<uint8_t>>());
  }

  SUBCASE("Nine bytes remaining declare two payload bytes")
  {
    auto bytes = make_size_prefixed_bytes(2, 1);
    ccf::kv::RawReader reader(bytes);
    REQUIRE_THROWS(reader.read_next<std::vector<uint8_t>>());
  }

  SUBCASE("Span of more payload bytes than remain")
  {
    auto bytes = make_size_prefixed_bytes(2, 1);
    ccf::kv::RawReader reader(bytes);
    REQUIRE_THROWS(reader.read_next_span());
  }

  SUBCASE("Impossible payload length")
  {
    auto bytes =
      make_size_prefixed_bytes(std::numeric_limits<size_t>::max(), 0);
    ccf::kv::RawReader reader(bytes);
    REQUIRE_THROWS(reader.read_next<std::vector<uint8_t>>());
  }

  SUBCASE("Payload is not a whole number of elements")
  {
    auto bytes = make_size_prefixed_bytes(1, 1);
    ccf::kv::RawReader reader(bytes);
    REQUIRE_THROWS(reader.read_next<std::vector<uint64_t>>());
  }

  SUBCASE("Default-constructed reader is immediately at end of stream")
  {
    ccf::kv::RawReader reader;
    REQUIRE(reader.is_eos());
    REQUIRE_THROWS(reader.read_next<uint64_t>());
  }
}

static std::vector<uint8_t> make_public_domain_entry(
  size_t declared_public_domain_size, const std::vector<uint8_t>& public_domain)
{
  ccf::kv::SerialisedEntryHeader header;
  header.set_size(sizeof(size_t) + public_domain.size());
  std::vector<uint8_t> entry(sizeof(header) + header.size);
  auto* data = entry.data();
  auto remaining = entry.size();
  serialized::write(data, remaining, header);
  serialized::write(data, remaining, declared_public_domain_size);
  serialized::write(
    data, remaining, public_domain.data(), public_domain.size());
  return entry;
}

TEST_CASE(
  "KV deserialiser rejects invalid public domains" *
  doctest::test_suite("serialisation"))
{
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();

  const auto initialise = [&](const std::vector<uint8_t>& entry) {
    ccf::kv::RawKvStoreDeserialiser deserialiser(
      encryptor, ccf::kv::SecurityDomain::PUBLIC);
    ccf::kv::Term term = 0;
    ccf::kv::EntryFlags flags = {};
    return deserialiser.init(entry.data(), entry.size(), term, flags, false);
  };

  SUBCASE("Public domain exceeds remaining entry")
  {
    const auto entry = make_public_domain_entry(2, {0});
    REQUIRE_THROWS(initialise(entry));
  }

  SUBCASE("Public domain length prefix is truncated")
  {
    ccf::kv::SerialisedEntryHeader header;
    header.set_size(sizeof(size_t) - 1);
    std::vector<uint8_t> entry(sizeof(header) + header.size);
    std::memcpy(entry.data(), &header, sizeof(header));
    REQUIRE_THROWS(initialise(entry));
  }

  SUBCASE("Public domain length is impossible")
  {
    const auto entry =
      make_public_domain_entry(std::numeric_limits<size_t>::max(), {});
    REQUIRE_THROWS(initialise(entry));
  }

  SUBCASE("Claims digest is truncated")
  {
    std::vector<uint8_t> public_domain(
      sizeof(ccf::kv::EntryType) + sizeof(ccf::kv::Version));
    auto* data = public_domain.data();
    *data++ = static_cast<uint8_t>(ccf::kv::EntryType::WriteSetWithClaims);
    const ccf::kv::Version version = 1;
    std::memcpy(data, &version, sizeof(version));
    const auto entry =
      make_public_domain_entry(public_domain.size(), public_domain);
    REQUIRE_THROWS(initialise(entry));
  }
}

TEST_CASE(
  "RawWriter, SizeWriter and SpanWriter agree" *
  doctest::test_suite("serialisation"))
{
  const auto check = [](const auto& entry) {
    ccf::kv::RawWriter raw_writer;
    ccf::kv::SizeWriter size_writer;
    const auto expected_size = ccf::kv::RawWriter::serialised_size(entry);
    raw_writer.append(entry);
    size_writer.append(entry);
    REQUIRE(raw_writer.size() == expected_size);
    REQUIRE(size_writer.size() == expected_size);

    // A SpanWriter writes the same bytes into a buffer of exactly that size,
    // and nothing beyond it
    std::vector<uint8_t> buffer(expected_size);
    ccf::kv::SpanWriter span_writer(buffer);
    span_writer.append(entry);
    REQUIRE(span_writer.size() == expected_size);
    REQUIRE(buffer == raw_writer.get_raw_data());
    REQUIRE_THROWS_AS(span_writer.append(1), std::length_error);
    REQUIRE_THROWS_AS(span_writer.append(entry), std::length_error);
    REQUIRE(span_writer.size() == expected_size);

    // Once cleared, it writes from the start of the buffer again
    span_writer.clear();
    REQUIRE(span_writer.size() == 0);
    span_writer.append(entry);
    REQUIRE(span_writer.size() == expected_size);
    REQUIRE(buffer == raw_writer.get_raw_data());
  };

  check(ccf::kv::EntryType::WriteSetWithCommitEvidenceAndClaims);
  check(uint8_t(42));
  check(uint64_t(42));
  check(ccf::kv::Version(42));
  check(ccf::crypto::Sha256Hash(std::string("some content")));
  check(std::string());
  check(std::string("a string of some length"));
  check(std::vector<uint8_t>());
  check(std::vector<uint8_t>(37, 'x'));
  check(std::vector<ccf::kv::Version>{1, 2, 3});
  check(ccf::kv::serialisers::SerialisedEntry());
  check(ccf::kv::serialisers::SerialisedEntry(91, 'y'));
}

TEST_CASE(
  "Writers append size-prefixed payloads in place" *
  doctest::test_suite("serialisation"))
{
  for (const size_t payload_size : {0, 37})
  {
    INFO(payload_size);
    std::vector<uint8_t> payload(payload_size);
    std::iota(payload.begin(), payload.end(), uint8_t{1});
    ccf::kv::RawWriter expected;
    expected.append(payload);

    size_t fills = 0;
    const auto fill = [&](std::span<uint8_t> out) {
      ++fills;
      REQUIRE(out.size() == payload.size());
      std::ranges::copy(payload, out.begin());
    };

    ccf::kv::RawWriter raw_writer;
    raw_writer.append_size_prefixed_in_place(payload_size, fill);
    REQUIRE(raw_writer.get_raw_data() == expected.get_raw_data());

    // Only measures, so does not fill, and has no data to return
    ccf::kv::SizeWriter size_writer;
    size_writer.append_size_prefixed_in_place(payload_size, fill);
    REQUIRE(size_writer.size() == expected.size());
    REQUIRE_THROWS_AS(std::ignore = size_writer.view(), std::logic_error);

    std::vector<uint8_t> buffer(expected.size());
    ccf::kv::SpanWriter span_writer(buffer);
    span_writer.append_size_prefixed_in_place(payload_size, fill);
    REQUIRE(span_writer.size() == expected.size());
    REQUIRE(buffer == expected.get_raw_data());

    // A buffer too small for the payload is detected before filling it
    std::vector<uint8_t> small_buffer(expected.size() - 1);
    ccf::kv::SpanWriter small_writer(small_buffer);
    REQUIRE_THROWS_AS(
      small_writer.append_size_prefixed_in_place(payload_size, fill),
      std::length_error);
    REQUIRE(small_writer.size() == 0);

    // Empty payloads are not filled
    REQUIRE(fills == (payload_size == 0 ? 0 : 2));
  }
}

TEST_CASE(
  "Writers discard a payload whose in-place fill throws" *
  doctest::test_suite("serialisation"))
{
  // Payloads within and beyond RawWriter's inline capacity
  for (const size_t payload_size : {37, 1000})
  {
    INFO(payload_size);
    const uint32_t header = 0x01020304;
    std::vector<uint8_t> payload(payload_size);
    std::iota(payload.begin(), payload.end(), uint8_t{1});
    ccf::kv::RawWriter expected;
    expected.append(header);
    expected.append(payload);
    const auto expected_header = expected.view().first(sizeof(header));

    const auto failing_fill = [](std::span<uint8_t> out) {
      std::ranges::fill(out.first(out.size() / 2), uint8_t{0xff});
      throw std::runtime_error("fill failed");
    };
    const auto fill = [&](std::span<uint8_t> out) {
      std::ranges::copy(payload, out.begin());
    };

    // The writer keeps only what it held before the failed append, so it
    // exports neither the payload's size nor the part of it that was written,
    // and can still be appended to
    ccf::kv::RawWriter raw_writer;
    raw_writer.append(header);
    REQUIRE_THROWS_WITH_AS(
      raw_writer.append_size_prefixed_in_place(payload_size, failing_fill),
      "fill failed",
      std::runtime_error);
    REQUIRE(raw_writer.size() == sizeof(header));
    REQUIRE(std::ranges::equal(raw_writer.view(), expected_header));
    raw_writer.append_size_prefixed_in_place(payload_size, fill);
    REQUIRE(raw_writer.get_raw_data() == expected.get_raw_data());

    std::vector<uint8_t> buffer(expected.size());
    ccf::kv::SpanWriter span_writer(buffer);
    span_writer.append(header);
    REQUIRE_THROWS_WITH_AS(
      span_writer.append_size_prefixed_in_place(payload_size, failing_fill),
      "fill failed",
      std::runtime_error);
    REQUIRE(span_writer.size() == sizeof(header));
    REQUIRE(std::ranges::equal(span_writer.view(), expected_header));
    span_writer.append_size_prefixed_in_place(payload_size, fill);
    REQUIRE(buffer == expected.get_raw_data());
  }
}

TEST_CASE(
  "Writers reject sizes beyond the serialisable limit" *
  doctest::test_suite("serialisation"))
{
  constexpr auto max_size = ccf::kv::RawWriter::MAX_SIZE;
  size_t fills = 0;
  const auto fill = [&fills](std::span<uint8_t>) { ++fills; };

  // A payload which, with its size prefix, would not fit in a ptrdiff_t is
  // rejected without reserving space for it or filling it
  for (const size_t payload_size :
       {max_size - sizeof(size_t) + 1, std::numeric_limits<size_t>::max()})
  {
    INFO(payload_size);
    ccf::kv::RawWriter raw_writer;
    REQUIRE_THROWS_AS(
      raw_writer.append_size_prefixed_in_place(payload_size, fill),
      std::length_error);
    REQUIRE(raw_writer.size() == 0);

    std::vector<uint8_t> buffer(sizeof(size_t));
    ccf::kv::SpanWriter span_writer(buffer);
    REQUIRE_THROWS_AS(
      span_writer.append_size_prefixed_in_place(payload_size, fill),
      std::length_error);
    REQUIRE(span_writer.size() == 0);

    ccf::kv::SizeWriter size_writer;
    REQUIRE_THROWS_AS(
      size_writer.append_size_prefixed_in_place(payload_size, fill),
      std::length_error);
    REQUIRE(size_writer.size() == 0);
  }

  // A payload which, with its size prefix, fits exactly is accepted
  ccf::kv::SizeWriter exact_writer;
  exact_writer.append_size_prefixed_in_place(max_size - sizeof(size_t), fill);
  REQUIRE(exact_writer.size() == max_size);

  // The total measured by a SizeWriter is bounded the same way, up to and
  // including the limit, whichever way it is reached
  ccf::kv::SizeWriter size_writer;
  size_writer.append_size_prefixed_in_place(
    max_size - sizeof(size_t) - sizeof(uint32_t), fill);
  REQUIRE(size_writer.size() == max_size - sizeof(uint32_t));
  REQUIRE_THROWS_AS(
    size_writer.append_size_prefixed_in_place(0, fill), std::length_error);
  REQUIRE_THROWS_AS(size_writer.append(uint64_t{0}), std::length_error);
  REQUIRE(size_writer.size() == max_size - sizeof(uint32_t));
  size_writer.append(uint32_t{0});
  REQUIRE(size_writer.size() == max_size);
  REQUIRE_THROWS_AS(size_writer.append(uint8_t{0}), std::length_error);
  REQUIRE(size_writer.size() == max_size);

  REQUIRE(fills == 0);
}
