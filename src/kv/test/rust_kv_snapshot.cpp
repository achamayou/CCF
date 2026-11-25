// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ds/internal_logger.h"
#include "kv/snapshot.h"
#include "kv/test/rust_kv_store.h"
#include "kv/untyped_change_set.h"

#include <bit>

namespace ccf::kv::rust_test
{
  namespace
  {
    using Rows = std::vector<std::pair<Bytes, untyped::VersionV>>;

    class MapSnapshot : public AbstractMap::Snapshot
    {
      const std::string name;
      const SecurityDomain domain;
      const Version revision;
      const Rows rows;

    public:
      MapSnapshot(std::string name_, Version revision_, Rows rows_) :
        name(std::move(name_)),
        domain(ccf::kv::get_security_domain(name)),
        revision(revision_),
        rows(std::move(rows_))
      {}

      SecurityDomain get_security_domain() const override
      {
        return domain;
      }

      void serialise(KvStoreSerialiser& s) override
      {
        size_t size = 0;
        for (const auto& [key, val] : rows)
        {
          size += ::map::get_serialized_size_with_padding(key);
          size += ::map::get_serialized_size_with_padding(val);
        }
        s.start_map(name, domain);
        s.serialise_entry_version(revision);
        s.serialise_raw_in_place(size, [&](std::span<uint8_t> dest) {
          auto* p = dest.data();
          auto remaining = dest.size();
          for (const auto& [key, val] : rows)
          {
            const auto ksize = ::map::serialize(key, p, remaining);
            ::map::add_padding(ksize, p, remaining);
            const auto vsize = ::map::serialize(val, p, remaining);
            ::map::add_padding(vsize, p, remaining);
          }
        });
      }
    };

    Rows decode_rows(std::span<const uint8_t> raw)
    {
      Rows rows;
      const auto* data = raw.data();
      auto size = raw.size();
      while (size != 0)
      {
        auto payload = [&](size_t minimum) {
          const auto length = serialized::read<uint64_t>(data, size);
          if (length < minimum || length > size)
          {
            throw std::logic_error("Invalid snapshot map payload size");
          }
          auto bytes = std::span(data, static_cast<size_t>(length));
          serialized::skip(data, size, length);
          serialized::skip(
            data, size, ::map::get_padding(sizeof(uint64_t) + length));
          return bytes;
        };
        auto key = payload(0);
        auto value = payload(sizeof(Version));
        const auto* p = value.data();
        auto remaining = value.size();
        const auto version = serialized::read<Version>(p, remaining);
        // Legacy snapshots encoded tombstones as negative write versions.
        if (std::bit_cast<int64_t>(version) >= 0)
        {
          rows.emplace_back(
            Bytes(key.begin(), key.end()),
            untyped::VersionV{version, Bytes(p, p + remaining)});
        }
      }
      return rows;
    }
  }

  std::unique_ptr<AbstractStore::AbstractSnapshot> Store::snapshot_unsafe_maps(
    Version version)
  {
    auto r = dispatch({.op = Opcode::SNAPSHOT_MAPS, .number = version});
    r.require();
    auto snapshot = std::make_unique<StoreSnapshot>(version);
    if (history)
    {
      snapshot->add_hash_at_snapshot(history->get_raw_leaf(version));
    }
    if (consensus)
    {
      snapshot->add_view_history(consensus->get_view_history(version));
    }
    for (size_t i = 0; i < r.size; ++i)
    {
      const auto map = ccf_rust_kv_snapshot_map(r.data.get(), i);
      const auto name = copy(map.name);
      Rows rows;
      rows.reserve(map.size);
      for (size_t j = 0; j < map.size; ++j)
      {
        const auto row = ccf_rust_kv_snapshot_cell(r.data.get(), i, j);
        rows.emplace_back(
          copy(row.key), untyped::VersionV{row.version, copy(row.value)});
      }
      snapshot->add_map_snapshot(std::make_unique<MapSnapshot>(
        std::string(name.begin(), name.end()), map.revision, std::move(rows)));
    }
    return snapshot;
  }

  std::unique_ptr<AbstractStore::AbstractSnapshot> Store::snapshot_maps(
    Version version)
  {
    std::lock_guard lock(mutex);
    return snapshot_unsafe_maps(version);
  }

  std::vector<uint8_t> Store::serialise_snapshot(
    std::unique_ptr<AbstractStore::AbstractSnapshot> snapshot)
  {
    std::lock_guard lock(mutex);
    return snapshot->serialise(encryptor);
  }

  void Store::swap_private_maps(Store& source)
  {
    if (this == &source)
    {
      throw std::logic_error("Cannot swap a Rust KV store with itself");
    }
    std::scoped_lock lock(mutex, source.mutex);
    if (source.head > head)
    {
      throw std::runtime_error(fmt::format(
        "Invalid call to swap_private_maps. Source is at version {} while "
        "target is at {}",
        source.head,
        head));
    }
    if (reserved_through > head || source.reserved_through > source.head)
    {
      throw std::logic_error("Cannot swap maps with outstanding reservations");
    }
    auto response =
      source.dispatch({.op = Opcode::SNAPSHOT_MAPS, .number = source.head});
    response.require();
    std::vector<std::string> names;
    for (size_t i = 0; i < response.size; ++i)
    {
      const auto raw =
        copy(ccf_rust_kv_snapshot_map(response.data.get(), i).name);
      std::string name(raw.begin(), raw.end());
      if (get_security_domain(name) == SecurityDomain::PRIVATE)
      {
        names.push_back(std::move(name));
      }
    }
    std::vector<ByteView> views;
    for (const auto& name : names)
    {
      views.push_back(bytes(name));
    }
    const auto status = ccf_rust_kv_swap_recovery_maps(
      native.get(), source.native.get(), views.data(), views.size());
    if (status != Status::OK)
    {
      throw std::logic_error(fmt::format(
        "Rust KV could not swap private maps (status {})",
        static_cast<unsigned>(status)));
    }
    for (const auto& name : names)
    {
      // Imported roots are a recovery baseline, not new commit deltas.
      map_deltas.erase(name);
      source.map_deltas.erase(name);
    }
  }

  ApplyResult Store::deserialise_snapshot(
    const uint8_t* data,
    size_t size,
    ConsensusHookPtrs& hooks,
    std::vector<Version>* view_history,
    bool public_only)
  {
    return deserialise_snapshot_internal(
      data, size, nullptr, hooks, view_history, public_only, nullptr, nullptr);
  }

  ApplyResult Store::deserialise_snapshot_in_place(
    std::span<uint8_t> data,
    ConsensusHookPtrs& hooks,
    std::vector<Version>* view_history,
    const SnapshotPublicMaps* public_maps)
  {
    return deserialise_snapshot_internal(
      data.data(),
      data.size(),
      data.data(),
      hooks,
      view_history,
      false,
      nullptr,
      public_maps);
  }

  ApplyResult Store::deserialise_public_snapshot_capturing(
    const uint8_t* data,
    size_t size,
    ConsensusHookPtrs& hooks,
    std::vector<Version>* view_history,
    std::optional<SnapshotPublicMaps>& captured)
  {
    captured.reset();
    return deserialise_snapshot_internal(
      data, size, nullptr, hooks, view_history, true, &captured, nullptr);
  }

  ApplyResult Store::deserialise_snapshot_internal(
    const uint8_t* data,
    size_t size,
    uint8_t* writable,
    ConsensusHookPtrs& hooks,
    std::vector<Version>* view_history,
    bool public_only,
    std::optional<SnapshotPublicMaps>* capture,
    const SnapshotPublicMaps* reuse)
  {
    std::lock_guard lock(mutex);
    RawKvStoreDeserialiser decoder(
      encryptor, public_only ? std::make_optional(PUBLIC) : std::nullopt);
    Term read_term = 0;
    EntryFlags flags{};
    const auto version = writable ?
      decoder.init_in_place(writable, size, read_term, flags, true) :
      decoder.init(data, size, read_term, flags, true);
    if (
      !version || flags != 0 || decoder.get_entry_type() != EntryType::Snapshot)
    {
      LOG_FAIL_FMT("Rust KV could not decode the snapshot envelope");
      return ApplyResult::FAIL;
    }
    if (reuse != nullptr && reuse->version != *version)
    {
      LOG_FAIL_FMT("Rust KV snapshot does not match the captured version");
      return ApplyResult::FAIL;
    }
    auto hash_at_snapshot =
      history ? decoder.deserialise_raw() : std::vector<uint8_t>{};
    auto decoded_history = view_history ? decoder.deserialise_view_history() :
                                          std::vector<Version>{};

    struct MapImage
    {
      Version revision;
      Rows rows;
      std::vector<SnapshotCell> views;
    };

    std::map<std::string, MapImage> maps;
    SnapshotPublicMaps captured;
    captured.version = *version;
    size_t reused = 0;
    for (auto name = decoder.start_map(); name; name = decoder.start_map())
    {
      const auto domain = parse_map_name(*name).first;
      if ((public_only && domain != PUBLIC) || maps.contains(*name))
      {
        LOG_FAIL_FMT("Rust KV snapshot contains a duplicate or invalid map");
        return ApplyResult::FAIL;
      }
      const auto revision = decoder.deserialise_entry_version();
      const auto raw = decoder.deserialise_raw_span();
      Rows rows;
      if (reuse != nullptr && domain == PUBLIC)
      {
        const auto it = reuse->maps.find(*name);
        if (
          it == reuse->maps.end() || it->second.revision != revision ||
          it->second.digest != ccf::crypto::Sha256Hash(raw.data(), raw.size()))
        {
          LOG_FAIL_FMT("Rust KV snapshot map differs from captured public map");
          return ApplyResult::FAIL;
        }
        rows = it->second.rows;
        ++reused;
      }
      else
      {
        rows = decode_rows(raw);
        if (capture != nullptr && domain == PUBLIC)
        {
          captured.maps.emplace(
            *name,
            SnapshotPublicMaps::CapturedMap{
              revision, ccf::crypto::Sha256Hash(raw.data(), raw.size()), rows});
        }
      }
      auto& image = maps.emplace(*name, MapImage{revision, std::move(rows), {}})
                      .first->second;
      for (const auto& [key, value] : image.rows)
      {
        image.views.push_back({bytes(key), bytes(value.value), value.version});
      }
    }
    if (reuse != nullptr && reused != reuse->maps.size())
    {
      LOG_FAIL_FMT("Rust KV snapshot omits captured public maps");
      return ApplyResult::FAIL;
    }
    std::vector<SnapshotInput> inputs;
    for (const auto& [name, image] : maps)
    {
      inputs.push_back(
        {{bytes(name), image.revision, image.views.size()},
         image.views.data()});
    }
    const auto status = ccf_rust_kv_install_snapshot(
      native.get(), *version, inputs.data(), inputs.size());
    if (status != Status::OK)
    {
      LOG_FAIL_FMT(
        "Rust KV did not install snapshot {} (status {})",
        *version,
        static_cast<unsigned>(status));
      return ApplyResult::FAIL;
    }
    head = *version;
    reserved_through = head;
    reserved_entries.clear();
    global = *version;
    last_committable = *version;
    last_view = read_term;
    for (const auto& [name, _] : maps)
    {
      map_deltas.erase(name);
    }
    for (const auto& [name, image] : maps)
    {
      const auto it = local_hooks.find(name);
      const auto glob = global_hooks.find(name);
      const bool local = it != local_hooks.end() && it->second;
      const bool global_hook = glob != global_hooks.end() && glob->second;
      if ((local || global_hook) && !image.rows.empty())
      {
        untyped::Write writes;
        for (const auto& [key, value] : image.rows)
        {
          writes.emplace(key, value.value);
        }
        if (local)
        {
          if (auto hook = it->second(image.revision, writes); hook)
          {
            hooks.push_back(std::move(hook));
          }
        }
        map_deltas[name].emplace(image.revision, MapDelta{std::move(writes)});
      }
    }
    if (view_history)
    {
      *view_history = std::move(decoded_history);
    }
    if (this->history && !this->history->init_from_snapshot(hash_at_snapshot))
    {
      LOG_FAIL_FMT("Rust KV could not initialise history from the snapshot");
      return ApplyResult::FAIL;
    }
    if (capture)
    {
      *capture = std::move(captured);
    }
    return ApplyResult::PASS;
  }
}
