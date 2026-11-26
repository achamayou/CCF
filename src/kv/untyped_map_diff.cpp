// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/kv/untyped_map_diff.h"

#include "ds/internal_logger.h"
#ifdef CCF_USE_RUST_KV
#  include "kv/rust_kv_store_impl.h"
#endif
#include "kv/untyped_change_set.h"

namespace ccf::kv::untyped
{
#ifdef CCF_USE_RUST_KV
  namespace
  {
    void assign_span(MapDiff::KeyType& dst, std::span<const uint8_t> src)
    {
      dst.resize(src.size());
      if (!src.empty())
      {
        std::memcpy(dst.data(), src.data(), src.size());
      }
    }

    const rust_detail::FlatMapWrite::EntrySpan* find_flat_entry(
      const rust_detail::FlatMapWrite& flat, const MapDiff::KeyType& key)
    {
      const std::span<const uint8_t> ks(key.data(), key.size());
      const auto it = std::lower_bound(
        flat.entries.begin(),
        flat.entries.end(),
        ks,
        [&](
          const rust_detail::FlatMapWrite::EntrySpan& e,
          std::span<const uint8_t> target) {
          return rust_detail::FlatMapWrite::compare_spans(
                   flat.key_span(e), target) < 0;
        });
      if (
        it == flat.entries.end() ||
        rust_detail::FlatMapWrite::compare_spans(flat.key_span(*it), ks) != 0)
      {
        return nullptr;
      }
      return &*it;
    }
  }

  void MapDiff::foreach_(const MapDiff::ElementVisitorWithEarlyOut& f)
  {
    if (!change_set.rust_diff)
    {
      return;
    }
    const auto& flat = *change_set.rust_diff;
    KeyType key_buf;
    std::optional<ValueType> val_buf;
    for (const auto& e : flat.entries)
    {
      assign_span(key_buf, flat.key_span(e));
      if (e.val_len == rust_detail::FlatMapWrite::REMOVED)
      {
        val_buf.reset();
      }
      else
      {
        if (!val_buf.has_value())
        {
          val_buf.emplace();
        }
        assign_span(*val_buf, flat.val_span(e));
      }
      if (!f(key_buf, val_buf))
      {
        return;
      }
    }
  }

  MapDiff::MapDiff(ccf::kv::untyped::ChangeSet& cs, std::string map_name_) :
    change_set(cs),
    map_name(std::move(map_name_))
  {
    KV_TRACE(trace::transaction(
      change_set.trace_metadata.id,
      "unsupported",
      {{"operation", "transaction diff"}}));
  }

  std::optional<std::optional<MapDiff::ValueType>> MapDiff::get(
    const MapDiff::KeyType& key)
  {
    if (!change_set.rust_diff)
    {
      return std::nullopt;
    }
    const auto& flat = *change_set.rust_diff;
    const auto* e = find_flat_entry(flat, key);
    if (e == nullptr)
    {
      return std::nullopt;
    }
    if (e->val_len == rust_detail::FlatMapWrite::REMOVED)
    {
      return std::optional<std::optional<ValueType>>(
        std::in_place, std::nullopt);
    }
    const auto vs = flat.val_span(*e);
    return std::optional<std::optional<ValueType>>(
      std::in_place, ValueType(vs.begin(), vs.end()));
  }

  bool MapDiff::has(const MapDiff::KeyType& key)
  {
    if (!change_set.rust_diff)
    {
      return false;
    }
    const auto* e = find_flat_entry(*change_set.rust_diff, key);
    return e != nullptr && e->val_len != rust_detail::FlatMapWrite::REMOVED;
  }

  bool MapDiff::is_deleted(const MapDiff::KeyType& key)
  {
    if (!change_set.rust_diff)
    {
      return false;
    }
    const auto* e = find_flat_entry(*change_set.rust_diff, key);
    return e != nullptr && e->val_len == rust_detail::FlatMapWrite::REMOVED;
  }

  void MapDiff::foreach(const MapDiff::ElementVisitorWithEarlyOut& f)
  {
    foreach_(f);
  }

  size_t MapDiff::size()
  {
    return change_set.rust_diff ? change_set.rust_diff->entries.size() : 0;
  }

  void MapDiff::range(
    const MapDiff::ElementVisitor& f,
    const std::optional<MapDiff::KeyType>& from,
    const std::optional<MapDiff::KeyType>& to)
  {
    if (
      !change_set.rust_diff ||
      (from.has_value() && to.has_value() &&
       (from.value() == to.value() || to.value() < from.value())))
    {
      return;
    }
    const auto& flat = *change_set.rust_diff;
    auto it = flat.entries.begin();
    if (from.has_value())
    {
      const std::span<const uint8_t> fs(from->data(), from->size());
      it = std::lower_bound(
        flat.entries.begin(),
        flat.entries.end(),
        fs,
        [&](
          const rust_detail::FlatMapWrite::EntrySpan& e,
          std::span<const uint8_t> target) {
          return rust_detail::FlatMapWrite::compare_spans(
                   flat.key_span(e), target) < 0;
        });
    }
    KeyType key_buf;
    std::optional<ValueType> val_buf;
    for (; it != flat.entries.end(); ++it)
    {
      const auto ks = flat.key_span(*it);
      if (to.has_value())
      {
        const std::span<const uint8_t> ts(to->data(), to->size());
        if (rust_detail::FlatMapWrite::compare_spans(ks, ts) >= 0)
        {
          break;
        }
      }
      assign_span(key_buf, ks);
      if (it->val_len == rust_detail::FlatMapWrite::REMOVED)
      {
        val_buf.reset();
      }
      else
      {
        if (!val_buf.has_value())
        {
          val_buf.emplace();
        }
        assign_span(*val_buf, flat.val_span(*it));
      }
      f(key_buf, val_buf);
    }
  }
#else
  // A change set created for a diff (see Map::create_change_set) holds the
  // state as of its start version, and its writes contain exactly the keys
  // deleted by the commit at that version, all mapped to nullopt. Puts are the
  // entries of the state whose version is the start version.

  namespace
  {
    // Returns the value written at the change set's start version if key was
    // put by that commit, else nullptr. The pointer is owned by change_set.
    const MapDiff::ValueType* written_value(
      const ChangeSet& change_set, const MapDiff::KeyType& key)
    {
      const auto* const search = change_set.state.getp(key);
      if (search == nullptr || search->version != change_set.start_version)
      {
        return nullptr;
      }

      return &search->value;
    }
  }

  void MapDiff::foreach_(const MapDiff::ElementVisitorWithEarlyOut& f)
  {
    for (const auto& [key, deleted] : change_set.writes)
    {
      if (!f(key, deleted))
      {
        return;
      }
    }

    const auto version = change_set.start_version;
    change_set.state.foreach(
      [&f, version](const KeyType& k, const VersionV& v) {
        if (v.version != version)
        {
          return true;
        }

        const std::optional<ValueType> value = v.value;
        return f(k, value);
      });
  }

  MapDiff::MapDiff(ccf::kv::untyped::ChangeSet& cs, std::string map_name) :
    change_set(cs),
    map_name(std::move(map_name))
  {
    KV_TRACE(trace::transaction(
      cs.trace_metadata.id, "unsupported", {{"operation", "map diff"}}));
  }

  std::optional<std::optional<MapDiff::ValueType>> MapDiff::get(
    const MapDiff::KeyType& key)
  {
    using MaybeValue = std::optional<ValueType>;

    if (change_set.writes.contains(key))
    {
      LOG_TRACE_FMT("KV[{}]::get({}) - deleted", map_name, key);
      return std::optional<MaybeValue>(std::in_place, std::nullopt);
    }

    const auto* value_p = written_value(change_set, key);
    if (value_p != nullptr)
    {
      LOG_TRACE_FMT("KV[{}]::get({}) - found", map_name, key);
      return std::optional<MaybeValue>(std::in_place, *value_p);
    }

    LOG_TRACE_FMT("KV[{}]::get({}) - not found", map_name, key);

    return std::nullopt;
  }

  bool MapDiff::has(const MapDiff::KeyType& key)
  {
    const bool found = written_value(change_set, key) != nullptr;

    LOG_TRACE_FMT(
      "KV[{}]::has({}) - {}found", map_name, key, found ? "" : "not ");
    return found;
  }

  bool MapDiff::is_deleted(const MapDiff::KeyType& key)
  {
    const bool deleted = change_set.writes.contains(key);

    LOG_TRACE_FMT(
      "KV[{}]::deleted({}) - {}deleted", map_name, key, deleted ? "" : "not ");
    return deleted;
  }

  void MapDiff::foreach(const MapDiff::ElementVisitorWithEarlyOut& f)
  {
    foreach_(f);
  }

  size_t MapDiff::size()
  {
    // Counted directly rather than via foreach, which would copy every value
    size_t size_ = change_set.writes.size();

    const auto version = change_set.start_version;
    change_set.state.foreach(
      [&size_, version](const KeyType&, const VersionV& v) {
        size_ += (v.version == version) ? 1 : 0;
        return true;
      });

    return size_;
  }

  void MapDiff::range(
    const MapDiff::ElementVisitor& f,
    const std::optional<MapDiff::KeyType>& from,
    const std::optional<MapDiff::KeyType>& to)
  {
    // Current limitations/ineficiencies:
    // - The state and writes are wastefully looped over until `from` is
    // found.
    // - All keys and values in the range are stored in the intermediate map
    // `res`.
    // - The constructed range is loop over at the end to call lambda on.
    // Optimisation is possible to only loop over the state/writes once, in
    // order, and call the user lambda on each element in the range directly.
    // This should include adding an iterator to the underlying ordered state
    // to find the start/end of the range using
    // std::lower_bound()/std::upper_bound() and loop over it, interleaves
    // with the local writes.

    if (
      from.has_value() && to.has_value() &&
      (from.value() == to.value() || to.value() < from.value()))
    {
      return;
    }

    // CHAMP maps are unordered, so we cannot early-out when we encounter a
    // key past the end of the range - there may still be in-range keys later
    // in the iteration. If the underlying state used an ordered collection,
    // this could be set to false to stop iteration once `to` is exceeded.
    bool continue_past_range_to = true;

    std::map<KeyType, std::optional<ValueType>> res;
    auto g = [&res, &from, &to, continue_past_range_to](
               const KeyType& k, const std::optional<ValueType>& v) {
      if (from.has_value() && k < from.value())
      {
        // Start of range is not yet found.
        return true;
      }

      if (to.has_value() && (k == to.value() || to.value() < k))
      {
        // End of range. Note: `to` is excluded.
        return continue_past_range_to;
      }

      res[k] = v;
      return true;
    };
    foreach_(g);

    for (const auto& e : res)
    {
      f(e.first, e.second);
    }
  }
#endif
}