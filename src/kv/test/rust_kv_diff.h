// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/test/rust_kv_store.h"

namespace ccf::kv::rust_test
{
  template <typename M>
  class DiffHandle : public HandleBase
  {
    using Key = typename MapTypes<M>::Key;
    using Value = typename MapTypes<M>::Value;
    using Keys = typename MapTypes<M>::Keys;
    using Values = typename MapTypes<M>::Values;

    const untyped::Write& writes;

    static std::optional<Value> decode(const std::optional<Bytes>& value)
    {
      return value ?
        std::make_optional<Value>(Values::from_serialised(*value)) :
        std::nullopt;
    }

  public:
    explicit DiffHandle(const untyped::Write& writes_) : writes(writes_) {}

    std::optional<std::optional<Value>> get(const Key& key) const
    {
      const auto it = writes.find(Keys::to_serialised(key));
      if (it == writes.end())
      {
        return std::nullopt;
      }
      return std::optional<std::optional<Value>>(
        std::in_place, decode(it->second));
    }

    bool has(const Key& key) const
    {
      const auto it = writes.find(Keys::to_serialised(key));
      return it != writes.end() && it->second.has_value();
    }

    bool is_deleted(const Key& key) const
    {
      const auto it = writes.find(Keys::to_serialised(key));
      return it != writes.end() && !it->second.has_value();
    }

    size_t size() const
    {
      return writes.size();
    }

    template <typename F>
    void foreach(F&& f) const
    {
      for (const auto& [k, v] : writes)
      {
        if (!f(Keys::from_serialised(k), decode(v)))
        {
          return;
        }
      }
    }

    template <typename F>
    void foreach_key(F&& f) const
    {
      for (const auto& [k, _] : writes)
      {
        if (!f(Keys::from_serialised(k)))
        {
          return;
        }
      }
    }

    template <typename F>
    void foreach_value(F&& f) const
    {
      for (const auto& [_, v] : writes)
      {
        if (!f(decode(v)))
        {
          return;
        }
      }
    }

    template <typename F>
    void range(
      F&& f,
      const std::optional<Bytes>& from,
      const std::optional<Bytes>& to) const
      requires std::is_same_v<M, untyped::Map>
    {
      for (auto it = from ? writes.lower_bound(*from) : writes.begin();
           it != writes.end() && (!to || it->first < *to);
           ++it)
      {
        f(it->first, it->second);
      }
    }
  };

  class TxDiff
  {
    struct State
    {
      MapWrites writes;
      std::map<
        std::pair<std::string, std::type_index>,
        std::unique_ptr<HandleBase>>
        handles;
    };

    std::unique_ptr<State> state = std::make_unique<State>();

  public:
    explicit TxDiff(MapWrites writes)
    {
      state->writes = std::move(writes);
    }

    template <typename M>
    DiffHandle<M>* diff(const std::string& name)
    {
      parse_map_name(name);
      auto key = std::make_pair(name, std::type_index(typeid(DiffHandle<M>)));
      if (auto it = state->handles.find(key); it != state->handles.end())
      {
        return static_cast<DiffHandle<M>*>(it->second.get());
      }
      auto handle = std::make_unique<DiffHandle<M>>(state->writes[name]);
      auto* result = handle.get();
      state->handles.emplace(std::move(key), std::move(handle));
      return result;
    }

    template <typename M>
    DiffHandle<M>* diff(const M& map)
    {
      return diff<M>(map.get_name());
    }
  };

  inline TxDiff Store::create_tx_diff()
  {
    return TxDiff(latest_map_deltas());
  }
}
