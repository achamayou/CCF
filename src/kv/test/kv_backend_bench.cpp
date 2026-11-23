// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/kv/map.h"
#include "ds/champ_map.h"
#include "kv/null_encryptor.h"
#include "kv/store.h"
#include "kv/test/rust_kv_store.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string_view>

namespace
{
  using Clock = std::chrono::steady_clock;
  using Map = ccf::kv::untyped::Map;
  using Bytes = ccf::kv::serialisers::SerialisedEntry;
  constexpr size_t SAMPLE_COUNT = 9;
  const std::string TABLE = "public:benchmark";

  template <typename F>
  double elapsed(F&& f)
  {
    const auto start = Clock::now();
    f();
    return std::chrono::duration<double, std::nano>(Clock::now() - start)
      .count();
  }

  template <typename F>
  void measure(std::string_view name, size_t size, size_t operations, F&& run)
  {
    run();
    std::array<double, SAMPLE_COUNT> samples{};
    for (auto& sample : samples)
    {
      sample = run() / operations;
    }
    std::sort(samples.begin(), samples.end());
    std::cout << name << ',' << size << ',' << operations << ','
              << samples[SAMPLE_COUNT / 2] << ',' << samples.front() << ','
              << samples.back() << '\n';
  }

  std::array<uint8_t, 8> fixed_key(uint64_t i)
  {
    std::array<uint8_t, 8> bytes{};
    for (size_t j = 0; j < bytes.size(); ++j)
    {
      bytes[j] = static_cast<uint8_t>(i >> (8 * (bytes.size() - j - 1)));
    }
    return bytes;
  }

  Bytes key(uint64_t i)
  {
    const auto bytes = fixed_key(i);
    return Bytes(bytes.begin(), bytes.end());
  }

  void run_champ()
  {
    using Key = std::array<uint8_t, 8>;
    using Value = std::array<uint8_t, 64>;

    struct Hash
    {
      size_t operator()(const Key& key) const
      {
        return std::hash<Bytes>{}(Bytes(key.begin(), key.end()));
      }
    };

    using State = champ::Map<Key, Value, Hash>;
    constexpr size_t WRITES = 128;
    Value base{};
    Value update{};
    base.fill(1);
    update.fill(2);
    auto check = [](bool valid) {
      if (!valid)
      {
        throw std::runtime_error("Unexpected CHAMP benchmark observation");
      }
    };

    for (const size_t entries : {64, 512, 2048, 8192})
    {
      std::vector<Key> keys;
      for (size_t i = 0; i < entries; ++i)
      {
        keys.push_back(fixed_key(i));
      }
      auto seeded = [&] {
        State state;
        for (const auto& k : keys)
        {
          state = state.put(k, base);
        }
        return state;
      };
      measure("point_read", entries, entries, [&] {
        const auto state = seeded();
        return elapsed([&] {
          for (const auto& k : keys)
          {
            const auto* value = state.getp(k);
            check(value != nullptr && (*value)[0] == 1);
          }
        });
      });
      measure("write_with_pinned_root", entries, WRITES, [&] {
        auto state = seeded();
        std::vector<State> history;
        return elapsed([&] {
          history.reserve(WRITES + 1);
          history.push_back(state);
          for (size_t i = 0; i < WRITES; ++i)
          {
            state = state.put(keys[(17 * i) % entries], update);
            history.push_back(state);
          }
          const auto* before = history.front().getp(keys.front());
          const auto* after = state.getp(keys.front());
          check(
            before != nullptr && (*before)[0] == 1 && after != nullptr &&
            (*after)[0] == 2);
        });
      });
      measure("range", entries, entries, [&] {
        const auto state = seeded();
        return elapsed([&] {
          for (size_t i = 0; i < entries; ++i)
          {
            const auto start = i % (entries - 8);
            size_t sum = 0;
            state.foreach([&](const Key& k, const Value& value) {
              if (keys[start] <= k && k < keys[start + 8])
              {
                sum += value[0];
              }
              return true;
            });
            check(sum == 8);
          }
        });
      });
    }
  }

  template <typename Tx>
  void commit(Tx& tx)
  {
    if (tx.commit() != ccf::kv::CommitResult::SUCCESS)
    {
      throw std::runtime_error("Unexpected benchmark transaction rejection");
    }
  }

  template <typename Store>
  void seed(
    Store& store, size_t entries, const Bytes& value, const std::string& table)
  {
    auto tx = store.create_tx();
    auto* handle = tx.template rw<Map>(table);
    for (size_t i = 0; i < entries; ++i)
    {
      handle->put(key(i), value);
    }
    commit(tx);
  }

  template <typename Store>
  void run_suite()
  {
    const auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
    const Bytes value(64, 0x3a);
    const Bytes update(64, 0xc5);
    for (const size_t size : {64, 512, 2048})
    {
      measure("commit_existing", size, 1, [&] {
        Store store;
        store.set_encryptor(encryptor);
        seed(store, size, value, TABLE);
        auto tx = store.create_tx();
        auto* handle = tx.template rw<Map>(TABLE);
        for (size_t i = 0; i < size; ++i)
        {
          handle->put(key(i), update);
        }
        return elapsed([&] { commit(tx); });
      });

      measure("stage_replace", size, size, [&] {
        Store store;
        store.set_encryptor(encryptor);
        auto tx = store.create_tx();
        auto* handle = tx.template rw<Map>(TABLE);
        for (size_t i = 0; i < size; ++i)
        {
          handle->put(key(i), value);
        }
        return elapsed([&] {
          for (size_t i = 0; i < size; ++i)
          {
            handle->put(key(i), update);
          }
        });
      });

      measure("point_read", size, size, [&] {
        Store store;
        store.set_encryptor(encryptor);
        seed(store, size, value, TABLE);
        auto tx = store.create_read_only_tx();
        auto* handle = tx.template ro<Map>(TABLE);
        return elapsed([&] {
          for (size_t i = 0; i < size; ++i)
          {
            if (handle->get(key(i)) != value)
            {
              throw std::runtime_error("Unexpected benchmark read value");
            }
          }
        });
      });
    }

    constexpr size_t MIX_ENTRIES = 512;
    constexpr size_t TRANSACTIONS = 128;
    measure("logging_mix", MIX_ENTRIES, TRANSACTIONS, [&] {
      Store store;
      store.set_encryptor(encryptor);
      seed(store, MIX_ENTRIES, value, TABLE);
      auto pinned = store.create_read_only_tx();
      auto* reader = pinned.template ro<Map>(TABLE);
      const auto first = key(0);
      if (reader->get(first) != value)
      {
        throw std::runtime_error("Unexpected pinned benchmark value");
      }
      const auto time = elapsed([&] {
        for (size_t i = 0; i < TRANSACTIONS; ++i)
        {
          const auto k = key((i * 17) % MIX_ENTRIES);
          if (i % 8 == 0)
          {
            auto tx = store.create_tx();
            tx.template rw<Map>(TABLE)->put(k, update);
            commit(tx);
            store.compact(store.current_version());
          }
          else
          {
            auto tx = store.create_read_only_tx();
            if (!tx.template ro<Map>(TABLE)->get(k).has_value())
            {
              throw std::runtime_error("Unexpected missing benchmark key");
            }
          }
        }
      });
      if (reader->get(first) != value)
      {
        throw std::runtime_error("Pinned benchmark value changed");
      }
      return time;
    });

    constexpr size_t GOVERNANCE_ENTRIES = 64;
    constexpr size_t GOVERNANCE_TXS = 64;
    const std::string other = "public:benchmark_other";
    measure("governance_mix", GOVERNANCE_ENTRIES, GOVERNANCE_TXS, [&] {
      Store store;
      store.set_encryptor(encryptor);
      seed(store, GOVERNANCE_ENTRIES, value, TABLE);
      seed(store, GOVERNANCE_ENTRIES, value, other);
      return elapsed([&] {
        for (size_t i = 0; i < GOVERNANCE_TXS; ++i)
        {
          auto tx = store.create_tx();
          auto* source = tx.template rw<Map>(TABLE);
          auto* dest = tx.template rw<Map>(other);
          size_t count = 0;
          source->range(
            [&](const auto&, const auto&) { ++count; }, key(8), key(16));
          if (count != 8)
          {
            throw std::runtime_error("Unexpected benchmark range");
          }
          source->put(key(i), update);
          dest->put(key(i), update);
          commit(tx);
        }
      });
    });
  }
}

int main(int argc, char** argv)
{
  const std::string_view backend = argc == 2 ? argv[1] : "";
  if (backend != "cpp" && backend != "rust" && backend != "champ")
  {
    std::cerr << "Usage: kv_backend_bench cpp|rust|champ\n";
    return 2;
  }
  std::cout
    << std::fixed << std::setprecision(1)
    << "workload,entries,operations,median_ns_per_operation,min_ns,max_ns\n";
  if (backend == "cpp")
  {
    run_suite<ccf::kv::Store>();
  }
  else if (backend == "rust")
  {
    run_suite<ccf::kv::rust_test::Store>();
  }
  else
  {
    run_champ();
  }
}
