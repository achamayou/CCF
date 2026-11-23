// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/kv/map.h"
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

  Bytes key(uint64_t i)
  {
    Bytes bytes(8);
    for (size_t j = 0; j < bytes.size(); ++j)
    {
      bytes[j] = static_cast<uint8_t>(i >> (8 * (bytes.size() - j - 1)));
    }
    return bytes;
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
  if (
    argc != 2 ||
    (std::string_view(argv[1]) != "cpp" && std::string_view(argv[1]) != "rust"))
  {
    std::cerr << "Usage: kv_backend_bench cpp|rust\n";
    return 2;
  }
  std::cout
    << std::fixed << std::setprecision(1)
    << "workload,entries,operations,median_ns_per_operation,min_ns,max_ns\n";
  if (std::string_view(argv[1]) == "cpp")
  {
    run_suite<ccf::kv::Store>();
  }
  else
  {
    run_suite<ccf::kv::rust_test::Store>();
  }
}
