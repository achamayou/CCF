// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include "ccf/kv/untyped.h"
#include "kv/raw_serialise.h"

namespace ccf::kv
{
  using RawKvStoreSerialiser = GenericSerialiseWrapper<RawWriter>;
  using SizeKvStoreSerialiser = GenericSerialiseWrapper<SizeWriter>;
  using SpanKvStoreSerialiser = GenericSerialiseWrapper<SpanWriter>;
  using RawKvStoreDeserialiser = GenericDeserialiseWrapper<RawReader>;

  inline void serialise_map_writes(
    KvStoreSerialiser& s,
    const std::string& name,
    SecurityDomain domain,
    const untyped::Write& writes)
  {
    s.start_map(name, domain);

    // Retain the legacy read-set headers for ledger compatibility.
    s.serialise_entry_version(NoVersion);
    s.serialise_count_header(0);

    uint64_t put_count = 0;
    uint64_t remove_count = 0;
    for (const auto& [_, value] : writes)
    {
      if (value.has_value())
      {
        ++put_count;
      }
      else
      {
        ++remove_count;
      }
    }

    s.serialise_count_header(put_count);
    for (const auto& [key, value] : writes)
    {
      if (value.has_value())
      {
        s.serialise_write(key, *value);
      }
    }

    s.serialise_count_header(remove_count);
    for (const auto& [key, value] : writes)
    {
      if (!value.has_value())
      {
        s.serialise_remove(key);
      }
    }
  }
}
