// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "enclave/claims.h"
#include "ds/serialized.h"

namespace kv
{
  struct WriteSetWithClaims
  {
    std::vector<uint8_t> write_set = {};
    std::vector<uint8_t> ledger_entry = {};
    std::optional<ccf::receipt::Claims> claims = std::nullopt;

    WriteSetWithClaims() = default;

    WriteSetWithClaims(std::vector<uint8_t>&& ws, std::optional<ccf::receipt::Claims>&& cl): write_set(std::move(ws)), claims(std::move(cl)) {}

    const std::vector<uint8_t>& entry()
    {
        if (ledger_entry.empty())
        {
            size_t size = sizeof(size_t) + write_set.size();
            if (claims.has_value())
                size += claims->serialised_size();
            ledger_entry.resize(size);
            uint8_t* buffer = ledger_entry.data();
            serialized::write(buffer, size, write_set.size());
            serialized::write(buffer, size, write_set.data(), write_set.size());
            serialized::write(buffer, size, claims->serialised_size());
        }
        return ledger_entry;
    }

    crypto::Sha256Hash digest() const
    {
      crypto::Sha256Hash wsd({write_set.data(), write_set.size()});
      if (claims.has_value())
      {
        return claims->ledger_leaf(wsd);
      }
      else
      {
        return wsd;
      }
    }

    bool empty() const
    {
      return write_set.empty();
    }
  };

}