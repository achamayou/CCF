// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "enclave/claims.h"

namespace kv
{
  struct WriteSetWithClaims
  {
    std::vector<uint8_t> write_set = {};
    std::optional<ccf::receipt::Claims> claims = std::nullopt;

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