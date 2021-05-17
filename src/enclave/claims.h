// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/hash_provider.h"
#include "node/merkle_tree.h"

namespace ccf
{
    namespace receipt
    {
        struct Claim
        {
            crypto::Sha256Hash digest;
            bool is_public = true;
        };

        class Claims
        {
            std::vector<Claim> claims = {};

        public:
            void add_public_claim_digest(const crypto::Sha256Hash& digest)
            {
                claims.emplace_back(Claim{digest, true});
            }

            crypto::Sha256Hash ledger_leaf(const crypto::Sha256Hash& write_set_digest)
            {
                HistoryTree tree;
                tree.insert(merkle::Hash(write_set_digest.h));
                for (const auto& claim: claims)
                {
                    tree.insert(merkle::Hash(claim.digest.h));
                }
                const merkle::Hash& root = tree.root();
                crypto::Sha256Hash result;
                std::copy(root.bytes, root.bytes + root.size(), result.h.begin());
                return result;
            }

            std::vector<uint8_t> serialise()
            {
                return {};
            }
        };
    }
}