// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/hash_provider.h"
#include "node/merkle_tree.h"
#include "ds/serialized.h"

namespace ccf
{
    namespace receipt
    {
        struct Claim
        {
            crypto::Sha256Hash digest;
        };

        class Claims
        {
            std::vector<Claim> claims = {};

        public:
            void add_public_claim_digest(const crypto::Sha256Hash& digest)
            {
                claims.emplace_back(Claim{digest});
            }

            void clear()
            {
                claims.clear();
            }

            crypto::Sha256Hash ledger_leaf(const crypto::Sha256Hash& write_set_digest) const
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

            size_t serialised_size() const
            {
                return sizeof(size_t) + claims.size() * crypto::Sha256Hash::SIZE;
            }

            std::vector<uint8_t> serialise()
            {
                auto size = serialised_size();
                std::vector<uint8_t> buffer(size);
                uint8_t * cursor = buffer.data();
                size_t claims_size = claims.size() * crypto::Sha256Hash::SIZE;
                serialized::write(cursor, size, claims_size);
                for (auto& claim: claims)
                {
                    serialized::write(cursor, size, claim.digest.h.data(), crypto::Sha256Hash::SIZE);
                }
                return buffer;
            }
        };
    }
}