// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include <cstdlib>
#include <ctime>
#include <fmt/format.h>
#define PICOBENCH_IMPLEMENT
#include <picobench/picobench.hpp>

#include <nlohmann/json.hpp>

#include "ds/files.h"

#include "crypto/base64.h"

#  include <openenclave/attestation/attester.h>
#  include <openenclave/attestation/custom_claims.h>
#  include <openenclave/attestation/sgx/evidence.h>
#  include <openenclave/attestation/verifier.h>

template <class A>
inline void do_not_optimize(A const& value)
{
  asm volatile("" : : "r,m"(value) : "memory");
}

inline void clobber_memory()
{
  asm volatile("" : : : "memory");
}

  struct Claims
  {
    oe_claim_t* data = nullptr;
    size_t length = 0;

    ~Claims()
    {
      oe_free_claims(data, length);
    }
  };

static void verify_attestation(picobench::state& s)
{
      auto rc = oe_verifier_initialize();
    if (rc != OE_OK)
    {
      std::cout << oe_result_str(rc) << std::endl;
      throw std::logic_error("Failed to load plugin");
    }

    oe_uuid_t oe_quote_format = {OE_FORMAT_UUID_SGX_ECDSA};

    auto quote_info_data = files::slurp("/home/amchamay/CCF/quote_info.json");
    auto quote_info = nlohmann::json::parse(quote_info_data);

    auto quote = quote_info["quote"].get<std::string_view>();

    auto evidence_data = crypto::raw_from_b64(quote);
    size_t evidence_size = evidence_data.size();
    uint8_t* evidence = evidence_data.data();

    auto quote_endorsement = quote_info["endorsements"].get<std::string_view>();

    auto endorsements_data = crypto::raw_from_b64(quote_endorsement);
    size_t endorsements_size = endorsements_data.size();
    uint8_t* endorsements = endorsements_data.data();

    Claims claims;

  size_t idx = 0;
  s.start_timer();
  for (auto _ : s)
  {
    (void)_;
    rc = oe_verify_evidence(
      &oe_quote_format,
      evidence,
      evidence_size,
      endorsements,
      endorsements_size,
      nullptr,
      0,
      &claims.data,
      &claims.length);
    if (rc != OE_OK)
    {
      std::cout << oe_result_str(rc) << std::endl;
      throw std::logic_error("Failed to verify");
    }
    do_not_optimize(rc);
    clobber_memory();
  }
  s.stop_timer();
}

const std::vector<int> sizes = {10, 100, 1000};

PICOBENCH_SUITE("attestation");
PICOBENCH(verify_attestation).iterations(sizes).samples(10).baseline();

int main(int argc, char* argv[])
{
  picobench::runner runner;
  runner.parse_cmd_line(argc, argv);
  return runner.run();
}
