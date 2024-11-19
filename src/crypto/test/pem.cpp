// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "ccf/crypto/pem.h"

#include <chrono>
#include <doctest/doctest.h>
#include <string>

#include "crypto/openssl/openssl_wrappers.h"
#include "crypto/openssl/rsa_key_pair.h"

#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

using namespace std;
using namespace ccf::crypto;

using namespace ccf::crypto::OpenSSL;

void check_bundles(
  const std::string& single_cert,
  const Pem& cert_pem,
  bool lr_before = false,
  bool lr_after = false)
{
  for (size_t count : {1, 2, 3, 10})
  {
    std::string certs;
    for (size_t i = 0; i < count; ++i)
    {
      if (lr_before)
      {
        certs += "\n";
      }
      certs += single_cert;
      if (lr_after)
      {
        certs += "\n";
      }
    }
    auto bundle = split_x509_cert_bundle(certs);
    REQUIRE(bundle.size() == count);
    for (const auto& pem : bundle)
    {
      REQUIRE(pem == cert_pem);
    }
  }
}

TEST_CASE("Split x509 cert bundle")
{
  REQUIRE(split_x509_cert_bundle("") == std::vector<Pem>{});

  const std::string single_cert =
    "-----BEGIN "
    "CERTIFICATE-----"
    "\nMIIByDCCAU6gAwIBAgIQOBe5SrcwReWmSzTjzj2HDjAKBggqhkjOPQQDAzATMREw\nDwYDVQ"
    "QDDAhDQ0YgTm9kZTAeFw0yMzA1MTcxMzUwMzFaFw0yMzA1MTgxMzUwMzBa\nMBMxETAPBgNVBA"
    "MMCENDRiBOb2RlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE74qL\nAc/"
    "45tiriN5MuquYhHVdMGQRvYSm08HBfYcODtET88qC0A39o6Y2TmfbIn6BdjMG\nkD58o377ZMT"
    "aApQu/oJcwt7qZ9/LE8j8WU2qHn0cPTlpwH/"
    "2tiud2w+U3voSo2cw\nZTASBgNVHRMBAf8ECDAGAQH/"
    "AgEAMB0GA1UdDgQWBBS9FJNwWSXtUpHaBV57EwTW\noM8vHjAfBgNVHSMEGDAWgBS9FJNwWSXt"
    "UpHaBV57EwTWoM8vHjAPBgNVHREECDAG\nhwR/"
    "xF96MAoGCCqGSM49BAMDA2gAMGUCMQDKxpjPToJ7VSqKqQSeMuW9tr4iL+"
    "9I\n7gTGdGwiIYV1qTSS35Sk9XQZ0VpSa58c/"
    "5UCMEgmH71k7XlTGVUypm4jAgjpC46H\ns+hJpGMvyD9dKzEpZgmZYtghbyakUkwBiqmFQA=="
    "\n-----END CERTIFICATE-----";
  auto bundle = split_x509_cert_bundle(single_cert);
  const auto cert_pem = Pem(single_cert);

  check_bundles(single_cert, cert_pem);
  check_bundles(single_cert, cert_pem, true);
  check_bundles(single_cert, cert_pem, false, true);
  check_bundles(single_cert, cert_pem, true, true);

  std::string bundle_with_invalid_suffix = single_cert + "ignored suffix";
  bundle = split_x509_cert_bundle(bundle_with_invalid_suffix);
  REQUIRE(bundle.size() == 1);
  REQUIRE(bundle[0] == cert_pem);

  bundle_with_invalid_suffix =
    single_cert + "-----BEGIN CERTIFICATE-----\nignored suffix";
  bundle = split_x509_cert_bundle(bundle_with_invalid_suffix);
  REQUIRE(bundle.size() == 1);
  REQUIRE(bundle[0] == cert_pem);

  const std::string bundle_with_very_invalid_pem =
    single_cert + "not a cert\n-----END CERTIFICATE-----";
  REQUIRE_THROWS_AS(
    split_x509_cert_bundle(bundle_with_very_invalid_pem), std::runtime_error);
}

TEST_CASE("GAH")
{
  const std::string cert = "-----BEGIN CERTIFICATE-----\n"
"MIIBvTCCAUOgAwIBAgIQfTOZ3Lt/V7/9bmk3ZxbatzAKBggqhkjOPQQDAzAWMRQw\n"
"EgYDVQQDDAtDQ0YgU2VydmljZTAeFw0yNDExMTcxNzA5NDhaFw0yNTAyMTUxNzA5\n"
"NDdaMBYxFDASBgNVBAMMC0NDRiBTZXJ2aWNlMHYwEAYHKoZIzj0CAQYFK4EEACID\n"
"YgAE5O9gvr+CL70uyQf4VFOg2x0raK5SFgrhylKb3rRcexJ7Z8XUHeRz2FT/+5Qb\n"
"tpm/yIXuG/sjlfY3LRmbs9DWJdA93+uqYxVyE2lEhJAQwogNe7IpNjch3NsP0CJ9\n"
"jxV/o1YwVDASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBTIydayc/wHi53b\n"
"mQDlE2GS49x3XTAfBgNVHSMEGDAWgBTIydayc/wHi53bmQDlE2GS49x3XTAKBggq\n"
"hkjOPQQDAwNoADBlAjEA5L8kqydp4QiGlO8+qS9YyoIdU7uRo4ZfFj05UyzzKTog\n"
"f2rTF5hLMUy7py+22ajnAjAUG5re2th+sGD0HaCeEGuFCcCePhlHMITwzmF2V850\n"
"JYrskuPWn+F56hx/cq3KqCo=\n"
"-----END CERTIFICATE-----\n\n\n\n";
  ccf::crypto::Pem pem(cert);
  Unique_BIO tcbio(pem);
  Unique_X509 tc(tcbio, true);
  REQUIRE(tc != nullptr);
}
