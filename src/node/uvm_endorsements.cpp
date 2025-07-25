// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "node/uvm_endorsements.h"

namespace ccf
{
  bool inline matches_uvm_roots_of_trust(
    const pal::UVMEndorsements& endorsements,
    const std::vector<pal::UVMEndorsements>& uvm_roots_of_trust)
  {
    for (const auto& uvm_root_of_trust : uvm_roots_of_trust)
    {
      if (
        uvm_root_of_trust.did == endorsements.did &&
        uvm_root_of_trust.feed == endorsements.feed &&
        uvm_root_of_trust.svn <= endorsements.svn)
      {
        return true;
      }
    }
    return false;
  }

  namespace cose
  {
    static constexpr auto HEADER_PARAM_ISSUER = "iss";
    static constexpr auto HEADER_PARAM_FEED = "feed";

    static std::vector<std::vector<uint8_t>> decode_x5chain(
      QCBORDecodeContext& ctx, const QCBORItem& x5chain)
    {
      std::vector<std::vector<uint8_t>> parsed;

      if (x5chain.uDataType == QCBOR_TYPE_ARRAY)
      {
        QCBORDecode_EnterArrayFromMapN(&ctx, headers::PARAM_X5CHAIN);
        while (true)
        {
          QCBORItem item;
          auto result = QCBORDecode_GetNext(&ctx, &item);
          if (result == QCBOR_ERR_NO_MORE_ITEMS)
          {
            break;
          }
          if (result != QCBOR_SUCCESS)
          {
            throw COSEDecodeError("Item in x5chain is not well-formed");
          }
          if (item.uDataType == QCBOR_TYPE_BYTE_STRING)
          {
            parsed.push_back(qcbor_buf_to_byte_vector(item.val.string));
          }
          else
          {
            throw COSEDecodeError(
              "Next item in x5chain was not of type byte string");
          }
        }
        QCBORDecode_ExitArray(&ctx);
        if (parsed.empty())
        {
          throw COSEDecodeError("x5chain array length was 0 in COSE header");
        }
      }
      else if (x5chain.uDataType == QCBOR_TYPE_BYTE_STRING)
      {
        parsed.push_back(qcbor_buf_to_byte_vector(x5chain.val.string));
      }
      else
      {
        throw COSEDecodeError(fmt::format(
          "Value type {} of x5chain in COSE header is not array or byte string",
          x5chain.uDataType));
      }

      return parsed;
    }

    static UvmEndorsementsProtectedHeader decode_protected_header(
      const std::vector<uint8_t>& uvm_endorsements_raw)
    {
      UsefulBufC msg{uvm_endorsements_raw.data(), uvm_endorsements_raw.size()};

      QCBORError qcbor_result = QCBOR_SUCCESS;

      QCBORDecodeContext ctx;
      QCBORDecode_Init(&ctx, msg, QCBOR_DECODE_MODE_NORMAL);

      QCBORDecode_EnterArray(&ctx, nullptr);
      qcbor_result = QCBORDecode_GetError(&ctx);
      if (qcbor_result != QCBOR_SUCCESS)
      {
        throw COSEDecodeError("Failed to parse COSE_Sign1 outer array");
      }

      uint64_t tag = QCBORDecode_GetNthTagOfLast(&ctx, 0);
      if (tag != CBOR_TAG_COSE_SIGN1)
      {
        throw COSEDecodeError("Failed to parse COSE_Sign1 tag");
      }

      struct q_useful_buf_c protected_parameters = {};
      QCBORDecode_EnterBstrWrapped(
        &ctx, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, &protected_parameters);
      QCBORDecode_EnterMap(&ctx, nullptr);

      enum
      {
        ALG_INDEX,
        CONTENT_TYPE_INDEX,
        X5_CHAIN_INDEX,
        ISS_INDEX,
        FEED_INDEX,
        END_INDEX
      };
      QCBORItem header_items[END_INDEX + 1];

      header_items[ALG_INDEX].label.int64 = headers::PARAM_ALG;
      header_items[ALG_INDEX].uLabelType = QCBOR_TYPE_INT64;
      header_items[ALG_INDEX].uDataType = QCBOR_TYPE_INT64;

      header_items[CONTENT_TYPE_INDEX].label.int64 =
        headers::PARAM_CONTENT_TYPE;
      header_items[CONTENT_TYPE_INDEX].uLabelType = QCBOR_TYPE_INT64;
      header_items[CONTENT_TYPE_INDEX].uDataType = QCBOR_TYPE_TEXT_STRING;

      header_items[X5_CHAIN_INDEX].label.int64 = headers::PARAM_X5CHAIN;
      header_items[X5_CHAIN_INDEX].uLabelType = QCBOR_TYPE_INT64;
      header_items[X5_CHAIN_INDEX].uDataType = QCBOR_TYPE_ANY;

      header_items[ISS_INDEX].label.string =
        UsefulBuf_FromSZ(HEADER_PARAM_ISSUER);
      header_items[ISS_INDEX].uLabelType = QCBOR_TYPE_TEXT_STRING;
      header_items[ISS_INDEX].uDataType = QCBOR_TYPE_TEXT_STRING;

      header_items[FEED_INDEX].label.string =
        UsefulBuf_FromSZ(HEADER_PARAM_FEED);
      header_items[FEED_INDEX].uLabelType = QCBOR_TYPE_TEXT_STRING;
      header_items[FEED_INDEX].uDataType = QCBOR_TYPE_TEXT_STRING;

      header_items[END_INDEX].uLabelType = QCBOR_TYPE_NONE;

      QCBORDecode_GetItemsInMap(&ctx, header_items);
      qcbor_result = QCBORDecode_GetError(&ctx);
      if (qcbor_result != QCBOR_SUCCESS)
      {
        throw COSEDecodeError("Failed to decode protected header");
      }

      UvmEndorsementsProtectedHeader phdr = {};

      if (header_items[ALG_INDEX].uDataType != QCBOR_TYPE_NONE)
      {
        phdr.alg = header_items[ALG_INDEX].val.int64;
      }

      if (header_items[CONTENT_TYPE_INDEX].uDataType != QCBOR_TYPE_NONE)
      {
        phdr.content_type =
          qcbor_buf_to_string(header_items[CONTENT_TYPE_INDEX].val.string);
      }

      if (header_items[X5_CHAIN_INDEX].uDataType != QCBOR_TYPE_NONE)
      {
        phdr.x5_chain = decode_x5chain(ctx, header_items[X5_CHAIN_INDEX]);
      }

      if (header_items[ISS_INDEX].uDataType != QCBOR_TYPE_NONE)
      {
        phdr.iss = qcbor_buf_to_string(header_items[ISS_INDEX].val.string);
      }

      if (header_items[FEED_INDEX].uDataType != QCBOR_TYPE_NONE)
      {
        phdr.feed = qcbor_buf_to_string(header_items[FEED_INDEX].val.string);
      }

      QCBORDecode_ExitMap(&ctx);
      QCBORDecode_ExitBstrWrapped(&ctx);

      qcbor_result = QCBORDecode_GetError(&ctx);
      if (qcbor_result != QCBOR_SUCCESS)
      {
        throw COSEDecodeError(
          fmt::format("Failed to decode protected header: {}", qcbor_result));
      }

      return phdr;
    }
  }

  static std::span<const uint8_t> verify_uvm_endorsements_signature(
    const ccf::crypto::Pem& leaf_cert_pub_key,
    const std::vector<uint8_t>& uvm_endorsements_raw)
  {
    auto verifier = ccf::crypto::make_cose_verifier_from_key(leaf_cert_pub_key);

    std::span<uint8_t> payload;
    if (!verifier->verify(uvm_endorsements_raw, payload))
    {
      throw cose::COSESignatureValidationError("Signature verification failed");
    }

    return payload;
  }

  pal::UVMEndorsements verify_uvm_endorsements(
    const std::vector<uint8_t>& uvm_endorsements_raw,
    const pal::PlatformAttestationMeasurement& uvm_measurement,
    const std::vector<pal::UVMEndorsements>& uvm_roots_of_trust,
    bool enforce_uvm_roots_of_trust)
  {
    auto phdr = cose::decode_protected_header(uvm_endorsements_raw);

    if (!(cose::is_rsa_alg(phdr.alg) || cose::is_ecdsa_alg(phdr.alg)))
    {
      throw std::logic_error(fmt::format(
        "Signature algorithm {} is not one of expected: RSA, ECDSA", phdr.alg));
    }

    std::vector<std::string> pem_chain;
    pem_chain.reserve(phdr.x5_chain.size());
    for (auto const& c : phdr.x5_chain)
    {
      pem_chain.emplace_back(ccf::crypto::cert_der_to_pem(c).str());
    }

    const auto& did = phdr.iss;

    ccf::crypto::Pem pubk;
    const auto jwk = nlohmann::json::parse(
      didx509::resolve_jwk(pem_chain, did, true /* ignore time */));
    const auto generic_jwk = jwk.get<ccf::crypto::JsonWebKey>();
    switch (generic_jwk.kty)
    {
      case ccf::crypto::JsonWebKeyType::RSA:
      {
        auto rsa_jwk = jwk.get<ccf::crypto::JsonWebKeyRSAPublic>();
        pubk = ccf::crypto::make_rsa_public_key(rsa_jwk)->public_key_pem();
        break;
      }
      case ccf::crypto::JsonWebKeyType::EC:
      {
        auto ec_jwk = jwk.get<ccf::crypto::JsonWebKeyECPublic>();
        pubk = ccf::crypto::make_public_key(ec_jwk)->public_key_pem();
        break;
      }
      default:
      {
        throw std::logic_error(fmt::format(
          "Unsupported public key type ({}) for DID {}", generic_jwk.kty, did));
      }
    }

    auto raw_payload =
      verify_uvm_endorsements_signature(pubk, uvm_endorsements_raw);

    if (phdr.content_type != cose::headers::CONTENT_TYPE_APPLICATION_JSON_VALUE)
    {
      throw std::logic_error(fmt::format(
        "Unexpected payload content type {}, expected {}",
        phdr.content_type,
        cose::headers::CONTENT_TYPE_APPLICATION_JSON_VALUE));
    }

    UVMEndorsementsPayload payload = nlohmann::json::parse(raw_payload);
    if (payload.sevsnpvm_launch_measurement != uvm_measurement.hex_str())
    {
      throw std::logic_error(fmt::format(
        "Launch measurement in UVM endorsements payload {} is not equal "
        "to UVM attestation measurement {}",
        payload.sevsnpvm_launch_measurement,
        uvm_measurement.hex_str()));
    }

    LOG_INFO_FMT(
      "Successfully verified endorsements for attested measurement {} against "
      "{}, feed {}, svn {}",
      payload.sevsnpvm_launch_measurement,
      did,
      phdr.feed,
      payload.sevsnpvm_guest_svn);

    pal::UVMEndorsements end{did, phdr.feed, payload.sevsnpvm_guest_svn};

    if (
      enforce_uvm_roots_of_trust &&
      !matches_uvm_roots_of_trust(end, uvm_roots_of_trust))
    {
      throw std::logic_error(fmt::format(
        "UVM endorsements did {}, feed {}, svn {} "
        "do not match any of the known UVM roots of trust",
        end.did,
        end.feed,
        end.svn));
    }

    return end;
  }

  namespace pal
  {
    UVMEndorsements verify_uvm_endorsements_descriptor(
      const std::vector<uint8_t>& uvm_endorsements_raw,
      const pal::PlatformAttestationMeasurement& uvm_measurement)
    {
      return verify_uvm_endorsements(
        uvm_endorsements_raw,
        uvm_measurement,
        {}, // No roots of trust
        false); // Do not check against roots of trust
    }
  }

  pal::UVMEndorsements verify_uvm_endorsements_against_roots_of_trust(
    const std::vector<uint8_t>& uvm_endorsements_raw,
    const pal::PlatformAttestationMeasurement& uvm_measurement,
    const std::vector<pal::UVMEndorsements>& uvm_roots_of_trust)
  {
    return verify_uvm_endorsements(
      uvm_endorsements_raw,
      uvm_measurement,
      uvm_roots_of_trust,
      true); // Check against roots of trust
  }
}