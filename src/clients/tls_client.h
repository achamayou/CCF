// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "../ds/buffer.h"
#include "../tls/ca.h"
#include "../tls/cert.h"
#include "../tls/error_string.h"

#include <cstdint>
#include <cstring>
#include <iostream>
#include <mbedtls/config.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string>
#include <vector>

class TlsClient
{
private:
  std::string host;
  std::string port;
  std::shared_ptr<tls::CA> node_ca;
  std::shared_ptr<tls::Cert> cert;
  bool connected = false;

  mbedtls_net_context server_fd;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;

  void connect()
  {
    auto err = mbedtls_ctr_drbg_seed(
      &ctr_drbg, mbedtls_entropy_func, &entropy, nullptr, 0);
    if (err)
      throw std::logic_error(tls::error_string(err));

    err = mbedtls_net_connect(
      &server_fd, host.c_str(), port.c_str(), MBEDTLS_NET_PROTO_TCP);
    if (err)
      throw std::logic_error(tls::error_string(err));

    err = mbedtls_ssl_config_defaults(
      &conf,
      MBEDTLS_SSL_IS_CLIENT,
      MBEDTLS_SSL_TRANSPORT_STREAM,
      MBEDTLS_SSL_PRESET_DEFAULT);
    if (err)
      throw std::logic_error(tls::error_string(err));

    if (cert != nullptr)
      cert->use(&ssl, &conf);
    if (node_ca != nullptr)
      node_ca->use(&conf);

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);

    err = mbedtls_ssl_setup(&ssl, &conf);
    if (err)
      throw std::logic_error(tls::error_string(err));

    if (err)
      throw std::logic_error(tls::error_string(err));

    mbedtls_ssl_set_bio(
      &ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, nullptr);

    while (true)
    {
      err = mbedtls_ssl_handshake(&ssl);
      if (err == 0)
        break;
      if (
        (err != MBEDTLS_ERR_SSL_WANT_READ) &&
        (err != MBEDTLS_ERR_SSL_WANT_WRITE))
        throw std::logic_error(tls::error_string(err));
    }
    connected = true;
  }

  void teardown()
  {
    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
  }

  void init()
  {
    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    try
    {
      connect();
    }
    catch (const std::exception&)
    {
      teardown();
      throw;
    }
  }

public:
  TlsClient(
    const std::string& host,
    const std::string& port,
    std::shared_ptr<tls::CA> node_ca = nullptr,
    std::shared_ptr<tls::Cert> cert = nullptr) :
    host(host),
    port(port),
    node_ca(node_ca),
    cert(cert)
  {
    init();
  }

  TlsClient(const TlsClient& c) :
    host(c.host),
    port(c.port),
    node_ca(c.node_ca),
    cert(c.cert)
  {
    init();
  }

  virtual ~TlsClient()
  {
    // Signal the end of the connection
    if (connected)
      mbedtls_ssl_close_notify(&ssl);
    teardown();
  }

  auto get_ciphersuite_name()
  {
    return mbedtls_ssl_get_ciphersuite(&ssl);
  }

  void write(CBuffer b)
  {
    for (size_t written = 0; written < b.n;)
    {
      auto ret = mbedtls_ssl_write(&ssl, b.p + written, b.n - written);
      if (ret > 0)
        written += ret;
      else
        throw std::logic_error(tls::error_string(ret));
    }
  }

  std::vector<uint8_t> read(size_t read_size)
  {
    std::vector<uint8_t> buf(read_size);
    auto ret = mbedtls_ssl_read(&ssl, buf.data(), buf.size());
    if (ret > 0)
    {
      buf.resize(ret);
    }
    else if (ret == 0)
    {
      connected = false;
      throw std::logic_error("Underlying transport closed");
    }
    else
    {
      throw std::logic_error(tls::error_string(ret));
    }

    return buf;
  }

  bool bytes_available()
  {
    return mbedtls_ssl_get_bytes_avail(&ssl) > 0;
  }

  std::vector<uint8_t> read_all()
  {
    constexpr auto read_size = 4096;
    std::vector<uint8_t> buf(read_size);
    auto ret = mbedtls_ssl_read(&ssl, buf.data(), buf.size());
    if (ret > 0)
    {
      buf.resize(ret);
    }
    else if (ret == 0)
    {
      connected = false;
      throw std::logic_error("Underlying transport closed");
    }
    else
    {
      throw std::logic_error(tls::error_string(ret));
    }

    return buf;
  }

  void set_tcp_nodelay(bool on)
  {
    int option = on ? 1 : 0;
    setsockopt(
      server_fd.fd, IPPROTO_TCP, TCP_NODELAY, (char*)&option, sizeof(int));
  }
};
