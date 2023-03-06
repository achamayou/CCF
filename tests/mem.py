# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
import suite.test_requirements as reqs
import infra.logging_app as app
import infra.e2e_args
from infra.tx_status import TxStatus
import infra.checker
import infra.jwt_issuer
import infra.proc
import http
from http.client import HTTPResponse
import ssl
import socket
import os
from collections import defaultdict
import time
import json
import hashlib
import infra.clients
from infra.log_capture import flush_info
import ccf.receipt
from ccf.tx_id import TxID
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.x509 import ObjectIdentifier
import urllib.parse
import random
import re
import infra.crypto
from infra.runner import ConcurrentRunner
from hashlib import sha256
from infra.member import AckException
import e2e_common_endpoints
from types import MappingProxyType

from loguru import logger as LOG

METADATA = {
    "id": "MxSnvo5Hth_4AIVQHwAV_HmteGAumE4ATubwD6Xk6ig",
    "controller": "EC56E6D5-33BD-4544-8388-3F0613531257",
    "controllerDocument": {
        "id": "did:ccf:STHIGG-DEVBOX.europe.corp.microsoft.com:MxSnvo5Hth_4AIVQHwAV_HmteGAumE4ATubwD6Xk6ig",
        "verificationMethod": [
            {
                "id": "did:ccf:STHIGG-DEVBOX.europe.corp.microsoft.com:MxSnvo5Hth_4AIVQHwAV_HmteGAumE4ATubwD6Xk6ig#otddUaOI1h1V",
                "controller": "did:ccf:STHIGG-DEVBOX.europe.corp.microsoft.com:MxSnvo5Hth_4AIVQHwAV_HmteGAumE4ATubwD6Xk6ig",
                "type": "JsonWebKey2020",
                "publicKeyJwk": {
                    "crv": "Ed25519",
                    "kid": "otddUaOI1h1V",
                    "kty": "OKP",
                    "x": "uw1P3QaG2QfrsJA0bcSHV1xEcMWLUIqROKdOFue1nz4"                }
            },
            {
                "id": "did:ccf:STHIGG-DEVBOX.europe.corp.microsoft.com:MxSnvo5Hth_4AIVQHwAV_HmteGAumE4ATubwD6Xk6ig#cyZCX5PgrXxw",
                "controller": "did:ccf:STHIGG-DEVBOX.europe.corp.microsoft.com:MxSnvo5Hth_4AIVQHwAV_HmteGAumE4ATubwD6Xk6ig",
                "type": "JsonWebKey2020",
                "publicKeyJwk": {
                    "crv": "Ed25519",
                    "kid": "cyZCX5PgrXxw",
                    "kty": "OKP",
                    "x": "u9as8VxfBXbYtRGRzVCYafaaX1sLJKFJcerLAS57rVU"                }
            }
        ],
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
            {
                "@vocab": "https://github.com/microsoft/did-ccf/blob/main/DID_CCF.md#"            }
        ],
        "authentication": [
            "did:ccf:STHIGG-DEVBOX.europe.corp.microsoft.com:MxSnvo5Hth_4AIVQHwAV_HmteGAumE4ATubwD6Xk6ig#otddUaOI1h1V"        ],
        "assertionMethod": [
            "did:ccf:STHIGG-DEVBOX.europe.corp.microsoft.com:MxSnvo5Hth_4AIVQHwAV_HmteGAumE4ATubwD6Xk6ig#otddUaOI1h1V"        ],
        "keyAgreement": [
            "did:ccf:STHIGG-DEVBOX.europe.corp.microsoft.com:MxSnvo5Hth_4AIVQHwAV_HmteGAumE4ATubwD6Xk6ig#cyZCX5PgrXxw"        ]
    },
    "keyPairs": [
        {
            "id": "otddUaOI1h1V",
            "use": "sig",
            "algorithm": "EdDSA",
            "publicKey": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAuw1P3QaG2QfrsJA0bcSHV1xEcMWLUIqROKdOFue1nz4=\n-----END PUBLIC KEY-----\n",
            "privateKey": "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIDKbBd5Qa9T5ffyYd9WWjWeVo8dmu4WrI4/1QsL/bOzF\n-----END PRIVATE KEY-----\n",
            "state": "current",
            "curve": "curve25519"        },
        {
            "id": "cyZCX5PgrXxw",
            "use": "enc",
            "algorithm": "EdDSA",
            "publicKey": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAu9as8VxfBXbYtRGRzVCYafaaX1sLJKFJcerLAS57rVU=\n-----END PUBLIC KEY-----\n",
            "privateKey": "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIGxNAyyUXl+GTtBdoj627hjmZAG6gvK+/PwZ+UOcQTuD\n-----END PRIVATE KEY-----\n",
            "state": "current",
            "curve": "curve25519"        }
    ],
    "controllerDelegate": "a6f2d6efa67192037a35548f1bbd7efdf26ba5b718ca5d423fc431147571e7a3"}

METADATA_JSON = json.dumps(METADATA)

@reqs.description("Running transactions against logging app and measuring memory usage")
@reqs.supports_methods("/app/log/private", "/app/log/public")
@reqs.at_least_n_nodes(2)
@reqs.no_http2()
def test(network, args):
    primary, _ = network.find_primary()

    with primary.client("user0") as c:
        index = 0
        for k in range(100):
            subi = 100
            for i in range(subi):
                r = c.post("/app/log/public", {"id": index, "msg": METADATA_JSON}, log_capture=[])
                assert r.status_code == 200
                index += 1
            r = c.get("/node/memory", log_capture=[])
            peak_mb = r.body.json()["peak_allocated_heap_size"] / 1024 ** 2
            extrapolated = (peak_mb / ((k + 1) * subi) * 1000000) / 1024
            print(f"Using {peak_mb:.2f}Mb after {(k + 1) * subi} iterations (extrapolated: {extrapolated:.2f}Gb for 1m entries)")
    return network


def run(args):
    # Listen on two additional RPC interfaces for each node
    def additional_interfaces(local_node_id):
        return {
            "first_interface": f"127.{local_node_id}.0.1",
            "second_interface": f"127.{local_node_id}.0.2",
        }

    for local_node_id, node_host in enumerate(args.nodes):
        for interface_name, host in additional_interfaces(local_node_id).items():
            node_host.rpc_interfaces[interface_name] = infra.interfaces.RPCInterface(
                host=host,
                app_protocol=infra.interfaces.AppProtocol.HTTP2
                if args.http2
                else infra.interfaces.AppProtocol.HTTP1,
            )

    txs = app.LoggingTxs("user0")
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        pdb=args.pdb,
        txs=txs,
    ) as network:
        network.start_and_open(args)
        test(network, args)


if __name__ == "__main__":
    cr = ConcurrentRunner()

    cr.add(
        "js",
        run,
        package="libjs_generic",
        nodes=infra.e2e_args.max_nodes(cr.args, f=0),
        initial_user_count=4,
        initial_member_count=2,
    )

    cr.run()
