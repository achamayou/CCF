# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
import suite.test_requirements as reqs
import infra.logging_app as app
import infra.e2e_args
from ccf.tx_status import TxStatus
import infra.checker
import infra.jwt_issuer
import inspect
import http
from http.client import HTTPResponse
import ssl
import socket
import os
from collections import defaultdict
import time
import json
import hashlib
import ccf.clients
from ccf.log_capture import flush_info
import ccf.receipt
from ccf.tx_id import TxID
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import urllib.parse
import random
import re
import infra.crypto
from infra.runner import ConcurrentRunner

from loguru import logger as LOG

@reqs.description("Test host notify on table write")
@reqs.supports_methods("log/public/notify")
@reqs.at_least_n_nodes(2)
def test_notify(network, args):
    primary, _ = network.find_primary()
    user = network.users[0]

    with primary.client(user.local_id) as c:
        r = c.post("/app/log/public/notify", "Hello World")
        assert r.status_code == http.HTTPStatus.OK.value, r.status_code
        c.wait_for_commit(r)

    return network

def run(args):
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        pdb=args.pdb,
    ) as network:
        network.start_and_join(args)
        network = test_notify(network, args)


if __name__ == "__main__":
    cr = ConcurrentRunner()

    cr.add(
        "cpp",
        run,
        package="samples/apps/logging/liblogging",
        js_app_bundle=None,
        nodes=infra.e2e_args.min_nodes(cr.args, f=1),
        initial_user_count=1,
        initial_member_count=1,
    )

    cr.run()
