# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from ccf.cose import (
    get_priv_key_type,
    cert_fingerprint,
    default_algorithm_for_key,
    from_cryptography_eckey_obj,
)

from typing import Optional

import argparse
import base64
import cbor2
import json
import sys
from datetime import datetime
import pycose.headers  # type: ignore
from pycose.keys.ec2 import EC2Key  # type: ignore
from pycose.keys.curves import P256, P384, P521  # type: ignore
from pycose.keys.keyparam import EC2KpCurve, EC2KpX, EC2KpY, EC2KpD  # type: ignore
from pycose.messages import Sign1Message  # type: ignore
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding

Pem = str


def cert_pem_to_der(pem: Pem) -> bytes:
    cert = load_pem_x509_certificate(pem.encode("ascii"))
    return cert.public_bytes(Encoding.DER)


def _parser(description):
    parser = argparse.ArgumentParser(
        description=description,
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "--content",
        help="Path to content file, or '-' for stdin",
        type=str,
        required=True,
    )
    parser.add_argument(
        "--signing-cert",
        help="Path to signing key, PEM-encoded",
        type=str,
        required=True,
    )
    return parser


def create_cose_sign1_prepare(
    payload: bytes,
    cert_pem: Pem,
    additional_protected_header: Optional[dict] = None,
) -> dict:
    cert = load_pem_x509_certificate(cert_pem.encode("ascii"), default_backend())
    alg = default_algorithm_for_key(cert.public_key())
    # What about content type?
    protected_header = {
        pycose.headers.Algorithm: alg,
        pycose.headers.X5chain: [cert_pem_to_der(cert_pem)],
        pycose.headers.ContentType: "application/vnd.dummy+json",
    }

    msg = Sign1Message(phdr=protected_header, payload=payload)
    tbs = cbor2.dumps(["Signature1", msg.phdr_encoded, b"", payload])

    assert cert.signature_hash_algorithm
    digester = hashes.Hash(cert.signature_hash_algorithm)
    digester.update(tbs)
    digest = digester.finalize()
    return {"alg": alg, "value": base64.b64encode(digest).decode()}


def prepare_cli():
    args = _parser("Prepare").parse_args()

    with open(
        args.content, "rb"
    ) if args.content != "-" else sys.stdin.buffer as content_:
        content = content_.read()

    with open(args.signing_cert, "r", encoding="utf-8") as signing_cert_:
        signing_cert = signing_cert_.read()

    digest = create_cose_sign1_prepare(content, signing_cert)
    json.dump(digest, sys.stdout)


if __name__ == "__main__":
    prepare_cli()
