# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import abc
import contextlib
import json
import time
import sys
import os
import subprocess
import tempfile
from dataclasses import dataclass
from http.client import HTTPResponse
from io import BytesIO
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
import struct
import base64
import re
from typing import Union, Optional, List, Any
from ccf.tx_id import TxID
import copy

import httpx
from loguru import logger as LOG  # type: ignore

import ccf.commit
from ccf.log_capture import flush_info

import base64, hashlib, hmac, time
import email.utils

import requests
from requests.compat import urlparse
from requests.exceptions import RequestException

from base64 import b64encode
import hashlib

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from base64 import b64encode
from collections import defaultdict
from datetime import datetime
from typing import Callable, DefaultDict, FrozenSet, List, Tuple


def sign_headers(
    key_id: str,
    sign: Callable[[bytes], bytes],
    method: str,
    path: str,
    headers_to_sign: Tuple[Tuple[str, str], ...],
    headers_to_ignore: FrozenSet[str] = frozenset(
        ("keep-alive", "transfer-encoding", "connection")
    ),
) -> Tuple[Tuple[str, str], ...]:
    created = str(int(datetime.now().timestamp()))

    def _signature_input() -> Tuple[Tuple[str, str], ...]:
        method_lower = method.lower()
        headers_with_pseudo_headers = (
            ("(created)", created),
            ("(request-target)", f"{method_lower} {path}"),
        ) + headers_to_sign

        headers_lists: DefaultDict[str, List[str]] = defaultdict(list)
        for key, value in headers_with_pseudo_headers:
            key_lower = key.lower()
            if key_lower not in headers_to_ignore:
                headers_lists[key_lower].append(value.strip())
        return tuple((key, ", ".join(values)) for key, values in headers_lists.items())

    signature_input = _signature_input()

    signature = b64encode(
        sign(
            "\n".join(f"{key}: {value}" for key, value in signature_input).encode(
                "ascii"
            )
        )
    ).decode("ascii")

    headers = " ".join(key for key, _ in signature_input)
    signature = f'keyId="{key_id}", created={created}, headers="{headers}", signature="{signature}"'

    return (("signature", signature),) + headers_to_sign


class HttpSignature(httpx.Auth):
    requires_request_body = True

    def __init__(self, key_id, pem_private_key):
        self.key_id = key_id
        self.private_key = load_pem_private_key(
            pem_private_key, password=None, backend=default_backend()
        )

    def auth_flow(self, request):
        body_digest = b64encode(hashlib.sha256(request.content).digest()).decode(
            "ascii"
        )
        headers_to_sign = tuple(request.headers.items()) + (
            ("digest", f"SHA256={body_digest}"),
        )
        request.headers = httpx.Headers(
            sign_headers(
                self.key_id,
                self.private_key.sign,
                str(request.method),
                request.url.raw_path,
                headers_to_sign,
            )
        )
        yield request


class HttpSig(httpx.Auth):
    requires_request_body = True

    def __init__(self, key_id, pem_private_key):
        self.key_id = key_id
        self.private_key = load_pem_private_key(
            pem_private_key, password=None, backend=default_backend()
        )

    def auth_flow(self, request):
        body_digest = b64encode(hashlib.sha256(request.content).digest()).decode(
            "ascii"
        )
        request.headers["digest"] = f"SHA-256={body_digest}"
        string_to_sign = "\n".join(
            [
                f"(request-target): {request.method.lower()} {request.url.raw_path.decode('utf-8')}",
                f"digest: SHA-256={body_digest}",
                f"content-length: {len(request.content)}",
            ]
        ).encode("utf-8")
        print("YYYYYYYYYY")
        print(string_to_sign)
        print("YYYYYYYYYY")
        signature = self.private_key.sign(
            signature_algorithm=ec.ECDSA(algorithm=hashes.SHA256()), data=string_to_sign
        )
        b64signature = b64encode(signature).decode("ascii")
        request.headers[
            "authorization"
        ] = f'Signature keyId="{self.key_id}",algorithm="ecdsa-sha256",headers="(request-target) digest content-length",signature="{b64signature}"'
        print(request.headers["authorization"])
        yield request


class RequestsHttpSignatureException(RequestException):
    """An error occurred while constructing the HTTP Signature for your request."""


class Crypto:
    def __init__(self, algorithm):
        if algorithm != "hmac-sha256":
            from cryptography.hazmat.primitives.serialization import (
                load_pem_private_key,
                load_pem_public_key,
            )
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives.asymmetric import rsa, ec
            from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
            from cryptography.hazmat.primitives.hashes import SHA1, SHA256, SHA512
        self.__dict__.update(locals())

    def sign(self, string_to_sign, key, passphrase=None):
        if self.algorithm == "hmac-sha256":
            return hmac.new(key, string_to_sign, digestmod=hashlib.sha256).digest()
        key = self.load_pem_private_key(
            key, password=passphrase, backend=self.default_backend()
        )
        if self.algorithm in {"rsa-sha1", "rsa-sha256"}:
            hasher = self.SHA1() if self.algorithm.endswith("sha1") else self.SHA256()
            return key.sign(
                padding=self.PKCS1v15(), algorithm=hasher, data=string_to_sign
            )
        elif self.algorithm in {"rsa-sha512"}:
            hasher = self.SHA512()
            return key.sign(
                padding=self.PKCS1v15(), algorithm=hasher, data=string_to_sign
            )
        elif self.algorithm == "ecdsa-sha256":
            return key.sign(
                signature_algorithm=self.ec.ECDSA(algorithm=self.SHA256()),
                data=string_to_sign,
            )

    def verify(self, signature, string_to_sign, key):
        if self.algorithm == "hmac-sha256":
            assert (
                signature
                == hmac.new(key, string_to_sign, digestmod=hashlib.sha256).digest()
            )
        else:
            key = self.load_pem_public_key(key, backend=self.default_backend())
            hasher = self.SHA1() if self.algorithm.endswith("sha1") else self.SHA256()
            if self.algorithm == "ecdsa-sha256":
                key.verify(signature, string_to_sign, self.ec.ECDSA(hasher))
            else:
                key.verify(signature, string_to_sign, self.PKCS1v15(), hasher)


class HTTPSignatureAuth(requests.auth.AuthBase):
    hasher_constructor = hashlib.sha256
    known_algorithms = {
        "rsa-sha1",
        "rsa-sha256",
        "rsa-sha512",
        "hmac-sha256",
        "ecdsa-sha256",
    }

    def __init__(
        self,
        key,
        key_id,
        algorithm="hmac-sha256",
        headers=None,
        passphrase=None,
        expires_in=None,
        spy=None,
    ):
        """
        :param typing.Union[bytes, string] passphrase: The passphrase for an encrypted RSA private key
        :param datetime.timedelta expires_in: The time after which this signature should expire
        """
        assert algorithm in self.known_algorithms
        self.key = key
        self.key_id = key_id
        self.algorithm = algorithm
        self.headers = [h.lower() for h in headers] if headers is not None else ["date"]
        self.passphrase = (
            passphrase
            if passphrase is None or isinstance(passphrase, bytes)
            else passphrase.encode()
        )
        self.expires_in = expires_in
        self.spy = spy

    def add_date(self, request, timestamp):
        if "Date" not in request.headers:
            request.headers["Date"] = email.utils.formatdate(timestamp, usegmt=True)

    def add_digest(self, request):
        if request.body is None and "digest" in self.headers:
            raise RequestsHttpSignatureException(
                "Could not compute digest header for request without a body"
            )
        if request.body is not None and "Digest" not in request.headers:
            if "digest" not in self.headers:
                self.headers.append("digest")
            digest = self.hasher_constructor(request.body).digest()
            request.headers["Digest"] = "SHA-256=" + base64.b64encode(digest).decode()

    @classmethod
    def get_string_to_sign(
        self, request, headers, created_timestamp, expires_timestamp
    ):
        sts = []
        r = requests.Request(request.method, str(request.url))
        for header in headers:
            if header == "(request-target)":
                path_url = requests.models.RequestEncodingMixin.path_url.fget(r)
                sts.append("{}: {} {}".format(header, r.method.lower(), path_url))
            elif header == "(created)":
                sts.append("{}: {}".format(header, created_timestamp))
            elif header == "(expires)":
                assert (
                    expires_timestamp is not None
                ), 'You should provide the "expires_in" argument when using the (expires) header'
                sts.append("{}: {}".format(header, int(expires_timestamp)))
            else:
                if header.lower() == "host":
                    url = urlparse(r.url)
                    value = request.headers.get("host", url.hostname)
                    if (
                        url.scheme == "http"
                        and url.port not in [None, 80]
                        or url.scheme == "https"
                        and url.port not in [443, None]
                    ):
                        value = "{}:{}".format(value, url.port)
                else:
                    value = request.headers[header]
                sts.append("{k}: {v}".format(k=header.lower(), v=value))
        ss = "\n".join(sts).encode()
        print("XXXXX")
        print(ss)
        print("XXXXX")
        return ss

    def create_signature_string(self, request):
        created_timestamp = int(time.time())
        expires_timestamp = None
        if self.expires_in is not None:
            expires_timestamp = created_timestamp + self.expires_in.total_seconds()
        self.add_date(request, created_timestamp)
        self.add_digest(request)
        raw_sig = Crypto(self.algorithm).sign(
            string_to_sign=self.get_string_to_sign(
                request, self.headers, created_timestamp, expires_timestamp
            ),
            key=self.key.encode() if isinstance(self.key, str) else self.key,
            passphrase=self.passphrase,
        )
        sig = base64.b64encode(raw_sig).decode()
        sig_struct = [
            ("keyId", self.key_id),
            ("algorithm", self.algorithm),
            ("headers", " ".join(self.headers)),
            ("signature", sig),
            ("created", int(created_timestamp)),
        ]
        if expires_timestamp is not None:
            sig_struct.append(("expires", int(expires_timestamp)))
        return ",".join('{}="{}"'.format(k, v) for k, v in sig_struct)

    def __call__(self, request):
        request.headers["Authorization"] = "Signature " + self.create_signature_string(
            request
        )
        print(request.headers)
        print(request.headers["authorization"])
        print("SPYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY")
        r = copy.deepcopy(request)
        rs = self.spy.auth_flow(r)
        rs = next(rs)
        print(rs.headers)
        print(rs.headers["authorization"])
        sys.exit(0)
        return request

    @classmethod
    def get_sig_struct(self, request, scheme="Authorization"):
        sig_struct = request.headers[scheme]
        if scheme == "Authorization":
            sig_struct = sig_struct.split(" ", 1)[1]
        return {
            i.split("=", 1)[0]: i.split("=", 1)[1].strip('"')
            for i in sig_struct.split(",")
        }

    @classmethod
    def verify(self, request, key_resolver, scheme="Authorization"):
        if scheme == "Authorization":
            assert "Authorization" in request.headers, "No Authorization header found"
            msg = (
                'Unexpected scheme found in Authorization header (expected "Signature")'
            )
            assert request.headers["Authorization"].startswith("Signature "), msg
        elif scheme == "Signature":
            assert "Signature" in request.headers, "No Signature header found"
        else:
            raise RequestsHttpSignatureException(
                'Unknown signature scheme "{}"'.format(scheme)
            )

        sig_struct = self.get_sig_struct(request, scheme=scheme)
        for field in "keyId", "algorithm", "signature":
            assert (
                field in sig_struct
            ), 'Required signature parameter "{}" not found'.format(field)
        assert (
            sig_struct["algorithm"] in self.known_algorithms
        ), "Unknown signature algorithm"
        created_timestamp = int(sig_struct["created"])
        expires_timestamp = sig_struct.get("expires")
        if expires_timestamp is not None:
            expires_timestamp = int(expires_timestamp)
        headers = sig_struct.get("headers", "date").split(" ")
        sig = base64.b64decode(sig_struct["signature"])
        sts = self.get_string_to_sign(
            request, headers, created_timestamp, expires_timestamp=expires_timestamp
        )
        key = key_resolver(
            key_id=sig_struct["keyId"], algorithm=sig_struct["algorithm"]
        )
        Crypto(sig_struct["algorithm"]).verify(sig, sts, key)


loguru_tag_regex = re.compile(r"\\?</?((?:[fb]g\s)?[^<>\s]*)>")


def escape_loguru_tags(s):
    return loguru_tag_regex.sub(lambda match: f"\\{match[0]}", s)


def truncate(string: str, max_len: int = 256):
    if len(string) > max_len:
        return f"{string[: max_len]} + {len(string) - max_len} chars"
    else:
        return string


CCF_TX_ID_HEADER = "x-ms-ccf-transaction-id"

DEFAULT_CONNECTION_TIMEOUT_SEC = 3
DEFAULT_REQUEST_TIMEOUT_SEC = 10
DEFAULT_COMMIT_TIMEOUT_SEC = 3

CONTENT_TYPE_TEXT = "text/plain"
CONTENT_TYPE_JSON = "application/json"
CONTENT_TYPE_BINARY = "application/octet-stream"


@dataclass
class Request:
    #: Resource path (with optional query string)
    path: str
    #: Body of request
    body: Optional[Union[dict, str, bytes]]
    #: HTTP verb
    http_verb: str
    #: HTTP headers
    headers: dict
    #: Whether redirect headers should be transparently followed
    allow_redirects: bool

    def __str__(self):
        string = f"<cyan>{self.http_verb}</> <green>{self.path}</>"
        if self.headers:
            string += f" <blue>{truncate(str(self.headers), max_len=25)}</>"
        if self.body is not None:
            string += f' {truncate(f"{self.body}")}'

        return string


@dataclass
class Identity:
    """
    Identity (as private key and corresponding certificate) for a :py:class:`ccf.clients.CCFClient` client.
    """

    #: Path to file containing private key
    key: str
    #: Path to file containing PEM certificate
    cert: str
    #: Identity description
    description: str


class FakeSocket:
    def __init__(self, bs):
        self.file = BytesIO(bs)

    def makefile(self, *args, **kwargs):
        return self.file


class ResponseBody(abc.ABC):
    @abc.abstractmethod
    def data(self) -> bytes:
        pass

    @abc.abstractmethod
    def text(self) -> str:
        pass

    @abc.abstractmethod
    def json(self) -> Any:
        pass

    def __len__(self):
        return len(self.data())

    def __str__(self):
        try:
            return self.text()
        except UnicodeDecodeError:
            return self.__repr__()

    def __repr__(self):
        return repr(self.data())


class RequestsResponseBody(ResponseBody):
    def __init__(self, response: httpx.Response):
        self._response = response

    def data(self):
        return self._response.content

    def text(self):
        return self._response.text

    def json(self):
        return self._response.json()


class RawResponseBody(ResponseBody):
    def __init__(self, data: bytes):
        self._data = data

    def data(self):
        return self._data

    def text(self):
        return self._data.decode()

    def json(self):
        return json.loads(self._data)


@dataclass
class Response:
    """
    Response to request sent via :py:class:`ccf.clients.CCFClient`
    """

    #: Response HTTP status code
    status_code: int
    #: Response body
    body: ResponseBody
    #: CCF sequence number
    seqno: Optional[int]
    #: CCF consensus view
    view: Optional[int]
    #: Response HTTP headers
    headers: dict

    def __str__(self):
        versioned = (self.view, self.seqno) != (None, None)
        status_color = "red" if self.status_code // 100 in (4, 5) else "green"
        body_s = escape_loguru_tags(truncate(str(self.body)))
        # Body can't end with a \, or it will escape the loguru closing tag
        if len(body_s) > 0 and body_s[-1] == "\\":
            body_s += " "

        return (
            f"<{status_color}>{self.status_code}</> "
            + (f"@<magenta>{self.view}.{self.seqno}</> " if versioned else "")
            + f"<yellow>{body_s}</>"
        )

    @staticmethod
    def from_requests_response(rr):
        tx_id = TxID.from_str(rr.headers.get(CCF_TX_ID_HEADER))
        return Response(
            status_code=rr.status_code,
            body=RequestsResponseBody(rr),
            seqno=tx_id.seqno,
            view=tx_id.view,
            headers=rr.headers,
        )

    @staticmethod
    def from_raw(raw):
        # Raw is the output of curl, which is a full HTTP response.
        # But in the case of a redirect, it is multiple concatenated responses.
        # We want the final response, so we keep constructing new responses from this stream until we have reached the end
        while True:
            sock = FakeSocket(raw)
            response = HTTPResponse(sock)
            response.begin()
            response_len = sock.file.tell() + response.length
            raw_len = len(raw)
            if raw_len == response_len:
                break
            raw = raw[response_len:]

        raw_body = response.read()

        tx_id = TxID.from_str(response.getheader(CCF_TX_ID_HEADER))
        return Response(
            response.status,
            body=RawResponseBody(raw_body),
            seqno=tx_id.seqno,
            view=tx_id.view,
            headers=response.headers,
        )


def human_readable_size(n):
    suffixes = ("B", "KB", "MB", "GB")
    i = 0
    while n >= 1024 and i < len(suffixes) - 1:
        n /= 1024.0
        i += 1
    return f"{n:,.2f} {suffixes[i]}"


class CCFConnectionException(Exception):
    """
    Exception raised if a :py:class:`ccf.clients.CCFClient` instance cannot successfully establish
    a connection with a target CCF node.
    """


def get_curve(ca_file):
    # Auto detect EC curve to use based on server CA
    ca_bytes = open(ca_file, "rb").read()
    return (
        x509.load_pem_x509_certificate(ca_bytes, default_backend()).public_key().curve
    )


def unpack_seqno_or_view(data):
    (value,) = struct.unpack("<q", data)
    if value == -sys.maxsize - 1:
        return None
    return value


class CurlClient:
    """
    This client uses Curl to send HTTP requests to CCF, and logs all Curl commands it runs.
    These commands could also be run manually, or used by another client tool.
    """

    def __init__(self, host, port, ca=None, session_auth=None, signing_auth=None):
        self.host = host
        self.port = port
        self.ca = ca
        self.session_auth = session_auth
        self.signing_auth = signing_auth
        self.ca_curve = get_curve(self.ca)

    def request(self, request, timeout=DEFAULT_REQUEST_TIMEOUT_SEC):
        with tempfile.NamedTemporaryFile() as nf:
            if self.signing_auth:
                cmd = ["scurl.sh"]
            else:
                cmd = ["curl"]

            url = f"https://{self.host}:{self.port}{request.path}"

            cmd += [
                url,
                "-X",
                request.http_verb,
                "-i",
                f"-m {timeout}",
            ]

            if request.allow_redirects:
                cmd.append("-L")

            if request.body is not None:
                if isinstance(request.body, str) and request.body.startswith("@"):
                    # Request is already a file path - pass it directly
                    cmd.extend(["--data-binary", request.body])
                    if request.body.lower().endswith(".json"):
                        content_type = CONTENT_TYPE_JSON
                    else:
                        content_type = CONTENT_TYPE_BINARY
                else:
                    # Write request body to temp file
                    if isinstance(request.body, str):
                        msg_bytes = request.body.encode()
                        content_type = CONTENT_TYPE_TEXT
                    elif isinstance(request.body, bytes):
                        msg_bytes = request.body
                        content_type = CONTENT_TYPE_BINARY
                    else:
                        msg_bytes = json.dumps(request.body).encode()
                        content_type = CONTENT_TYPE_JSON
                    LOG.debug(f"Writing request body: {truncate(msg_bytes)}")
                    nf.write(msg_bytes)
                    nf.flush()
                    cmd.extend(["--data-binary", f"@{nf.name}"])
                if not "content-type" in request.headers and len(request.body) > 0:
                    request.headers["content-type"] = content_type

            # Set requested headers first - so they take precedence over defaults
            for k, v in request.headers.items():
                cmd.extend(["-H", f"{k}: {v}"])

            if self.ca:
                cmd.extend(["--cacert", self.ca])
            if self.session_auth:
                cmd.extend(["--key", self.session_auth.key])
                cmd.extend(["--cert", self.session_auth.cert])
            if self.signing_auth:
                cmd.extend(["--signing-key", self.signing_auth.key])
                cmd.extend(["--signing-cert", self.signing_auth.cert])

            cmd_s = " ".join(cmd)
            env = {k: v for k, v in os.environ.items()}

            LOG.debug(f"Running: {cmd_s}")
            rc = subprocess.run(cmd, capture_output=True, check=False, env=env)

            if rc.returncode != 0:
                if rc.returncode == 60:  # PEER_FAILED_VERIFICATION
                    raise CCFConnectionException
                if rc.returncode == 28:  # OPERATION_TIMEDOUT
                    raise TimeoutError
                LOG.error(rc.stderr)
                raise RuntimeError(f"Curl failed with return code {rc.returncode}")

            return Response.from_raw(rc.stdout)


class HTTPSignatureAuth_AlwaysDigest(HTTPSignatureAuth):
    """
    Support for HTTP signatures with empty body.
    """

    def add_digest(self, request):
        # Add digest of empty body, never leave it blank
        if not hasattr(request, "body"):
            setattr(request, "body", getattr(request, "_content", None))

        if request.body is None:
            if "digest" not in self.headers:
                self.headers.append("digest")
            digest = self.hasher_constructor(b"").digest()
            request.headers["Digest"] = "SHA-256=" + base64.b64encode(digest).decode()
        else:
            super(HTTPSignatureAuth_AlwaysDigest, self).add_digest(request)


class RequestClient:
    """
    CCF default client and wrapper around Python Requests, handling HTTP signatures.
    """

    _auth_provider = HTTPSignatureAuth_AlwaysDigest

    def __init__(
        self,
        host: str,
        port: int,
        ca: str,
        session_auth: Optional[Identity] = None,
        signing_auth: Optional[Identity] = None,
    ):
        self.host = host
        self.port = port
        self.ca = ca
        self.session_auth = session_auth
        self.signing_auth = signing_auth
        self.key_id = None
        client_args = {"verify": self.ca}
        if self.session_auth:
            client_args["cert"] = (self.session_auth.cert, self.session_auth.key)
        self.session = httpx.Client(**client_args)
        if self.signing_auth:
            with open(self.signing_auth.cert, encoding="utf-8") as cert_file:
                self.key_id = (
                    x509.load_pem_x509_certificate(
                        cert_file.read().encode(), default_backend()
                    )
                    .fingerprint(hashes.SHA256())
                    .hex()
                )

    def request(
        self,
        request: Request,
        timeout: int = DEFAULT_REQUEST_TIMEOUT_SEC,
    ):
        extra_headers = {}
        extra_headers.update(request.headers)

        auth_value = None
        auth = None
        if self.signing_auth is not None:
            # Add content length of 0 when signing a GET request
            if request.http_verb == "GET":
                if (
                    "Content-Length" in extra_headers
                    and extra_headers.get("Content-Length") != "0"
                ):
                    raise ValueError(
                        "Content-Length should be set to 0 for GET requests"
                    )
                else:
                    extra_headers["Content-Length"] = "0"
            auth_value = RequestClient._auth_provider(
                algorithm="ecdsa-sha256",
                key=open(self.signing_auth.key, "rb").read(),
                key_id=self.key_id,
                headers=["(request-target)", "Digest", "Content-Length"],
                spy=HttpSig(self.key_id, open(self.signing_auth.key, "rb").read()),
            )
            auth = HttpSig(self.key_id, open(self.signing_auth.key, "rb").read())
            # auth=auth_value

        request_body = None
        if request.body is not None:
            if isinstance(request.body, str) and request.body.startswith("@"):
                # Request is a file path - read contents
                with open(request.body[1:], "rb") as f:
                    request_body = f.read()
                if request.body.lower().endswith(".json"):
                    content_type = CONTENT_TYPE_JSON
                else:
                    content_type = CONTENT_TYPE_BINARY
            elif isinstance(request.body, str):
                request_body = request.body.encode()
                content_type = CONTENT_TYPE_TEXT
            elif isinstance(request.body, bytes):
                request_body = request.body
                content_type = CONTENT_TYPE_BINARY
            else:
                request_body = json.dumps(request.body).encode()
                content_type = CONTENT_TYPE_JSON

            if not "content-type" in request.headers and len(request.body) > 0:
                extra_headers["content-type"] = content_type

        try:
            response = self.session.request(
                request.http_verb,
                url=f"https://{self.host}:{self.port}{request.path}",
                auth=auth,
                headers=extra_headers,
                allow_redirects=request.allow_redirects,
                timeout=timeout,
                data=request_body,
            )
        except httpx.ReadTimeout as exc:
            raise TimeoutError from exc
        except httpx.NetworkError as exc:
            raise CCFConnectionException from exc
        except Exception as exc:
            raise RuntimeError("Request client failed with unexpected error") from exc

        return Response.from_requests_response(response)


class CCFClient:
    """
    Client used to connect securely and issue requests to a given CCF node.

    This is a wrapper around either Python Requests over TLS or curl with added:

    - Retry logic when connecting to nodes that are joining the network
    - Support for HTTP signatures (https://tools.ietf.org/html/draft-cavage-http-signatures-12).

    :param str host: RPC IP address or domain name of node to connect to.
    :param int port: RPC port number of node to connect to.
    :param str ca: Path to CCF network certificate.
    :param Identity session_auth: Path to private key and certificate to be used as client authentication for the session (optional).
    :param Identity signing_auth: Path to private key and certificate to be used to sign requests for the session (optional).
    :param int connection_timeout: Maximum time to wait for successful connection establishment before giving up.
    :param str description: Message to print on each request emitted with this client.

    A :py:exc:`CCFConnectionException` exception is raised if the connection is not established successfully within ``connection_timeout`` seconds.
    """

    client_impl: Union[CurlClient, RequestClient]

    def __init__(
        self,
        host: str,
        port: int,
        ca: str,
        session_auth: Optional[Identity] = None,
        signing_auth: Optional[Identity] = None,
        connection_timeout: int = DEFAULT_CONNECTION_TIMEOUT_SEC,
        description: Optional[str] = None,
    ):
        self.connection_timeout = connection_timeout
        self.name = f"[{host}:{port}]"
        self.description = description or self.name
        self.is_connected = False
        self.auth = bool(session_auth)
        self.sign = bool(signing_auth)

        if os.getenv("CURL_CLIENT"):
            self.client_impl = CurlClient(host, port, ca, session_auth, signing_auth)
        else:
            self.client_impl = RequestClient(host, port, ca, session_auth, signing_auth)

    def _response(self, response: Response) -> Response:
        LOG.info(response)
        return response

    def _call(
        self,
        path: str,
        body: Optional[Union[str, dict, bytes]] = None,
        http_verb: str = "POST",
        headers: Optional[dict] = None,
        timeout: int = DEFAULT_REQUEST_TIMEOUT_SEC,
        log_capture: Optional[list] = None,
        allow_redirects=True,
    ) -> Response:
        if headers is None:
            headers = {}
        r = Request(path, body, http_verb, headers, allow_redirects)

        flush_info([f"{self.description} {r}"], log_capture, 3)
        response = self.client_impl.request(r, timeout)
        flush_info([str(response)], log_capture, 3)
        return response

    def call(
        self,
        path: str,
        body: Optional[Union[str, dict, bytes]] = None,
        http_verb: str = "POST",
        headers: Optional[dict] = None,
        timeout: int = DEFAULT_REQUEST_TIMEOUT_SEC,
        log_capture: Optional[list] = None,
        allow_redirects: bool = True,
    ) -> Response:
        """
        Issues one request, synchronously, and returns the response.

        :param str path: URI of the targeted resource. Must begin with '/'
        :param body: Request body (optional).
        :type body: str or dict or bytes
        :param str http_verb: HTTP verb (e.g. "POST" or "GET").
        :param dict headers: HTTP request headers (optional).
        :param int timeout: Maximum time to wait for a response before giving up.
        :param list log_capture: Rather than emit to default handler, capture log lines to list (optional).
        :param bool allow_redirects: Select whether redirects are followed.

        :return: :py:class:`ccf.clients.Response`
        """
        if not path.startswith("/"):
            raise ValueError(f"URL path '{path}' is invalid, must start with /")

        logs: List[str] = []

        if self.is_connected:
            r = self._call(
                path, body, http_verb, headers, timeout, logs, allow_redirects
            )
            flush_info(logs, log_capture, 2)
            return r

        end_time = time.time() + self.connection_timeout
        while True:
            try:
                logs = []
                response = self._call(
                    path, body, http_verb, headers, timeout, logs, allow_redirects
                )
                # Only the first request gets this timeout logic - future calls
                # call _call
                self.is_connected = True
                flush_info(logs, log_capture, 2)
                return response
            except (CCFConnectionException, TimeoutError) as e:
                # If the initial connection fails (e.g. due to node certificate
                # not yet being endorsed by the network) sleep briefly and try again
                if time.time() > end_time:
                    flush_info(logs, log_capture, 2)
                    raise CCFConnectionException(
                        f"Connection still failing after {self.connection_timeout}s"
                    ) from e
                time.sleep(0.1)

    def get(self, *args, **kwargs) -> Response:
        """
        Issue ``GET`` request.
        See :py:meth:`ccf.clients.CCFClient.call`.

        :return: :py:class:`ccf.clients.Response`
        """
        if "http_verb" in kwargs:
            raise ValueError('"http_verb" should not be specified')

        kwargs["http_verb"] = "GET"
        return self.call(*args, **kwargs)

    def post(self, *args, **kwargs) -> Response:
        """
        Issue ``POST`` request.
        See :py:meth:`ccf.clients.CCFClient.call`.

        :return: :py:class:`ccf.clients.Response`
        """
        if "http_verb" in kwargs:
            raise ValueError('"http_verb" should not be specified')

        kwargs["http_verb"] = "POST"
        return self.call(*args, **kwargs)

    def put(self, *args, **kwargs) -> Response:
        """
        Issue ``PUT`` request.
        See :py:meth:`ccf.clients.CCFClient.call`.

        :return: :py:class:`ccf.clients.Response`
        """
        if "http_verb" in kwargs:
            raise ValueError('"http_verb" should not be specified')

        kwargs["http_verb"] = "PUT"
        return self.call(*args, **kwargs)

    def delete(self, *args, **kwargs) -> Response:
        """
        Issue ``DELETE`` request.
        See :py:meth:`ccf.clients.CCFClient.call`.

        :return: :py:class:`ccf.clients.Response`
        """
        if "http_verb" in kwargs:
            raise ValueError('"http_verb" should not be specified')

        kwargs["http_verb"] = "DELETE"
        return self.call(*args, **kwargs)

    def head(self, *args, **kwargs) -> Response:
        """
        Issue ``HEAD`` request.
        See :py:meth:`ccf.clients.CCFClient.call`.

        :return: :py:class:`ccf.clients.Response`
        """
        if "http_verb" in kwargs:
            raise ValueError('"http_verb" should not be specified')

        kwargs["http_verb"] = "HEAD"
        return self.call(*args, **kwargs)

    def wait_for_commit(
        self, response: Response, timeout: int = DEFAULT_COMMIT_TIMEOUT_SEC
    ):
        """
        Given a :py:class:`ccf.clients.Response`, this functions waits
        for the associated sequence number and view to be committed by the CCF network.

        The client will poll the ``/node/tx`` endpoint until ``COMMITTED`` is returned.

        :param ccf.clients.Response response: Response returned by :py:meth:`ccf.clients.CCFClient.call`
        :param int timeout: Maximum time (secs) to wait for commit before giving up.

        A ``TimeoutError`` exception is raised if the transaction is not committed within ``timeout`` seconds.
        """
        if response.seqno is None or response.view is None:
            raise ValueError("Response seqno and view should not be None")

        ccf.commit.wait_for_commit(self, response.seqno, response.view, timeout)


@contextlib.contextmanager
def client(*args, **kwargs):
    yield CCFClient(*args, **kwargs)
