"""Régressions des dépendances auth/HTTP, entrées et secrets synthétiques.

Cas adaptés des avis mainteneurs GHSA-gvp8-978c-rx2q / w6j9-cwv2-h6wq et
des tests urllib3 2.8.0 test_response.py (trailing_data / chunk_size_line_too_long).
"""
import base64
from datetime import datetime, timedelta, timezone
import http.client
import io
import json
import socket
import ssl
import threading
import zlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import jwt
import pytest
import urllib3
from urllib3.exceptions import ProtocolError, ProxyError, SSLError


def test_jwt_options_are_not_mutated():
    options = {"verify_signature": False}
    token = jwt.encode({"exp": 1}, "s" * 32, algorithm="HS256")
    jwt.decode(token, options=options)
    assert options == {"verify_signature": False}


def test_jwt_reused_options_restore_expiration_check():
    options = {"verify_signature": False}
    token = jwt.encode({"exp": 1}, "s" * 32, algorithm="HS256")
    jwt.decode(token, options=options)
    options["verify_signature"] = True
    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(token, "s" * 32, algorithms=["HS256"], options=options)


def test_deep_jwt_payload_has_documented_error():
    def encode(value):
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode()

    payload = b'{"nested":' + b"[" * 2000 + b"0" + b"]" * 2000 + b"}"
    token = encode(b'{"alg":"none"}') + "." + encode(payload) + "."
    with pytest.raises(jwt.DecodeError):
        jwt.decode(token, options={"verify_signature": False})


@pytest.fixture
def rsa_keys():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    good = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    good["kid"] = "valid"
    bad = {"kty": "RSA", "n": good["n"], "e": good["e"], "d": "AAAAAA", "kid": "malformed"}
    return key, good, bad


def test_malformed_rsa_jwk_normalizes_exception(rsa_keys):
    _, _, bad = rsa_keys
    with pytest.raises(jwt.InvalidKeyError) as error:
        jwt.PyJWK.from_dict(bad)
    assert isinstance(error.value.__cause__, ValueError)


def test_malformed_jwk_keeps_later_valid_key_usable(rsa_keys):
    key, good, bad = rsa_keys
    keys = jwt.PyJWKSet.from_dict({"keys": [bad, good]})
    assert [item.key_id for item in keys.keys] == ["valid"]
    token = jwt.encode({"proof": "synthetic"}, key, algorithm="RS256", headers={"kid": "valid"})
    assert jwt.decode(token, keys.keys[0], algorithms=["RS256"]) == {"proof": "synthetic"}


def test_valid_rsa_key_control(rsa_keys):
    key, good, _ = rsa_keys
    keys = jwt.PyJWKSet.from_dict({"keys": [good]})
    token = jwt.encode({"proof": "synthetic"}, key, algorithm="RS256")
    assert jwt.decode(token, keys.keys[0], algorithms=["RS256"]) == {"proof": "synthetic"}


def chunked_response(encoded, *, encoding=None):
    class IOSocket:
        def makefile(self, mode):
            return io.BytesIO(encoded)

    raw = http.client.HTTPResponse(IOSocket())
    headers = {"transfer-encoding": "chunked"}
    if encoding:
        headers["content-encoding"] = encoding
    raw.fp = io.BytesIO(encoded)
    raw.chunked = True
    return urllib3.response.HTTPResponse(raw, headers=headers, preload_content=False)


@pytest.mark.timeout(2)
@pytest.mark.parametrize("method", ["stream", "read_chunked"])
def test_deflate_trailing_bytes_do_not_loop(method):
    data = b"A" * 100
    compressed = zlib.compress(data) + b"tail"
    encoded = f"{len(compressed):x}\r\n".encode() + compressed + b"\r\n0\r\n\r\n"
    with chunked_response(encoded, encoding="deflate") as response:
        assert b"".join(getattr(response, method)(amt=50, decode_content=True)) == data


@pytest.mark.parametrize("method", ["stream", "read_chunked"])
def test_chunk_size_line_is_rejected_before_unbounded_read(method):
    # Public upstream regression input: an unterminated size line over 64 KiB.
    with chunked_response(b"f" * (2**16 + 1024)) as response:
        with pytest.raises(ProtocolError, match="chunk size line exceeded maximum allowed length"):
            next(getattr(response, method)())


def certificate(tmp_path, name):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .sign(key, hashes.SHA256()))
    certpath, keypath = tmp_path / (name + ".pem"), tmp_path / (name + ".key")
    certpath.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keypath.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    keypath.chmod(0o600)
    return certpath, keypath


@pytest.mark.timeout(5)
@pytest.mark.parametrize("proxy_trusted", [True, False])
def test_https_forwarding_proxy_uses_its_own_ca(tmp_path, proxy_trusted):
    """Vrai handshake loopback ; proxy répond sans connexion à une destination."""
    cert, key = certificate(tmp_path, "proxy")
    wrong, _ = certificate(tmp_path, "different-trust-domain")
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert, key)
    proxy_context = ssl.create_default_context(cafile=str(cert if proxy_trusted else wrong))
    target_context = ssl.create_default_context(cafile=str(wrong if proxy_trusted else cert))
    failures, requests = [], []
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(2)

        def serve():
            try:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(2)
                    try:
                        with server_context.wrap_socket(connection, server_side=True) as secured:
                            request = b""
                            while b"\r\n\r\n" not in request:
                                part = secured.recv(1024)
                                if not part:
                                    break
                                request += part
                                if len(request) > 8192:
                                    raise RuntimeError("oversized synthetic request")
                            requests.append(request)
                            secured.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                    except ssl.SSLError:
                        # Expected handshake refusal for the negative CA case.
                        pass
            except Exception as error:
                failures.append(error)

        thread = threading.Thread(target=serve)
        thread.start()
        manager = urllib3.ProxyManager(f"https://localhost:{listener.getsockname()[1]}",
                                       proxy_ssl_context=proxy_context, ssl_context=target_context,
                                       use_forwarding_for_https=True, retries=False,
                                       timeout=urllib3.Timeout(connect=1, read=1))
        try:
            if proxy_trusted:
                assert manager.request("GET", "https://localhost/proof").data == b"ok"
            else:
                with pytest.raises(ProxyError) as error:
                    manager.request("GET", "https://localhost/proof")
                assert isinstance(error.value.args[1], SSLError)
        finally:
            manager.clear()
            thread.join(3)
            assert not thread.is_alive()
        assert failures == []
        assert bool(requests) is proxy_trusted
