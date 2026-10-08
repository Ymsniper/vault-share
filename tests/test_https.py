import http.client
import os
import socket
import ssl
import stat
import subprocess
import threading
from pathlib import Path
from urllib.parse import urlencode

import pytest
from cryptography import x509
from app import create_app
from app.serving import make_app_server

PKI = Path(__file__).parent.parent / "pki"


@pytest.fixture(scope="session")
def tls_dir(ca_dir, ca_passphrase, tmp_path_factory):
    out = tmp_path_factory.mktemp("tls")
    subprocess.run(
        ["sh", str(PKI / "create_server_cert.sh"), str(ca_dir), str(out)],
        env={**os.environ, "CA_PASSPHRASE": ca_passphrase},
        check=True,
        capture_output=True,
    )
    return out


@pytest.fixture
def https_app(app, tls_dir):
    """The test app in HTTPS mode, on the same database and files."""
    config = {k: v for k, v in app.config.items() if k.isupper()}
    config.update(
        HTTPS=True, TLS_CERT=str(tls_dir / "server.crt"), TLS_KEY=str(tls_dir / "server.key")
    )
    return create_app(config)


@pytest.fixture
def https_port(https_app):
    server = make_app_server(https_app, port=0)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    yield server.server_port
    server.shutdown()
    thread.join()


def test_server_certificate_is_issued_by_the_ca(ca_dir, tls_dir):
    r = subprocess.run(
        ["openssl", "verify", "-CAfile", str(ca_dir / "ca.crt"), "-purpose", "sslserver",
         str(tls_dir / "server.crt")],
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0, r.stdout + r.stderr

    cert = x509.load_pem_x509_certificate((tls_dir / "server.crt").read_bytes())
    names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert names.get_values_for_type(x509.DNSName) == ["localhost"]
    assert [str(ip) for ip in names.get_values_for_type(x509.IPAddress)] == ["127.0.0.1"]
    assert stat.S_IMODE(os.stat(tls_dir / "server.key").st_mode) == 0o600


def test_browser_trusting_the_ca_gets_a_secure_cookie(ca_dir, https_port):
    trusting = ssl.create_default_context(cafile=str(ca_dir / "ca.crt"))
    form = {"username": "alice", "password": "contract-2026"}
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    for host in ("localhost", "127.0.0.1"):
        conn = http.client.HTTPSConnection(host, https_port, context=trusting)
        conn.request("POST", "/auth/register", urlencode(form), headers)
        conn.getresponse().read()
        conn.request("POST", "/auth/login", urlencode(form), headers)
        response = conn.getresponse()
        response.read()
        cookie = response.getheader("Set-Cookie")
        assert cookie.startswith("sid=")
        assert "Secure" in cookie and "HttpOnly" in cookie
        conn.close()


def test_client_without_the_ca_refuses_the_connection(https_port):
    default = ssl.create_default_context()
    conn = http.client.HTTPSConnection("localhost", https_port, context=default)
    with pytest.raises(ssl.SSLCertVerificationError):
        conn.request("GET", "/auth/login")
    conn.close()


def test_plain_http_is_redirected_to_https(https_app):
    r = https_app.test_client().get("/auth/login")
    assert r.status_code == 302
    assert r.headers["Location"] == "https://localhost/auth/login"


def test_a_silent_client_does_not_freeze_the_server(ca_dir, https_port):
    # connects, then never starts the TLS handshake, as a browser stuck on
    # a certificate warning does
    silent = socket.create_connection(("127.0.0.1", https_port))
    try:
        trusting = ssl.create_default_context(cafile=str(ca_dir / "ca.crt"))
        conn = http.client.HTTPSConnection("localhost", https_port, context=trusting, timeout=5)
        conn.request("GET", "/auth/login")
        assert conn.getresponse().status == 200
        conn.close()
    finally:
        silent.close()
