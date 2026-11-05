import http.client
import os
import re
import socket
import ssl
import stat
import subprocess
import threading
from urllib.parse import urlencode

import pytest
from cryptography import x509
from app import create_app
from app.serving import make_app_server
from tests.conftest import invite_code
from tests.test_csrf import token_from

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
    yield server.port
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


def register_and_log_in(conn, code, password="contract-2026"):
    """Both registration steps, then login, carrying the session cookie as a
    browser does. Returns the login response."""
    cookie = ""

    def send(method, path, form=None):
        nonlocal cookie
        headers = {"Cookie": cookie}
        if form is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            form = urlencode(form)
        conn.request(method, path, form, headers)
        response = conn.getresponse()
        body = response.read()
        for c in response.headers.get_all("Set-Cookie") or []:
            if c.startswith("session="):
                cookie = c.split(";")[0]
        return response, body

    send("POST", "/auth/register", {"code": code, "username": "alice"})
    send("POST", "/auth/register/password", {"password": password})
    # the login page fills in the new username
    _, page = send("GET", "/auth/login")
    handle = re.search(rb'autocomplete="username" value="([^"]+)"', page).group(1).decode()
    response, _ = send("POST", "/auth/login", {"username": handle, "password": password})
    return response


def test_browser_trusting_the_ca_gets_a_secure_cookie(https_app, ca_dir, https_port):
    trusting = ssl.create_default_context(cafile=str(ca_dir / "ca.crt"))
    for host in ("localhost", "127.0.0.1"):
        conn = http.client.HTTPSConnection(host, https_port, context=trusting)
        response = register_and_log_in(conn, invite_code(https_app))
        cookie = [c for c in response.headers.get_all("Set-Cookie") if c.startswith("sid=")][0]
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


def test_connections_over_the_cap_wait_for_a_thread(app):
    server = make_app_server(app, port=0, max_threads=2)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    idle = [socket.create_connection(("127.0.0.1", server.port)) for _ in range(2)]
    late = socket.create_connection(("127.0.0.1", server.port))
    try:
        # both threads are held by connections that send nothing
        late.sendall(b"GET /auth/login HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        late.settimeout(1)
        with pytest.raises(TimeoutError):
            late.recv(64)
        # one of them goes away, and the waiting connection gets its thread
        idle[0].close()
        late.settimeout(5)
        assert late.recv(64).startswith(b"HTTP/1.1 200")
    finally:
        for s in (*idle, late):
            s.close()
        server.shutdown()
        thread.join()


@pytest.fixture
def csrf_on(https_app):
    # Flask-WTF reads this on every request, as in test_csrf.py
    https_app.config["WTF_CSRF_ENABLED"] = True


def register_over_https(ca_dir, port, referer, code="not a code"):
    """Registers alice as a browser does: the form page first, then the form
    sent back with its token, the cookies and the given Referer."""
    trusting = ssl.create_default_context(cafile=str(ca_dir / "ca.crt"))
    conn = http.client.HTTPSConnection("localhost", port, context=trusting)
    try:
        conn.request("GET", "/auth/register")
        page = conn.getresponse()
        cookies = "; ".join(c.split(";")[0] for c in page.headers.get_all("Set-Cookie", []))
        form = {"code": code, "username": "alice", "csrf_token": token_from(page.read())}
        headers = {"Content-Type": "application/x-www-form-urlencoded", "Cookie": cookies}
        if referer:
            headers["Referer"] = referer
        conn.request("POST", "/auth/register", urlencode(form), headers)
        response = conn.getresponse()
        return response.status, response.read()
    finally:
        conn.close()


def test_pages_send_the_referer_to_this_site_only(ca_dir, https_port):
    # a browser following no-referrer sends no Referer at all, and Flask-WTF
    # then refuses every form over HTTPS
    trusting = ssl.create_default_context(cafile=str(ca_dir / "ca.crt"))
    conn = http.client.HTTPSConnection("localhost", https_port, context=trusting)
    conn.request("GET", "/auth/login")
    assert conn.getresponse().getheader("Referrer-Policy") == "same-origin"
    conn.close()


def test_form_from_this_site_is_accepted_over_https(https_app, csrf_on, ca_dir, https_port):
    status, _ = register_over_https(
        ca_dir, https_port, f"https://localhost:{https_port}/auth/register", invite_code(https_app)
    )
    assert status == 302


@pytest.mark.parametrize(
    ("referer", "reason"),
    [
        (None, b"The referrer header is missing."),
        ("https://evil.example/auth/register", b"The referrer does not match the host."),
    ],
    ids=["no referer", "another site"],
)
def test_form_not_from_this_site_is_refused_over_https(
    csrf_on, ca_dir, https_port, referer, reason
):
    status, page = register_over_https(ca_dir, https_port, referer)
    assert status == 400
    assert reason in page


def test_the_server_does_not_name_werkzeug(ca_dir, https_port):
    trusting = ssl.create_default_context(cafile=str(ca_dir / "ca.crt"))
    conn = http.client.HTTPSConnection("localhost", https_port, context=trusting)
    conn.request("GET", "/auth/login")
    assert conn.getresponse().getheader("Server") == "Vault-Share"
    conn.close()
