"""The server's guards against slow connections (design revision 2, B4): a
cap on the connections one address holds, and one clock for the request
head and another for the body, watched by a single thread that closes the
connections that run late."""
import socket
import threading
import time

import pytest

from app.serving import make_app_server

GET = b"GET /auth/login HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"


@pytest.fixture
def serve(app):
    servers = []

    def start(served=None, **kwargs):
        server = make_app_server(served or app, port=0, **kwargs)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append((server, thread))
        return server

    yield start
    for server, thread in servers:
        server.shutdown()
        thread.join(timeout=10)


def connect(server, source="127.0.0.1"):
    return socket.create_connection(("127.0.0.1", server.port), timeout=5,
                                    source_address=(source, 0))


def closed_within(sock, seconds):
    """Whether the server ends the connection within that many seconds,
    whatever it answered before."""
    end = time.monotonic() + seconds
    try:
        while time.monotonic() < end:
            sock.settimeout(max(0.05, end - time.monotonic()))
            if not sock.recv(65536):
                return True
    except TimeoutError:
        return False
    except OSError:
        return True
    return False


def trickle(sock, chunks, every):
    """Send the chunks one at a time, every that many seconds, until the
    server ends the connection. Returns how long that took, or None."""
    start = time.monotonic()
    for chunk in chunks:
        if closed_within(sock, every):
            return time.monotonic() - start
        try:
            sock.sendall(chunk)
        except OSError:
            return time.monotonic() - start
    return time.monotonic() - start if closed_within(sock, every) else None


def answer(sock):
    sock.sendall(GET)
    sock.settimeout(5)
    return sock.recv(64)


def test_one_address_holds_only_its_share_of_the_threads(serve):
    server = serve(per_address=2)
    held = [connect(server) for _ in range(2)]
    try:
        time.sleep(0.2)
        assert closed_within(connect(server), 2)
        # someone else is served at once
        assert answer(connect(server, source="127.0.0.2")).startswith(b"HTTP/1.1 200")
        # and the address gets its place back when a connection ends
        held.pop().close()
        time.sleep(0.3)
        assert answer(connect(server)).startswith(b"HTTP/1.1 200")
    finally:
        for s in held:
            s.close()


def test_behind_a_proxy_this_machine_is_not_capped(app, serve):
    # every visitor of a public link arrives from the proxy on this machine
    app.config["BEHIND_PROXY"] = True
    server = serve(per_address=2)
    held = [connect(server) for _ in range(2)]
    try:
        assert answer(connect(server)).startswith(b"HTTP/1.1 200")
    finally:
        for s in held:
            s.close()


def test_a_slow_head_is_cut_at_its_deadline(serve):
    server = serve(head_seconds=1)
    slow = connect(server)
    slow.sendall(b"GET /auth/login HTTP/1.1\r\n")
    # a header line every 0.3 s, quicker than the wait between reads, and
    # never the blank line that ends the head
    took = trickle(slow, [f"X-Slow-{i}: 1\r\n".encode() for i in range(20)], 0.3)
    assert took is not None and took < 2


def test_a_slow_body_is_cut_at_the_minimum_rate(serve):
    server = serve(head_seconds=1, min_rate=10)
    slow = connect(server)
    # 20 bytes at 10 a second, after one second of grace: 3 seconds at most
    slow.sendall(b"POST /auth/login HTTP/1.1\r\nHost: localhost\r\n"
                 b"Content-Type: application/x-www-form-urlencoded\r\n"
                 b"Content-Length: 20\r\n\r\n")
    took = trickle(slow, [b"x"] * 20, 0.5)
    assert took is not None and 2 < took < 4.5


def test_a_body_at_a_decent_rate_is_served(serve):
    server = serve(head_seconds=1, min_rate=10)
    s = connect(server)
    s.sendall(b"POST /auth/login HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
              b"Content-Type: application/x-www-form-urlencoded\r\n"
              b"Content-Length: 20\r\n\r\n")
    for _ in range(4):
        time.sleep(0.2)
        s.sendall(b"x=1&a")
    s.settimeout(5)
    assert s.recv(64).startswith(b"HTTP/1.1 200")


def test_a_silent_connection_waits_only_a_little(serve):
    server = serve()
    # nothing at all is sent: the first read gives up after 5 seconds
    assert closed_within(connect(server), 7)


def test_a_stranger_cannot_send_a_large_body(serve):
    server = serve()
    s = connect(server)
    # the head only: a large body is refused before it is read
    s.sendall(b"POST /auth/login HTTP/1.1\r\nHost: localhost\r\n"
              b"Content-Type: application/x-www-form-urlencoded\r\n"
              b"Content-Length: 1048576\r\n\r\n")
    s.settimeout(5)
    assert s.recv(64).startswith(b"HTTP/1.1 413")


def test_a_logged_in_upload_is_not_held_to_the_stranger_limit(alice):
    from .test_files import new_file

    url = new_file(alice, b"Minutes of the weekly meeting.\n" * 4000, "minutes.txt")
    assert alice.get(url).status_code == 200
