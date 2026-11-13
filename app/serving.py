import ipaddress
import socket
import ssl
import threading
import time
from collections import Counter

from werkzeug.serving import ThreadedWSGIServer, WSGIRequestHandler

# connections served at once; each has a thread of its own
MAX_THREADS = 64
# connections one visitor holds at once, so a few slow ones cannot take all
# the threads; an IPv6 visitor counts by their /48, as the login limits do
PER_ADDRESS = 8
# the TLS handshake, the request line and every header must arrive within
# this, however steadily they trickle in
HEAD_SECONDS = 10
# then a body must come at this many bytes a second on average
MIN_BODY_RATE = 32 * 1024
# any read waits this long for its next bytes (Werkzeug closes a connection
# after every answer, so none waits for a next request)
IDLE_SECONDS = 5


class Watchdog(threading.Thread):
    """Ends the connections whose deadline passed: one thread watches them
    all, so a deadline costs no thread of its own."""

    def __init__(self):
        super().__init__(name="deadlines", daemon=True)
        self._lock = threading.Lock()
        self._deadlines = {}
        self._cut = set()
        self._stopped = threading.Event()

    def set(self, sock, seconds):
        with self._lock:
            self._deadlines[sock] = time.monotonic() + seconds

    def clear(self, sock):
        with self._lock:
            self._deadlines.pop(sock, None)

    def was_cut(self, sock):
        """Whether this connection ran late and was ended: a head cut short
        reads as complete, and must not reach the app."""
        with self._lock:
            return sock in self._cut

    def forget(self, sock):
        with self._lock:
            self._cut.discard(sock)

    def run(self):
        while not self._stopped.wait(0.25):
            now = time.monotonic()
            with self._lock:
                late = [s for s, t in self._deadlines.items() if t <= now]
                for s in late:
                    del self._deadlines[s]
                    self._cut.add(s)
            for s in late:
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def stop(self):
        self._stopped.set()


class Handler(WSGIRequestHandler):
    # between two reads
    timeout = IDLE_SECONDS

    def version_string(self):
        # the Server header, without Werkzeug's name and version
        return "Vault-Share"

    def handle(self):
        # the clock starts now, before the TLS handshake: one deadline covers
        # the handshake and the whole head of the first request
        self._first = True
        self.server.watchdog.set(self.connection, self.server.head_seconds)
        try:
            # the TLS handshake runs here, in this connection's own thread
            if isinstance(self.connection, ssl.SSLSocket):
                try:
                    self.connection.do_handshake()
                except (ssl.SSLError, OSError) as e:
                    self.log("info", "TLS handshake with %s failed: %s", self.address_string(), e)
                    return
            super().handle()
        finally:
            self.server.watchdog.clear(self.connection)
            self.server.watchdog.forget(self.connection)

    def handle_one_request(self):
        # a later request on the same connection, should there be one, gets
        # the same clock
        if not self._first:
            self.server.watchdog.set(self.connection, self.server.head_seconds)
        self._first = False
        super().handle_one_request()

    def parse_request(self):
        ok = super().parse_request()
        if ok and self.server.watchdog.was_cut(self.connection):
            # the head ended because the connection was cut, not by itself
            self.close_connection = True
            return False
        # the head is in; what is left is the body, at a minimum rate
        size = 0
        if ok:
            if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
                size = self.server.app.config.get("MAX_CONTENT_LENGTH") or 0
            else:
                try:
                    size = max(0, int(self.headers.get("Content-Length") or 0))
                except ValueError:
                    size = 0
        if size:
            self.server.watchdog.set(
                self.connection, self.server.head_seconds + size / self.server.min_rate
            )
        else:
            self.server.watchdog.clear(self.connection)
        return ok

    def send_response(self, *args, **kwargs):
        # the answer starts, so the body is in; no clock runs on the answer
        self.server.watchdog.clear(self.connection)
        super().send_response(*args, **kwargs)


def address_key(host, exempt_loopback=False):
    """What the per-address cap counts a visitor by, or None when it does
    not count them: IPv4 as it is, IPv6 by its /48, and this machine not at
    all behind a proxy, where every visitor arrives from it."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if exempt_loopback and ip.is_loopback:
        return None
    if ip.version == 6:
        return str(ipaddress.ip_network(f"{ip}/48", strict=False))
    return str(ip)


class CappedServer(ThreadedWSGIServer):
    """One thread per connection, as Werkzeug does, but at most max_threads
    at once, and at most per_address for one visitor. When they are all
    taken, a new connection waits for one to end instead of costing a
    thread of its own, so thousands of idle connections cannot pile up
    threads; one over its address's share is refused. With the deadlines,
    a slow connection gives its thread back within seconds."""

    def __init__(self, *args, max_threads=MAX_THREADS, per_address=PER_ADDRESS,
                 head_seconds=HEAD_SECONDS, min_rate=MIN_BODY_RATE, exempt_loopback=False,
                 **kwargs):
        super().__init__(*args, **kwargs)
        self._threads_left = threading.BoundedSemaphore(max_threads)
        self._stopping = False
        self.per_address = per_address
        self.head_seconds = head_seconds
        self.min_rate = min_rate
        self.exempt_loopback = exempt_loopback
        self._held = Counter()
        self._counted = {}
        self._held_lock = threading.Lock()
        self.watchdog = Watchdog()
        self.watchdog.start()

    def verify_request(self, request, client_address):
        key = address_key(client_address[0], self.exempt_loopback)
        if key is None:
            return True
        with self._held_lock:
            if self._held[key] >= self.per_address:
                return False
            self._held[key] += 1
            self._counted[request] = key
        return True

    def shutdown_request(self, request):
        # every accepted connection ends here once, whatever happened to it
        with self._held_lock:
            key = self._counted.pop(request, None)
            if key is not None:
                self._held[key] -= 1
                if not self._held[key]:
                    del self._held[key]
        super().shutdown_request(request)

    def process_request(self, request, client_address):
        # waits in short steps, so shutdown() can still stop the server
        while not self._threads_left.acquire(timeout=0.5):
            if self._stopping:
                self.shutdown_request(request)
                return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._threads_left.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._threads_left.release()

    def shutdown(self):
        self._stopping = True
        super().shutdown()
        self.watchdog.stop()


def make_app_server(app, host="127.0.0.1", port=5000, max_threads=MAX_THREADS,
                    per_address=PER_ADDRESS, head_seconds=HEAD_SECONDS, min_rate=MIN_BODY_RATE):
    """The development server for app, over HTTPS when app.config["HTTPS"].

    Werkzeug's own HTTPS mode does each TLS handshake inside the loop that
    accepts connections, so one client that connects and never finishes
    the handshake (a browser showing a certificate warning does that)
    freezes the whole server. Here the handshake waits for the
    connection's own thread instead.

    Raises OSError when the port is taken.
    """
    # bound here, so a taken port raises OSError: when Werkzeug binds it, it
    # prints a message and ends the whole program, console included
    with socket.create_server((host, port)) as listener:
        server = CappedServer(
            host, port, app, Handler, fd=listener.fileno(), max_threads=max_threads,
            per_address=per_address, head_seconds=head_seconds, min_rate=min_rate,
            # behind a proxy on this machine every visitor arrives from it
            exempt_loopback=app.config.get("BEHIND_PROXY", False),
        )
    if app.config["HTTPS"]:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(app.config["TLS_CERT"], app.config["TLS_KEY"])
        server.socket = context.wrap_socket(
            server.socket, server_side=True, do_handshake_on_connect=False
        )
        # Werkzeug reads this to tell the app the request came over HTTPS
        server.ssl_context = context
    return server
