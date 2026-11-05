import socket
import ssl
import threading

from werkzeug.serving import ThreadedWSGIServer, WSGIRequestHandler

# connections served at once; each has a thread of its own
MAX_THREADS = 64


class Handler(WSGIRequestHandler):
    # a connection that stays silent is dropped instead of holding a thread
    timeout = 30

    def version_string(self):
        # the Server header, without Werkzeug's name and version
        return "Vault-Share"

    def handle(self):
        # the TLS handshake runs here, in this connection's own thread
        if isinstance(self.connection, ssl.SSLSocket):
            try:
                self.connection.do_handshake()
            except (ssl.SSLError, OSError) as e:
                self.log("info", "TLS handshake with %s failed: %s", self.address_string(), e)
                return
        super().handle()


class CappedServer(ThreadedWSGIServer):
    """One thread per connection, as Werkzeug does, but at most max_threads
    at once. When they are all taken, a new connection waits for one to end
    instead of costing a thread of its own, so thousands of idle connections
    cannot pile up threads. With the handler's timeout, a silent one gives
    its thread back after 30 seconds."""

    def __init__(self, *args, max_threads=MAX_THREADS, **kwargs):
        super().__init__(*args, **kwargs)
        self._threads_left = threading.BoundedSemaphore(max_threads)
        self._stopping = False

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


def make_app_server(app, host="127.0.0.1", port=5000, max_threads=MAX_THREADS):
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
            host, port, app, Handler, fd=listener.fileno(), max_threads=max_threads
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
