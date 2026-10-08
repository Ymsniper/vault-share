import ssl

from werkzeug.serving import WSGIRequestHandler, make_server


class Handler(WSGIRequestHandler):
    # a connection that stays silent is dropped instead of holding a thread
    timeout = 30

    def handle(self):
        # the TLS handshake runs here, in this connection's own thread
        if isinstance(self.connection, ssl.SSLSocket):
            try:
                self.connection.do_handshake()
            except (ssl.SSLError, OSError) as e:
                self.log("info", "TLS handshake with %s failed: %s", self.address_string(), e)
                return
        super().handle()


def make_app_server(app, host="127.0.0.1", port=5000):
    """The development server for app, over HTTPS when app.config["HTTPS"].

    Werkzeug's own HTTPS mode does each TLS handshake inside the loop that
    accepts connections, so one client that connects and never finishes
    the handshake (a browser showing a certificate warning does that)
    freezes the whole server. Here the handshake waits for the
    connection's own thread instead.
    """
    server = make_server(host, port, app, threaded=True, request_handler=Handler)
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
