def test_unknown_page_shows_a_plain_404(client):
    r = client.get("/no-such-page")
    assert r.status_code == 404
    assert b"404 Not Found" in r.data


def test_crash_reveals_nothing(app, client):
    app.config["PROPAGATE_EXCEPTIONS"] = False

    @app.route("/boom")
    def boom():
        raise RuntimeError("database password is hunter2")

    r = client.get("/boom")
    assert r.status_code == 500
    assert b"500 Internal Server Error" in r.data
    assert b"hunter2" not in r.data
    assert b"Traceback" not in r.data
