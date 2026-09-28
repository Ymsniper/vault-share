import io
import re

import pytest


# request this fixture after alice or bob, so they log in before the check is on
@pytest.fixture
def csrf_app(app):
    app.config["WTF_CSRF_ENABLED"] = True
    return app


def token_from(page):
    return re.search(rb'name="csrf_token" value="([^"]+)"', page).group(1).decode()


def test_form_without_token_is_refused(alice, csrf_app):
    page = alice.get("/upload").data
    url = alice.post(
        "/upload",
        data={"file": (io.BytesIO(b"board minutes"), "minutes.txt"), "csrf_token": token_from(page), "password": "contract-2026"},
        content_type="multipart/form-data",
    ).headers["Location"]
    assert alice.post(f"{url}/delete").status_code == 400
    assert alice.get(url).status_code == 200


def test_form_with_the_page_token_works(csrf_app, client):
    token = token_from(client.get("/auth/register").data)
    r = client.post(
        "/auth/register",
        data={"username": "alice", "password": "contract-2026", "csrf_token": token},
    )
    assert r.headers["Location"] == "/auth/login"


def test_logout_needs_a_token(alice, csrf_app):
    assert alice.post("/auth/logout").status_code == 400
    assert alice.get("/").status_code == 200
