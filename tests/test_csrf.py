import io
import re

import pytest

from .conftest import invite_code


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
    code = invite_code(client.application)
    r = client.post("/auth/register", data={"code": code, "username": "alice", "csrf_token": token})
    assert r.headers["Location"] == "/auth/register/password"
    token = token_from(client.get("/auth/register/password").data)
    r = client.post(
        "/auth/register/password", data={"password": "contract-2026", "csrf_token": token}
    )
    assert r.headers["Location"] == "/auth/login"


def test_logout_needs_a_token(alice, csrf_app):
    assert alice.post("/auth/logout").status_code == 400
    assert alice.get("/").status_code == 200


def test_the_duress_forms_need_their_token(app, alice, bob, csrf_app):
    """The forms of the duress levels, posted as a browser does: with the
    token from their page they work, without it nothing happens."""
    from .test_duress import DURESS
    from .test_files import file_id, my_files, shared_with_me

    page = alice.get("/upload").data
    url = alice.post(
        "/upload",
        data={"file": (io.BytesIO(b"board minutes"), "minutes.txt"), "csrf_token": token_from(page),
              "password": "contract-2026"},
        content_type="multipart/form-data",
    ).headers["Location"]
    duress = {"password": "contract-2026", "duress_password": DURESS, "mode": "cover"}
    cover = {"password": "contract-2026", "direction": "down", "file": file_id(url)}
    change = {"password": "contract-2026", "new_password": "orchard-window-copper-58"}
    for path, data, done in (
        ("/auth/duress", duress, b"Duress password saved."),
        ("/auth/duress/cover", cover, b"Moved 1 file."),
        ("/auth/password", change, b"Password changed."),
    ):
        assert alice.post(path, data=data).status_code == 400
        data = {**data, "csrf_token": token_from(alice.get("/auth/duress").data)}
        assert done in alice.post(path, data=data, follow_redirects=True).data
    assert b"minutes.txt" not in my_files(alice)

    # a recipient removing a file from their list
    page = bob.get("/").data
    shared = alice.get(url).data
    alice.post(f"{url}/share", data={"username": bob.handle, "csrf_token": token_from(shared),
                                     "password": "orchard-window-copper-58"})
    assert bob.post(f"{url}/dismiss", data={"password": "contract-2026"}).status_code == 400
    page = bob.get(url).data
    r = bob.post(f"{url}/dismiss", data={"password": "contract-2026", "csrf_token": token_from(page)},
                 follow_redirects=True)
    assert b"Removed minutes.txt from your list." in r.data
    assert b"minutes.txt" not in shared_with_me(bob)
