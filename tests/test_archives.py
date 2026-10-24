import pytest

from app.db import get_db

from .samples import ARCHIVES, CHECKED, ELF, EXE
from .test_files import PASSWORD, download, my_files, new_file, share, shared_with_me, upload

BUNDLE = ARCHIVES["bundle.zip"]


def stored(app, name):
    with app.app_context():
        return get_db().execute(
            "SELECT mime, checked FROM files WHERE filename = ?", (name,)
        ).fetchone()


def shared_bundle(alice, bob):
    url = new_file(alice, BUNDLE, name="bundle.zip")
    share(alice, url, bob.handle)
    return url


@pytest.mark.parametrize("name", sorted(ARCHIVES))
def test_archives_are_accepted_but_not_checked(app, alice, name):
    assert f"Uploaded {name}.".encode() in upload(alice, ARCHIVES[name], name=name).data
    assert stored(app, name)["checked"] == 0


def test_checked_files_stay_checked(app, alice):
    upload(alice, CHECKED["report.pdf"], name="report.pdf")
    assert stored(app, "report.pdf")["checked"] == 1


def test_a_document_named_zip_is_a_zip(app, alice):
    assert b"Uploaded letter.zip." in upload(alice, CHECKED["letter.docx"], name="letter.zip").data
    assert tuple(stored(app, "letter.zip")) == ("application/zip", 0)


def test_programs_renamed_as_archives_are_refused(alice):
    for data, name in (
        (ELF, "tools.zip"),
        (EXE, "tools.7z"),
        (CHECKED["report.pdf"], "report.tar.gz"),
    ):
        assert b"does not match the ." in upload(alice, data, name=name).data, name
    assert b"No files found." in my_files(alice)


def test_lists_mark_archives(alice, bob):
    shared_bundle(alice, bob)
    new_file(alice)
    assert my_files(alice).count(b"not checked") == 1
    assert b"not checked" in shared_with_me(bob)


def test_recipients_are_warned_and_owners_told(alice, bob):
    url = shared_bundle(alice, bob)
    page = bob.get(url).data
    assert b"Vault-Share confirmed this is a ZIP archive, but did not look inside." in page
    assert b'name="understood"' in page
    page = alice.get(url).data
    assert b"Everyone you share it with is warned." in page
    assert b"the people you share it with will see a warning" in page
    assert b'name="understood"' not in page


def test_recipients_must_confirm_before_downloading(alice, bob):
    url = shared_bundle(alice, bob)
    r = download(bob, url, follow_redirects=True)
    assert b"Tick the box to confirm you know this archive was not checked." in r.data
    r = bob.post(f"{url}/download", data={"password": PASSWORD, "understood": "y"})
    assert r.data == BUNDLE
    assert r.headers["Content-Disposition"].startswith("attachment;")
    assert r.mimetype == "application/zip"


def test_the_owner_downloads_without_confirming(alice):
    url = new_file(alice, BUNDLE, name="bundle.zip")
    assert download(alice, url).data == BUNDLE


@pytest.mark.parametrize(
    "change", ["UPDATE files SET checked = 1", "UPDATE files SET mime = 'application/pdf'"]
)
def test_the_mark_and_the_type_are_in_the_record_fingerprint(app, alice, change):
    url = new_file(alice, BUNDLE, name="bundle.zip")
    with app.app_context():
        db = get_db()
        db.execute(change)
        db.commit()
    assert b"record of this file was changed in the database" in alice.get(url).data
