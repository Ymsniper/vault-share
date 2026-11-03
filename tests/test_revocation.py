import subprocess
import time
from datetime import datetime, timedelta
from types import SimpleNamespace

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from app import files
from app.admin import revoke_certificate
from app.db import get_db
from security import pki
from security.pki import crl_to_pem, load_ca_certificate, load_certificate, make_crl

from .test_files import CONTRACT, download, new_file


def revoke(app, username, *options):
    return app.test_cli_runner().invoke(args=["admin", "revoke", username, *options])


def certificates(app):
    with app.app_context():
        return get_db().execute(
            "SELECT pem, revoked_at, invalid_from, not_before FROM certificates ORDER BY id"
        ).fetchall()


def local(minutes_from_now):
    """A local time as the commands read it."""
    return (datetime.now() + timedelta(minutes=minutes_from_now)).strftime("%Y-%m-%d %H:%M")


def verified(alice):
    return f"Record verified. Signature valid, signed by {alice.handle}.".encode()


def test_revoke_marks_the_certificate_and_publishes_a_crl(app, ca_dir, tmp_path, alice):
    r = revoke(app, alice.handle)
    assert r.exit_code == 0, r.output
    assert f"Revoked {alice.handle}'s certificate." in r.output
    assert certificates(app)[0]["revoked_at"] is not None

    (tmp_path / "alice.crt").write_text(certificates(app)[0]["pem"])
    out = subprocess.run(
        ["openssl", "verify", "-crl_check", "-CAfile", str(ca_dir / "ca.crt"),
         "-CRLfile", app.config["CA_CRL"], str(tmp_path / "alice.crt")],
        capture_output=True,
        text=True,
    )
    assert out.returncode != 0
    assert "certificate revoked" in out.stdout + out.stderr


def test_revoke_needs_an_active_certificate(app, alice):
    assert "nobody has no certificate to revoke" in revoke(app, "nobody").output
    revoke(app, alice.handle)
    assert f"{alice.handle} has no certificate to revoke" in revoke(app, alice.handle).output


def test_files_uploaded_before_a_revocation_stay_valid(app, alice):
    url = new_file(alice)
    # a revocation fails the files of its own second too
    time.sleep(1.1)
    revoke(app, alice.handle)
    assert verified(alice) in alice.get(url).data
    assert download(alice, url).data == CONTRACT


def test_a_revocation_fails_the_files_uploaded_from_its_time_on(app, alice):
    before = new_file(alice)
    time.sleep(1.1)
    with app.app_context():
        since = get_db().execute("SELECT datetime('now')").fetchone()[0]
    time.sleep(1.1)
    after = new_file(alice, name="after.txt")
    with app.app_context():
        revoke_certificate(alice.handle, since=since)
    assert verified(alice) in alice.get(before).data
    assert b"the certificate was revoked" in alice.get(after).data
    assert CONTRACT not in download(alice, after, follow_redirects=True).data


def test_revoke_since_a_local_time(app, alice):
    url = new_file(alice)
    r = revoke(app, alice.handle, "--since", local(-60))
    assert r.exit_code == 0, r.output
    # earlier than the certificate itself: every file it signed fails
    cert = certificates(app)[0]
    assert cert["invalid_from"] == cert["not_before"]
    assert b"the certificate was revoked" in alice.get(url).data


def test_revoking_all_files_for_a_key_stolen_at_an_unknown_time(app, alice):
    url = new_file(alice)
    revoke(app, alice.handle, "--all")
    cert = certificates(app)[0]
    assert cert["invalid_from"] == cert["not_before"]
    assert b"the certificate was revoked" in alice.get(url).data


def test_the_crl_carries_the_time_files_fail_from(app, alice):
    revoke(app, alice.handle, "--all")
    cert = load_certificate(certificates(app)[0]["pem"])
    with open(app.config["CA_CRL"], "rb") as f:
        entry = x509.load_pem_x509_crl(f.read()).get_revoked_certificate_by_serial_number(
            cert.serial_number
        )
    since = entry.extensions.get_extension_for_class(x509.InvalidityDate).value
    assert since.invalidity_date_utc == cert.not_valid_before_utc


def test_erasing_the_revocation_from_the_database_is_not_enough(app, alice):
    url = new_file(alice)
    revoke(app, alice.handle, "--all")
    with app.app_context():
        db = get_db()
        db.execute("UPDATE certificates SET revoked_at = NULL, invalid_from = NULL")
        db.commit()
    assert b"the certificate was revoked" in alice.get(url).data


def test_moving_the_time_later_in_the_database_is_not_enough(app, alice):
    url = new_file(alice)
    revoke(app, alice.handle, "--since", local(-60))
    with app.app_context():
        db = get_db()
        db.execute("UPDATE certificates SET invalid_from = datetime('now', '+1 day')")
        db.commit()
    assert b"the certificate was revoked" in alice.get(url).data


def test_revoke_wants_a_past_time_and_one_option(app, alice):
    r = revoke(app, alice.handle, "--since", local(120))
    assert r.exit_code != 0 and "in the future" in r.output
    r = revoke(app, alice.handle, "--since", local(-60), "--all")
    assert r.exit_code != 0 and "not both" in r.output
    assert certificates(app)[0]["revoked_at"] is None


def test_crl_not_signed_by_the_ca_is_refused(app, alice):
    url = new_file(alice)
    ca_cert = load_ca_certificate(app.config["CA_CERT"])
    forged = make_crl(ca_cert, ec.generate_private_key(ec.SECP256R1()), [])
    with open(app.config["CA_CRL"], "wb") as f:
        f.write(crl_to_pem(forged))
    assert b"the revocation list is not signed by the local CA" in alice.get(url).data


def test_next_upload_gets_a_new_certificate(app, alice):
    old = new_file(alice)
    time.sleep(1.1)
    revoke(app, alice.handle)

    new = new_file(alice, name="after-revocation.txt")
    certs = certificates(app)
    assert len(certs) == 2
    assert certs[0]["revoked_at"] is not None and certs[1]["revoked_at"] is None
    assert verified(alice) in alice.get(new).data
    assert verified(alice) in alice.get(old).data


def test_expired_certificate_is_renewed_at_upload(app, alice, test_certs):
    with app.app_context():
        db = get_db()
        db.execute("UPDATE certificates SET pem = ?", ((test_certs / "expired.crt").read_text(),))
        db.commit()

    url = new_file(alice)
    assert len(certificates(app)) == 2
    verified = f"Record verified. Signature valid, signed by {alice.handle}."
    assert verified.encode() in alice.get(url).data


def a_year_later(monkeypatch):
    """Move the clocks that certificates are issued and judged by, and that
    uploads are dated by, 366 days ahead."""
    real = pki.datetime

    class Later(real.datetime):
        @classmethod
        def now(cls, tz=None):
            return real.datetime.now(tz) + real.timedelta(days=366)

    clock = SimpleNamespace(datetime=Later, UTC=real.UTC, timedelta=real.timedelta)
    monkeypatch.setattr(pki, "datetime", clock)
    monkeypatch.setattr(files, "datetime", clock)


def test_files_stay_valid_after_the_certificate_expires(app, alice, monkeypatch):
    url = new_file(alice)
    a_year_later(monkeypatch)
    verified = f"Record verified. Signature valid, signed by {alice.handle}."
    assert verified.encode() in alice.get(url).data
    assert download(alice, url).data == CONTRACT


def test_renewing_an_expired_certificate_keeps_old_files_valid(app, alice, monkeypatch):
    old = new_file(alice)
    a_year_later(monkeypatch)
    # the certificate has expired, so this upload renews it
    new = new_file(alice, name="a-year-later.txt")
    assert len(certificates(app)) == 2
    verified = f"Record verified. Signature valid, signed by {alice.handle}."
    assert verified.encode() in alice.get(new).data
    assert verified.encode() in alice.get(old).data
    assert download(alice, old).data == CONTRACT


def test_the_upload_time_is_covered_by_the_record_hmac(app, alice):
    url = new_file(alice)
    with app.app_context():
        db = get_db()
        # moved back into a validity window it was not signed in
        db.execute("UPDATE files SET uploaded_at = datetime(uploaded_at, '-1 day')")
        db.commit()
    assert b"the record of this file was changed in the database" in alice.get(url).data
