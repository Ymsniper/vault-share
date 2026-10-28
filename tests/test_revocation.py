import subprocess
from types import SimpleNamespace

from cryptography.hazmat.primitives.asymmetric import ec

from app.db import get_db
from security import pki
from security.pki import crl_to_pem, load_ca_certificate, make_crl

from .test_files import CONTRACT, download, new_file


def revoke(app, username):
    return app.test_cli_runner().invoke(args=["admin", "revoke", username])


def certificates(app):
    with app.app_context():
        return get_db().execute("SELECT pem, revoked_at FROM certificates ORDER BY id").fetchall()


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


def test_files_signed_before_revocation_fail(app, alice):
    url = new_file(alice)
    revoke(app, alice.handle)
    assert b"the certificate was revoked" in alice.get(url).data


def test_erasing_the_revocation_from_the_database_is_not_enough(app, alice):
    url = new_file(alice)
    revoke(app, alice.handle)
    with app.app_context():
        db = get_db()
        db.execute("UPDATE certificates SET revoked_at = NULL")
        db.commit()
    assert b"the certificate was revoked" in alice.get(url).data


def test_crl_not_signed_by_the_ca_is_refused(app, alice):
    url = new_file(alice)
    ca_cert = load_ca_certificate(app.config["CA_CERT"])
    forged = make_crl(ca_cert, ec.generate_private_key(ec.SECP256R1()), [])
    with open(app.config["CA_CRL"], "wb") as f:
        f.write(crl_to_pem(forged))
    assert b"the revocation list is not signed by the local CA" in alice.get(url).data


def test_next_upload_gets_a_new_certificate(app, alice):
    old = new_file(alice)
    revoke(app, alice.handle)

    new = new_file(alice, name="after-revocation.txt")
    certs = certificates(app)
    assert len(certs) == 2
    assert certs[0]["revoked_at"] is not None and certs[1]["revoked_at"] is None
    verified = f"Record verified. Signature valid, signed by {alice.handle}."
    assert verified.encode() in alice.get(new).data
    assert b"the certificate was revoked" in alice.get(old).data


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
    """Move the clock that certificates are judged by 366 days ahead."""
    real = pki.datetime

    class Later(real.datetime):
        @classmethod
        def now(cls, tz=None):
            return real.datetime.now(tz) + real.timedelta(days=366)

    clock = SimpleNamespace(datetime=Later, UTC=real.UTC, timedelta=real.timedelta)
    monkeypatch.setattr(pki, "datetime", clock)


def test_files_stay_valid_after_the_certificate_expires(app, alice, monkeypatch):
    url = new_file(alice)
    a_year_later(monkeypatch)
    verified = f"Record verified. Signature valid, signed by {alice.handle}."
    assert verified.encode() in alice.get(url).data
    assert download(alice, url).data == CONTRACT


def test_the_upload_time_is_covered_by_the_record_hmac(app, alice):
    url = new_file(alice)
    with app.app_context():
        db = get_db()
        # moved back into a validity window it was not signed in
        db.execute("UPDATE files SET uploaded_at = datetime(uploaded_at, '-1 day')")
        db.commit()
    assert b"the record of this file was changed in the database" in alice.get(url).data
