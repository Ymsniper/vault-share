# Secure file sharing

Flask web app for sharing confidential files between users. Each file is
encrypted at rest with its own AES-256-GCM key, checked with SHA-256 and an
HMAC, and signed with an ECDSA key certified by a local CA.

## Run

    python -m venv .venv
    .venv/bin/pip install -r requirements-dev.txt
    export CA_PASSPHRASE='a long passphrase only you know'
    pki/create_ca.sh
    .venv/bin/flask --app app init-db
    .venv/bin/python run.py

Then open http://127.0.0.1:5000. `pki/create_ca.sh` creates the local CA in
`instance/ca/` once; the app needs the same `CA_PASSPHRASE` every time it
starts, to issue a certificate to each new user.

Uploading asks for your password again: it unlocks your private key to sign
the file. Each file page also offers a signature proof, a zip with the
signature, the signer's certificate, the CA certificate and the OpenSSL
commands that check the file without the app.

Five wrong passwords for one username, at login or upload, block it for 15
minutes, and twenty from one address block that address. The counters live
in memory (Flask-Limiter), so restarting the app clears them.

Two-factor login is optional, per user, from the "Two-factor" page: scan
the QR code with an authenticator app such as Aegis or FreeOTP and confirm
with a first code. Wrong codes count toward the same limit as wrong
passwords, and each code works only once.

A duress password, set from the "Duress" page, is the one to give if someone
forces you to log in. It opens your account as if it were empty and writes a
silent alert to the audit log; with the wipe option it first destroys your
files, their keys and your private key, which nobody can undo. Every account
has a duress slot, used or not, and its mode is stored encrypted, so the
database does not show who set one.

On first start the app creates two random keys in `instance/secrets/`:
`secret_key` signs the cookies and CSRF tokens, and `master.key` protects
the key of every stored file and the database itself, which SQLCipher keeps
fully encrypted. Back up `master.key` separately from the database: without
it nothing can be decrypted, and anyone holding both can read everything.

## USB stick and passphrase

By default the master key is `instance/secrets/master.key` alone. It can
also need a USB stick, a passphrase, or both; it is then rebuilt from all of
them each time, so the disk, the stick or the passphrase alone opens
nothing. Stop the app before changing this:

    .venv/bin/flask --app app keys add-usb /run/media/$USER/STICK
    .venv/bin/flask --app app keys set-passphrase
    .venv/bin/flask --app app keys status

`add-usb` writes a random key file on the stick and prints a recovery code:
keep it on paper, away from the stick, since it replaces a lost stick
(`keys remove-usb` asks for it when the stick is missing). While `run.py`
runs, pulling the stick out locks the app within a second: the key is
dropped from memory, everyone is logged out and visitors only see "This
service is paused"; the reason goes to the server log. Plugging it back
unlocks it. With a passphrase, the operator types it at `/unlock` after
every start; no page links there. Adding or removing a factor re-encrypts the database and
the wrapped file keys; the encrypted files themselves are not touched.

## HTTPS

    pki/create_server_cert.sh    # with CA_PASSPHRASE exported; again to renew
    .venv/bin/python run.py      # now https://localhost:5000

`run.py` serves HTTPS as soon as `instance/tls/server.crt` exists. The app
then redirects plain HTTP to HTTPS and marks the cookies Secure, through
Flask-Talisman, which also sets the Content-Security-Policy and the other
security headers. Browsers warn
until they trust the local CA: import `instance/ca/ca.crt` as a certificate
authority (in Firefox: Settings, Privacy & Security, View Certificates,
Authorities, Import). To look at the certificate chain from a terminal:

    openssl s_client -connect localhost:5000 -CAfile instance/ca/ca.crt

## Admin

To let a user read the audit log:

    .venv/bin/flask --app app admin grant <username>

To revoke a user's certificate, for example after their key leaked:

    .venv/bin/flask --app app admin revoke <username>

This needs `CA_PASSPHRASE`: it also writes `instance/ca/crl.pem`, a
revocation list signed by the CA. Files signed with the revoked certificate
stop passing verification, and the user's next upload gives them a new key
and certificate. OpenSSL can check a certificate against the list:

    openssl verify -crl_check -CAfile instance/ca/ca.crt -CRLfile instance/ca/crl.pem <certificate>

## Tests

    .venv/bin/pytest

`hooks/pre-commit` runs the local checks: bandit (a security linter), the
tests, and pip-audit (known vulnerabilities in the pinned dependencies,
needs the internet) when a requirements file is part of the commit. Run it
by hand, or have git run it before every commit:

    git config core.hooksPath hooks
