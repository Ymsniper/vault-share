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
starts, to issue a certificate to each new user. Uploading asks for your
password again: it unlocks your private key to sign the file.

On first start the app creates two random keys in `instance/secrets/`:
`secret_key` signs the cookies and CSRF tokens, and `master.key` protects
the key of every stored file. Back up `master.key` separately from the
database: without it no file can be decrypted, and anyone holding both
the database and that key can read every file.

When serving over HTTPS, set `SESSION_COOKIE_SECURE = True` in
`app/__init__.py` so the cookies are never sent over plain HTTP.

To let a user read the audit log:

    .venv/bin/flask --app app admin grant <username>

## Tests

    .venv/bin/pytest
