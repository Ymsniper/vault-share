# Secure file sharing

Flask web app for sharing confidential files between users. Files are meant
to be encrypted at rest with AES-GCM, checked with SHA-256 and signed with
ECDSA keys certified by a local CA.

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

To let a user read the audit log:

    .venv/bin/flask --app app admin grant <username>

## Tests

    .venv/bin/pytest
