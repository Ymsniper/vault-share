# Secure file sharing

Flask web app for sharing confidential files between users. Files are meant
to be encrypted at rest with AES-GCM, checked with SHA-256 and signed with
ECDSA keys certified by a local CA.

## Run

    python -m venv .venv
    .venv/bin/pip install -r requirements-dev.txt
    .venv/bin/flask --app app init-db
    .venv/bin/python run.py

Then open http://127.0.0.1:5000.

## Tests

    .venv/bin/pytest
