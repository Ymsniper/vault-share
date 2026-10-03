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
password again: it unlocks your private key to sign the file. Five wrong
passwords for one username, at login or upload, block it for 15 minutes,
and twenty from one address block that address. The counters live in
memory (Flask-Limiter), so restarting the app clears them.

Two-factor login is optional, per user, from the "Two-factor" page: scan
the QR code with an authenticator app such as Aegis or FreeOTP and confirm
with a first code. Wrong codes count toward the same limit as wrong
passwords, and each code works only once. Each file page
also offers a signature proof: a zip with the signature, the signer's
certificate, the CA certificate and the OpenSSL commands that check the
file without the app.

On first start the app creates two random keys in `instance/secrets/`:
`secret_key` signs the cookies and CSRF tokens, and `master.key` protects
the key of every stored file. Back up `master.key` separately from the
database: without it no file can be decrypted, and anyone holding both
the database and that key can read every file.

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
