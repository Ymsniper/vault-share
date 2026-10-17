# Vault-Share

Secure file sharing: a Flask web app for sharing confidential files between
users. Each file is encrypted at rest with its own AES-256-GCM key, kept
only as copies encrypted to the public key of each person allowed to open
it, checked with SHA-256 and an HMAC, and signed with an ECDSA key certified
by a local CA.

<!-- The pictures live in docs/screenshots/; replace a file there to update it here. -->
![The file list](docs/screenshots/web-files.png)

## Features

- Every file has its own AES-256-GCM key, stored only as copies encrypted
  with HPKE (X25519) for its owner and each person it is shared with: the
  server's own keys cannot open a stored file.
- Files are signed with ECDSA P-256 keys certified by a local OpenSSL CA,
  with revocation and a signature proof that can be checked offline.
- The database is encrypted with SQLCipher, and every file record is
  protected by an HMAC.
- Argon2id passwords, server-side sessions, CSRF protection, rate limits,
  security headers and optional two-factor login.
- A duress password that opens an empty account, and can wipe it.
- The master key can also require a USB stick and a passphrase; pulling the
  stick locks the service.
- A terminal console to run and manage the server.
- A Fallout-inspired interface.

## Run

    python -m venv .venv
    .venv/bin/pip install -r requirements-dev.txt
    bin/vault-share install        # the `vault-share` command, from any terminal
    read -s -x CA_PASSPHRASE       # fish; in bash: read -rs CA_PASSPHRASE && export CA_PASSPHRASE
    pki/create_ca.sh
    vault-share init-db
    vault-share                    # the console; `vault-share serve` runs the server alone

![Setting up and starting the server](docs/screenshots/setup-install.png)

`read -s` asks for the CA passphrase without showing it and without saving
it in the shell history, which `export CA_PASSPHRASE='...'` would do. The
console asks for it itself at startup when it is not set, and keeps it in
memory only. `vault-share` passes anything else to `flask --app app`, so
`vault-share keys status` or `vault-share admin grant alice` work from any
folder; `vault-share install` links the command into `~/.local/bin`.

Then open http://127.0.0.1:5000. `pki/create_ca.sh` creates the local CA in
`instance/ca/` once; the app needs the same `CA_PASSPHRASE` every time it
starts, to issue a certificate to each new user.

## Using it

![Logging in](docs/screenshots/web-login.png)

Uploading asks for your password again: it unlocks your private key to sign
the file. Each file page also offers a signature proof, a zip with the
signature, the signer's certificate, the CA certificate and the OpenSSL
commands that check the file without the app.

![Uploading a file](docs/screenshots/web-upload.png)

![A file's page: verified record, download, sharing](docs/screenshots/web-file-record.png)

Every visit to a file's page checks its record and signature, and every
download checks the file itself. A record changed behind the app's back
shows up at once:

![A record that fails its check](docs/screenshots/web-integrity-failed.png)

Five wrong passwords for one username, at login or upload, block it for 15
minutes, and twenty from one address block that address. The counters live
in memory (Flask-Limiter), so restarting the app clears them.

Two-factor login is optional, per user, from the "Two-factor" page: scan
the QR code with an authenticator app such as Aegis or FreeOTP and confirm
with a first code. Wrong codes count toward the same limit as wrong
passwords, and each code works only once.

![Turning on two-factor login](docs/screenshots/web-two-factor.png)

A duress password, set from the "Duress" page, is the one to give if someone
forces you to log in. It opens your account as if it were empty and writes a
silent alert to the audit log; with the wipe option it first destroys your
files, every file key copy made for you and your private keys, which nobody
can undo. Every account
has a duress slot, used or not, and its mode is stored encrypted, so the
database does not show who set one.

![Setting a duress password](docs/screenshots/web-duress.png)

The pages also work on a phone:

<img src="docs/screenshots/web-mobile.png" alt="The file list on a phone" width="300">

On first start the app creates two random keys in `instance/secrets/`:
`secret_key` signs the cookies and CSRF tokens, and `master.key` protects
the database itself, which SQLCipher keeps fully encrypted, along with the
file records' HMACs, the two-factor secrets and the duress settings. Back up
`master.key` separately from the database: without it the database cannot
be opened.

## File keys

The master key does not open files. Each file's key is stored only as
copies encrypted with HPKE (RFC 9180: X25519, HKDF-SHA256, AES-256-GCM), one
for each person who may open the file: its owner and every recipient of an
active share. Every user has an X25519 key pair for this, separate from
their signing key, and its private key is locked under a key derived from
their password with Argon2id. So even someone holding the whole server, keys
included, opens no file without the password of a person it was shared with.

That is why download and share ask for your password, like upload: it
unlocks your key for that one request, so a stolen session cookie alone
downloads nothing. Sharing opens your copy and encrypts the key again for
the recipient; revoking deletes their copy, so bringing the share back in
the database gives them nothing.

![A file shared with you](docs/screenshots/web-shared-file.png)

This is not end-to-end encryption. While a file is uploaded or downloaded
the server sees it, which is what lets it check uploads; a compromised
running server could keep what passes through it. The same library also
offers a post-quantum suite (`MLKEM768_X25519`) for a later upgrade.

## Server console

    vault-share                    # or: .venv/bin/python -m console

A terminal console (Textual) that runs the app and replaces most commands:
start and stop the server and watch its log, unlock it, see users and make
one an admin or revoke a certificate, read the audit log as it fills, add or
remove the USB stick and the passphrase, create the CA and the HTTPS
certificate, and reset the database. It uses the terminal's own colors.
Every action also stays available as a `flask --app app ...` command.

<table>
  <tr>
    <td width="50%"><img src="docs/screenshots/console-splash.png" alt="Startup checks"><br>Startup checks</td>
    <td width="50%"><img src="docs/screenshots/console-ca-passphrase.png" alt="The CA passphrase prompt"><br>The CA passphrase, asked at startup and kept in memory</td>
  </tr>
  <tr>
    <td width="50%"><img src="docs/screenshots/console-server.png" alt="The server and its log"><br>The server and its log</td>
    <td width="50%"><img src="docs/screenshots/console-users.png" alt="Users"><br>Users: make an admin, revoke a certificate</td>
  </tr>
  <tr>
    <td width="50%"><img src="docs/screenshots/console-audit.png" alt="The audit log"><br>The audit log as it fills</td>
    <td width="50%"><img src="docs/screenshots/console-setup.png" alt="Setup"><br>Setup: the CA, its passphrase, the HTTPS certificate</td>
  </tr>
</table>

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
the record HMACs; file keys and the encrypted files are not touched, since
the master key does not protect them.

The console's Keys tab does the same without commands:

![The master key's factors in the console](docs/screenshots/console-keys.png)

## HTTPS

    pki/create_server_cert.sh    # with CA_PASSPHRASE exported; again to renew
    .venv/bin/python run.py      # now https://localhost:5000

![Creating the HTTPS certificate](docs/screenshots/setup-https.png)

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

![The audit log](docs/screenshots/web-audit-log.png)

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
