#!/bin/sh
# Have the local CA issue the HTTPS certificate of this machine: a new ECDSA
# P-256 key and a certificate for localhost and 127.0.0.1, valid one year.
# Run it again to renew.
#
# The server key is not encrypted, because the app has to start without
# anyone typing a passphrase; only its owner can read it.
#
# usage: CA_PASSPHRASE=... pki/create_server_cert.sh [CA dir] [output dir]
set -eu

: "${CA_PASSPHRASE:?export CA_PASSPHRASE first}"
pki=$(dirname "$0")
ca=${1:-"$pki/../instance/ca"}
out=${2:-"$pki/../instance/tls"}
cnf="$pki/openssl.cnf"

mkdir -p "$out"
umask 077
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$out/server.key"
openssl req -new -config "$cnf" -key "$out/server.key" -subj "/CN=localhost" -out "$out/server.csr"
openssl x509 -req -in "$out/server.csr" \
    -CA "$ca/ca.crt" -CAkey "$ca/ca.key" -passin env:CA_PASSPHRASE \
    -extfile "$cnf" -extensions v3_server -days 365 -out "$out/server.crt"
rm "$out/server.csr"
openssl verify -CAfile "$ca/ca.crt" -purpose sslserver "$out/server.crt"
