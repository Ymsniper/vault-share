#!/bin/sh
# Create the local certificate authority that issues user certificates:
# an ECDSA P-256 key encrypted with AES-256 under $CA_PASSPHRASE, and a
# self-signed certificate valid for 10 years.
#
# usage: CA_PASSPHRASE=... pki/create_ca.sh [output dir]
set -eu

: "${CA_PASSPHRASE:?export CA_PASSPHRASE first}"
pki=$(dirname "$0")
out=${1:-"$pki/../instance/ca"}

# a new CA key would make every certificate already issued untrusted
if [ -e "$out/ca.key" ]; then
    echo "$out/ca.key already exists, not overwriting it" >&2
    exit 1
fi

mkdir -p "$out"
umask 077
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -aes256 -pass env:CA_PASSPHRASE -out "$out/ca.key"
openssl req -x509 -new -config "$pki/openssl.cnf" -extensions v3_ca \
    -key "$out/ca.key" -passin env:CA_PASSPHRASE \
    -sha256 -days 3650 -out "$out/ca.crt"
openssl x509 -in "$out/ca.crt" -noout -subject -enddate
