#!/bin/sh
# Make certificates that the app must refuse, all for the same user name:
#   expired.crt   issued by the local CA, but only valid in January 2025
#   rogue.crt     issued by rogue-ca.crt, a CA the app does not trust
# Each certificate gets its own new key (expired.key, rogue.key).
#
# usage: CA_PASSPHRASE=... pki/make_test_certs.sh <username> [CA dir] [output dir]
set -eu

: "${CA_PASSPHRASE:?export CA_PASSPHRASE first}"
if [ $# -lt 1 ]; then
    echo "usage: $0 <username> [CA dir] [output dir]" >&2
    exit 2
fi
user=$1
pki=$(dirname "$0")
ca=${2:-"$pki/../instance/ca"}
out=${3:-"$pki/../instance/test-certs"}
cnf="$pki/openssl.cnf"

mkdir -p "$out"
umask 077

newkey() {
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1"
}

newkey "$out/expired.key"
openssl req -new -config "$cnf" -key "$out/expired.key" -subj "/CN=$user" -out "$out/expired.csr"
openssl x509 -req -in "$out/expired.csr" \
    -CA "$ca/ca.crt" -CAkey "$ca/ca.key" -passin env:CA_PASSPHRASE \
    -extfile "$cnf" -extensions v3_user \
    -not_before 20250101000000Z -not_after 20250201000000Z -out "$out/expired.crt"

newkey "$out/rogue-ca.key"
openssl req -x509 -new -config "$cnf" -extensions v3_ca -key "$out/rogue-ca.key" \
    -subj "/CN=Rogue CA" -days 365 -out "$out/rogue-ca.crt"
newkey "$out/rogue.key"
openssl req -new -config "$cnf" -key "$out/rogue.key" -subj "/CN=$user" -out "$out/rogue.csr"
openssl x509 -req -in "$out/rogue.csr" \
    -CA "$out/rogue-ca.crt" -CAkey "$out/rogue-ca.key" \
    -extfile "$cnf" -extensions v3_user -days 365 -out "$out/rogue.crt"

rm "$out/expired.csr" "$out/rogue.csr"

# both should fail: "certificate has expired" and "unable to get local issuer certificate"
for name in expired rogue; do
    openssl verify -CAfile "$ca/ca.crt" "$out/$name.crt" 2>&1 || true
done
