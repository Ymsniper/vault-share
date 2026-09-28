import datetime

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID


def load_ca(cert_path, key_path, passphrase):
    if not passphrase:
        raise ValueError("CA_PASSPHRASE is not set")
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    with open(key_path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=passphrase.encode())
    return cert, key


def make_csr(key, username):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, username)])
    return x509.CertificateSigningRequestBuilder().subject_name(name).sign(key, hashes.SHA256())


def issue_certificate(csr, ca_cert, ca_key, days=365):
    # the CSR is signed with the key it asks to certify, which proves the
    # requester holds that private key
    if not csr.is_signature_valid:
        raise ValueError("the CSR is not signed by its own key")
    now = datetime.datetime.now(datetime.UTC)
    public_key = csr.public_key()
    return (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )


def to_pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def load_certificate(pem):
    return x509.load_pem_x509_certificate(pem.encode())


def common_name(cert):
    return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value


def load_ca_certificate(path):
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def certificate_problem(cert, ca_cert, username):
    """Why cert cannot vouch for a signature by username, or None if it can."""
    try:
        cert.verify_directly_issued_by(ca_cert)
    except (ValueError, TypeError, InvalidSignature):
        return "the certificate was not issued by the local CA"
    now = datetime.datetime.now(datetime.UTC)
    if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
        return "the certificate has expired or is not valid yet"
    try:
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        usage = None
    if usage is None or not usage.digital_signature:
        return "the certificate does not allow signing"
    if common_name(cert) != username:
        return "the certificate belongs to someone else"
    return None
