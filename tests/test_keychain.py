import os

import pytest
from cryptography.exceptions import InvalidTag

from security.hybrid import generate_encryption_key, public_bytes
from security.keychain import (
    follow_link,
    link_key,
    lock_key,
    lock_signing_key,
    unlock_key,
    unlock_signing_key,
    unused_lock,
)
from security.signing import generate_key, sign_digest, verify_digest

PASSWORD = "contract-2026"


def test_a_lock_opens_with_its_password_only():
    key, salt = generate_encryption_key(), os.urandom(16)
    lock = lock_key(key, PASSWORD, salt, b"lock|1|0")
    assert public_bytes(unlock_key(lock, PASSWORD, salt, b"lock|1|0")) == public_bytes(key)
    with pytest.raises(InvalidTag):
        unlock_key(lock, "a guess", salt, b"lock|1|0")
    # bound to its account and level: moved to another row, it no longer opens
    with pytest.raises(InvalidTag):
        unlock_key(lock, PASSWORD, salt, b"lock|1|1")


def test_an_unused_lock_looks_like_a_real_one():
    key, salt = generate_encryption_key(), os.urandom(16)
    assert len(unused_lock()) == len(lock_key(key, PASSWORD, salt, b"lock|1|0"))
    assert unused_lock() != unused_lock()


def test_a_link_leads_down_only():
    upper, lower = generate_encryption_key(), generate_encryption_key()
    link = link_key(upper, lower, b"link|1|1")
    assert public_bytes(follow_link(upper, link, b"link|1|1")) == public_bytes(lower)
    # the lower key does not open its own link, and nothing leads back up
    with pytest.raises(InvalidTag):
        follow_link(lower, link, b"link|1|1")
    with pytest.raises(InvalidTag):
        follow_link(upper, link, b"link|1|2")


def test_the_signing_key_hangs_off_the_lowest_level():
    bottom, other = generate_encryption_key(), generate_encryption_key()
    signing = generate_key()
    blob = lock_signing_key(bottom, signing, b"signing|1")
    opened = unlock_signing_key(bottom, blob, b"signing|1")
    digest = os.urandom(32)
    assert verify_digest(signing.public_key(), sign_digest(opened, digest), digest)
    with pytest.raises(InvalidTag):
        unlock_signing_key(other, blob, b"signing|1")
    with pytest.raises(InvalidTag):
        unlock_signing_key(bottom, blob, b"signing|2")
