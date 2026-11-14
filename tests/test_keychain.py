import os

import pytest
from cryptography.exceptions import InvalidTag

from security.hybrid import generate_encryption_key, public_bytes
from security.keychain import (
    follow_link,
    link_key,
    lock_key,
    lock_secret,
    lock_signing_key,
    unlock_key,
    unlock_signing_key,
    unused_lock,
    verifier,
)
from security.signing import generate_key, sign_digest, verify_digest

MASTER = os.urandom(32)


def test_a_lock_opens_with_its_password_s_secret_only():
    key = generate_encryption_key()
    lock = lock_key(key, lock_secret(MASTER, 1, 0), b"lock|1|0")
    assert public_bytes(unlock_key(lock, lock_secret(MASTER, 1, 0), b"lock|1|0")) == public_bytes(key)
    with pytest.raises(InvalidTag):
        unlock_key(lock, lock_secret(os.urandom(32), 1, 0), b"lock|1|0")
    # bound to its account and level: moved to another row, it no longer opens
    with pytest.raises(InvalidTag):
        unlock_key(lock, lock_secret(MASTER, 1, 0), b"lock|1|1")
    # and each level's secret is its own
    assert lock_secret(MASTER, 1, 0) != lock_secret(MASTER, 1, 1) != lock_secret(MASTER, 2, 1)


def test_an_unused_lock_looks_like_a_real_one():
    key = generate_encryption_key()
    assert len(unused_lock()) == len(lock_key(key, lock_secret(MASTER, 1, 0), b"lock|1|0"))
    assert unused_lock() != unused_lock()


def test_a_verifier_names_its_row():
    # 32 bytes, as random as an unused row's, and bound to account and row
    assert len(verifier(MASTER, 1, 7)) == 32
    assert verifier(MASTER, 1, 7) == verifier(MASTER, 1, 7)
    assert len({verifier(MASTER, 1, 7), verifier(MASTER, 1, 8), verifier(MASTER, 2, 7),
                verifier(os.urandom(32), 1, 7)}) == 4


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


@pytest.mark.real_argon2
def test_one_run_is_nine_passes_at_64_mib(monkeypatch):
    """Design revision 2, B1: the one run per password is three times as
    strong as each of the three it replaces."""
    from security import passwords

    seen = {}
    monkeypatch.setattr(passwords, "hash_secret_raw",
                        lambda secret, salt, **kw: seen.update(kw) or bytes(32))
    passwords.derive_master("password", bytes(16))
    assert (seen["time_cost"], seen["memory_cost"], seen["parallelism"]) == (9, 64 * 1024, 4)
    assert seen["hash_len"] == 32 and seen["type"].name == "ID"

