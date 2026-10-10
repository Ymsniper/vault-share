import pytest
from cryptography.exceptions import InvalidTag

from security.crypto import new_key
from security.hybrid import generate_encryption_key, public_bytes, unwrap_file_key, wrap_file_key
from security.signing import lock_private_key, unlock_private_key

FILE_ID = "3f0c2a5e-1d4b-4c8e-9a71-0b2f6d8e4c10"
BOB = 2


def test_only_the_recipient_opens_their_copy():
    bob, eve = generate_encryption_key(), generate_encryption_key()
    file_key = new_key()
    copy = wrap_file_key(public_bytes(bob), file_key, FILE_ID, BOB)
    assert file_key not in copy
    assert unwrap_file_key(bob, copy, FILE_ID, BOB) == file_key
    with pytest.raises(InvalidTag):
        unwrap_file_key(eve, copy, FILE_ID, BOB)


@pytest.mark.parametrize(
    ("file_id", "user_id"),
    [("6a1e7c3d-2b9f-4e05-8d44-7f3a9c1b2e58", BOB), (FILE_ID, 3)],
    ids=["another file", "another person"],
)
def test_a_copy_opens_only_for_its_file_and_person(file_id, user_id):
    bob = generate_encryption_key()
    copy = wrap_file_key(public_bytes(bob), new_key(), FILE_ID, BOB)
    with pytest.raises(InvalidTag):
        unwrap_file_key(bob, copy, file_id, user_id)


def test_a_changed_byte_is_detected():
    bob = generate_encryption_key()
    copy = bytearray(wrap_file_key(public_bytes(bob), new_key(), FILE_ID, BOB))
    copy[-1] ^= 1
    with pytest.raises(InvalidTag):
        unwrap_file_key(bob, bytes(copy), FILE_ID, BOB)


def test_every_copy_is_different():
    # a fresh ephemeral key each time, so copies cannot be compared
    bob = generate_encryption_key()
    file_key = new_key()
    first = wrap_file_key(public_bytes(bob), file_key, FILE_ID, BOB)
    assert first != wrap_file_key(public_bytes(bob), file_key, FILE_ID, BOB)


def test_the_private_key_opens_only_with_the_password():
    bob = generate_encryption_key()
    salt, locked = lock_private_key(bob, "contract-2026", b"bob:encryption")
    with pytest.raises(InvalidTag):
        unlock_private_key(salt, locked, "not the password", b"bob:encryption")
    with pytest.raises(InvalidTag):
        unlock_private_key(salt, locked, "contract-2026", b"bob")
    opened = unlock_private_key(salt, locked, "contract-2026", b"bob:encryption")
    assert public_bytes(opened) == public_bytes(bob)
