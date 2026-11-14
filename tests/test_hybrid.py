import pytest
from cryptography.exceptions import InvalidTag

from app import levels
from app.db import get_db
from security.crypto import new_key
from security.hybrid import generate_encryption_key, public_bytes, unwrap_file_key, wrap_file_key

from .test_files import private_key, user_id

FILE_ID = "3f0c2a5e-1d4b-4c8e-9a71-0b2f6d8e4c10"
BOB = 2


def test_only_the_recipient_opens_their_copy():
    bob, eve = generate_encryption_key(), generate_encryption_key()
    file_key = new_key()
    copy = wrap_file_key(public_bytes(bob), file_key, FILE_ID, BOB, 0)
    assert file_key not in copy
    assert unwrap_file_key(bob, copy, FILE_ID, BOB, 0) == file_key
    with pytest.raises(InvalidTag):
        unwrap_file_key(eve, copy, FILE_ID, BOB, 0)


@pytest.mark.parametrize(
    ("file_id", "user_id", "level"),
    [("6a1e7c3d-2b9f-4e05-8d44-7f3a9c1b2e58", BOB, 0), (FILE_ID, 3, 0), (FILE_ID, BOB, 1)],
    ids=["another file", "another person", "another level"],
)
def test_a_copy_opens_only_for_its_file_person_and_level(file_id, user_id, level):
    bob = generate_encryption_key()
    copy = wrap_file_key(public_bytes(bob), new_key(), FILE_ID, BOB, 0)
    with pytest.raises(InvalidTag):
        unwrap_file_key(bob, copy, file_id, user_id, level)


def test_a_changed_byte_is_detected():
    bob = generate_encryption_key()
    copy = bytearray(wrap_file_key(public_bytes(bob), new_key(), FILE_ID, BOB, 0))
    copy[-1] ^= 1
    with pytest.raises(InvalidTag):
        unwrap_file_key(bob, bytes(copy), FILE_ID, BOB, 0)


def test_every_copy_is_different():
    # a fresh ephemeral key each time, so copies cannot be compared
    bob = generate_encryption_key()
    file_key = new_key()
    first = wrap_file_key(public_bytes(bob), file_key, FILE_ID, BOB, 0)
    assert first != wrap_file_key(public_bytes(bob), file_key, FILE_ID, BOB, 0)


def test_every_user_gets_four_key_pairs_apart_from_the_signing_key(app, alice):
    with app.app_context():
        db = get_db()
        publics = [
            r["public_key"] for r in db.execute(
                "SELECT public_key FROM level_keys WHERE user_id = ? ORDER BY level",
                (user_id(app, alice.handle),),
            )
        ]
        signing = db.execute("SELECT enc_private_key FROM signing_keys").fetchone()[0]
    # one per level, and one below the last for its cover files
    assert len(publics) == len(set(publics)) == levels.KEY_LEVELS
    assert all(len(p) == 32 for p in publics) and signing not in publics
    # her password opens the first one, and it is the pair of its public key
    with pytest.raises(InvalidTag):
        private_key(app, alice.handle, "not the password")
    assert public_bytes(private_key(app, alice.handle)) == publics[0]
