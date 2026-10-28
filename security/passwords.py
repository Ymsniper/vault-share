import threading

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from argon2.low_level import Type, hash_secret_raw
from zxcvbn import zxcvbn

# argon2-cffi defaults to Argon2id with 64 MiB of memory, 3 passes, 4 lanes
# and a random 16-byte salt per hash (the RFC 9106 low-memory profile). The
# salt and the parameters are stored inside the hash string itself.
_hasher = PasswordHasher()
_DUMMY_HASH = _hasher.hash("not a real account")

# every Argon2id call holds 64 MiB: four at most run at once, whatever the
# number of requests, so a burst of logins cannot use up the memory
_slots = threading.BoundedSemaphore(4)


def hash_password(password):
    with _slots:
        return _hasher.hash(password)


def check_password(stored_hash, password):
    try:
        with _slots:
            return _hasher.verify(stored_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def derive_key(password, salt):
    """A 256-bit key from the password, at the same Argon2id cost as the hashes."""
    with _slots:
        return hash_secret_raw(
            password.encode(),
            salt,
            time_cost=_hasher.time_cost,
            memory_cost=_hasher.memory_cost,
            parallelism=_hasher.parallelism,
            hash_len=32,
            type=Type.ID,
        )


def check_password_of_unknown_user(password):
    """Spend as long as a real check, so timing does not show which usernames exist."""
    check_password(_DUMMY_HASH, password)
    return False


def password_problem(username, password):
    """Why this password is refused, or None if it is acceptable."""
    if username and username.lower() in password.lower():
        return "Password must not contain the username."
    # zxcvbn estimates how many guesses a cracker would need; a score of 3
    # out of 4 means at least 10^8, too many to try against Argon2id hashes
    result = zxcvbn(password, user_inputs=[username], max_length=128)
    if result["score"] < 3:
        hint = result["feedback"]["warning"] or "Add another word or two."
        return f"This password is too easy to guess. {hint}"
    return None


def passphrase_problem(passphrase):
    """Why a passphrase for one of the server's keys is refused, or None.
    These keys can be attacked offline once their files are copied: the
    master key and the CA's private key."""
    if len(passphrase) < 12:
        return "Use at least 12 characters."
    if len(passphrase) > 128:
        return "Use at most 128 characters."
    return password_problem("", passphrase)
