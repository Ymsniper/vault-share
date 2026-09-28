import re

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from argon2.low_level import Type, hash_secret_raw

# argon2-cffi defaults to Argon2id with 64 MiB of memory, 3 passes, 4 lanes
# and a random 16-byte salt per hash (the RFC 9106 low-memory profile). The
# salt and the parameters are stored inside the hash string itself.
_hasher = PasswordHasher()
_DUMMY_HASH = _hasher.hash("not a real account")

USERNAME_RE = re.compile(r"[A-Za-z0-9_]{3,32}")

# a few of the most common long passwords; a real deployment would check a
# large list of leaked passwords instead
COMMON_PASSWORDS = frozenset(
    {
        "123456789012",
        "1234567890123",
        "password1234",
        "password12345",
        "qwertyuiop12",
        "qwerty123456",
        "1q2w3e4r5t6y",
        "iloveyou1234",
        "abcdefghijkl",
        "aaaaaaaaaaaa",
        "111111111111",
        "azertyuiop12",
        "motdepasse123",
        "administrator",
        "changeme1234",
    }
)


def hash_password(password):
    return _hasher.hash(password)


def check_password(stored_hash, password):
    try:
        return _hasher.verify(stored_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def derive_key(password, salt):
    """A 256-bit key from the password, at the same Argon2id cost as the hashes."""
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
    if not 12 <= len(password) <= 128:
        return "Password must be 12 to 128 characters long."
    if username.lower() in password.lower():
        return "Password must not contain the username."
    if password.lower() in COMMON_PASSWORDS:
        return "This password is too common."
    return None
