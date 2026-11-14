import threading

from argon2.low_level import Type, hash_secret_raw
from zxcvbn import zxcvbn

# every Argon2id call holds 64 MiB: four at most run at once, whatever the
# number of requests, so a burst of logins cannot use up the memory
_slots = threading.BoundedSemaphore(4)

# One run per password typed (app/levels.py): every check and key of an
# account's passwords comes from it. 9 passes over 64 MiB with 4 lanes,
# three times the passes of argon2-cffi's default profile (RFC 9106's
# low-memory one), which each of the three checks it replaced used.
MASTER_PARAMS = {"time_cost": 9, "memory_cost": 64 * 1024, "parallelism": 4}

# the master key's passphrase (app/keyring.py): that default profile, as
# before, so a passphrase set earlier still opens
PASSPHRASE_PARAMS = {"time_cost": 3, "memory_cost": 64 * 1024, "parallelism": 4}


def derive_master(password, salt):
    """The 256-bit value every check and key of this password comes from."""
    with _slots:
        return hash_secret_raw(password.encode(), salt, hash_len=32, type=Type.ID, **MASTER_PARAMS)


def derive_key(password, salt):
    """A 256-bit key from a passphrase, for the master key."""
    with _slots:
        return hash_secret_raw(
            password.encode(), salt, hash_len=32, type=Type.ID, **PASSPHRASE_PARAMS
        )


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
