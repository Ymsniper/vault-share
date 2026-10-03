import hmac
import time

import pyotp
import qrcode
import qrcode.image.svg

ISSUER = "File sharing"


def new_secret():
    """160 random bits, base32, the format authenticator apps expect."""
    return pyotp.random_base32()


def qr_svg(secret, username):
    uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=ISSUER)
    img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage)
    return img.to_string(encoding="unicode")


def matching_step(secret, code, last_step):
    """The 30-second time step this code belongs to, or None.

    The steps just before and after the current one are accepted, to absorb
    clock drift between the phone and the server. A step at or before
    last_step was already used, so every code works only once.
    """
    totp = pyotp.TOTP(secret)
    now = int(time.time()) // totp.interval
    for step in (now - 1, now, now + 1):
        if last_step is not None and step <= last_step:
            continue
        if hmac.compare_digest(totp.generate_otp(step), code):
            return step
    return None
