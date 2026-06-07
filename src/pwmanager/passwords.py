from __future__ import annotations

import secrets
import string


ALPHABET = string.ascii_lowercase + string.ascii_uppercase + string.digits + "!@#$%^&*()-_=+[]{};:,.?/|"


def generate_password(length: int) -> str:
    if length < 8:
        raise ValueError("password length must be at least 8")
    return "".join(secrets.choice(ALPHABET) for _ in range(length))
