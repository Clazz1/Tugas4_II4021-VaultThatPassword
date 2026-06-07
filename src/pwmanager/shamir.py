from __future__ import annotations

import json
import secrets
from dataclasses import dataclass

from .encoding import b64d, b64e

PRIME = 2**521 - 1


@dataclass(frozen=True)
class Share:
    x: int
    y: int


def _eval_poly(coefficients: list[int], x: int) -> int:
    result = 0
    for coefficient in reversed(coefficients):
        result = (result * x + coefficient) % PRIME
    return result


def split_secret(secret: bytes, threshold: int = 2, total: int = 3) -> list[Share]:
    if threshold < 2:
        raise ValueError("threshold must be at least 2")
    if total < threshold:
        raise ValueError("total shares must be >= threshold")

    secret_int = int.from_bytes(secret, "big")
    if secret_int >= PRIME:
        raise ValueError("secret is too large for the selected field")

    coefficients = [secret_int] + [secrets.randbelow(PRIME - 1) + 1 for _ in range(threshold - 1)]
    return [Share(x=x, y=_eval_poly(coefficients, x)) for x in range(1, total + 1)]


def recover_secret(shares: list[Share], length: int = 16) -> bytes:
    if len({share.x for share in shares}) != len(shares):
        raise ValueError("duplicate share coordinate")
    if len(shares) < 2:
        raise ValueError("at least two shares are required")

    secret = 0
    for i, share_i in enumerate(shares):
        numerator = 1
        denominator = 1
        for j, share_j in enumerate(shares):
            if i == j:
                continue
            numerator = (numerator * (-share_j.x)) % PRIME
            denominator = (denominator * (share_i.x - share_j.x)) % PRIME
        lagrange = numerator * pow(denominator, -1, PRIME)
        secret = (secret + share_i.y * lagrange) % PRIME
    if secret >= 1 << (length * 8):
        raise ValueError("recovered secret does not fit the expected key length")
    return secret.to_bytes(length, "big")


def share_to_dict(share: Share, label: str) -> dict:
    return {
        "scheme": "SSS-P521",
        "threshold": 2,
        "label": label,
        "x": share.x,
        "y": hex(share.y),
    }


def share_from_dict(data: dict) -> Share:
    if data.get("scheme") != "SSS-P521":
        raise ValueError("unsupported share scheme")
    return Share(x=int(data["x"]), y=int(str(data["y"]), 16))


def format_share(share: Share, label: str) -> str:
    """Return a compact JSON share that still contains x and y explicitly."""
    return json.dumps(share_to_dict(share, label), separators=(",", ":"))


def parse_share(text: str) -> Share:
    text = text.strip()
    if text.startswith("SSS1."):
        payload = json.loads(b64d(text[5:]).decode("utf-8"))
    else:
        payload = json.loads(text)
    return share_from_dict(payload)


def format_share_token(share: Share, label: str) -> str:
    payload = json.dumps(share_to_dict(share, label), separators=(",", ":")).encode("utf-8")
    return "SSS1." + b64e(payload)
