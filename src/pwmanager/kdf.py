from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

from .encoding import b64d, b64e


@dataclass(frozen=True)
class KdfParams:
    name: str
    salt: bytes
    n: int = 2**14
    r: int = 8
    p: int = 1
    length: int = 16

    def to_json(self) -> dict:
        return {
            "name": self.name,
            "salt": b64e(self.salt),
            "n": self.n,
            "r": self.r,
            "p": self.p,
            "length": self.length,
        }

    @classmethod
    def from_json(cls, data: dict) -> "KdfParams":
        if data.get("name") != "scrypt":
            raise ValueError("unsupported KDF")
        return cls(
            name="scrypt",
            salt=b64d(data["salt"]),
            n=int(data["n"]),
            r=int(data["r"]),
            p=int(data["p"]),
            length=int(data["length"]),
        )


def new_params() -> KdfParams:
    return KdfParams(name="scrypt", salt=secrets.token_bytes(16))


def derive_key(master_password: str, params: KdfParams) -> bytes:
    return hashlib.scrypt(
        master_password.encode("utf-8"),
        salt=params.salt,
        n=params.n,
        r=params.r,
        p=params.p,
        dklen=params.length,
    )
