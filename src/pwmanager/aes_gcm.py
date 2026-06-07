from __future__ import annotations

import hmac


class InvalidTag(ValueError):
    """Raised saat autentikasi AES-GCM gagal."""


S_BOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

R_CON = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36,
)


def _bytes2matrix(block: bytes) -> list[list[int]]:
    return [list(block[i:i + 4]) for i in range(0, len(block), 4)]


def _matrix2bytes(matrix: list[list[int]]) -> bytes:
    return bytes(sum(matrix, []))


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _add_round_key(state: list[list[int]], key: list[list[int]]) -> None:
    for i in range(4):
        for j in range(4):
            state[i][j] ^= key[i][j]


def _sub_bytes(state: list[list[int]]) -> None:
    for i in range(4):
        for j in range(4):
            state[i][j] = S_BOX[state[i][j]]


def _shift_rows(state: list[list[int]]) -> None:
    state[0][1], state[1][1], state[2][1], state[3][1] = state[1][1], state[2][1], state[3][1], state[0][1]
    state[0][2], state[1][2], state[2][2], state[3][2] = state[2][2], state[3][2], state[0][2], state[1][2]
    state[0][3], state[1][3], state[2][3], state[3][3] = state[3][3], state[0][3], state[1][3], state[2][3]


def _xtime(a: int) -> int:
    return (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)


def _mix_single_column(a: list[int]) -> None:
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ _xtime(a[0] ^ a[1])
    a[1] ^= t ^ _xtime(a[1] ^ a[2])
    a[2] ^= t ^ _xtime(a[2] ^ a[3])
    a[3] ^= t ^ _xtime(a[3] ^ u)


def _mix_columns(state: list[list[int]]) -> None:
    for i in range(4):
        _mix_single_column(state[i])


def _expand_key(master_key: bytes) -> list[list[list[int]]]:
    if len(master_key) != 16:
        raise ValueError("AES-128 requires a 16-byte key")

    key_columns = _bytes2matrix(master_key)
    iteration_size = 4
    rcon_iteration = 1

    while len(key_columns) < 44:
        word = list(key_columns[-1])
        if len(key_columns) % iteration_size == 0:
            word.append(word.pop(0))
            word = [S_BOX[b] for b in word]
            word[0] ^= R_CON[rcon_iteration]
            rcon_iteration += 1
        word = [x ^ y for x, y in zip(word, key_columns[-iteration_size])]
        key_columns.append(word)

    return [key_columns[4 * i:4 * (i + 1)] for i in range(11)]


class AES128:
    def __init__(self, key: bytes):
        self.round_keys = _expand_key(key)

    def encrypt_block(self, plaintext: bytes) -> bytes:
        if len(plaintext) != 16:
            raise ValueError("AES block must be exactly 16 bytes")

        state = _bytes2matrix(plaintext)
        _add_round_key(state, self.round_keys[0])

        for round_index in range(1, 10):
            _sub_bytes(state)
            _shift_rows(state)
            _mix_columns(state)
            _add_round_key(state, self.round_keys[round_index])

        _sub_bytes(state)
        _shift_rows(state)
        _add_round_key(state, self.round_keys[-1])
        return _matrix2bytes(state)


def _inc32(counter: bytes) -> bytes:
    prefix = counter[:12]
    suffix = (int.from_bytes(counter[12:], "big") + 1) & 0xFFFFFFFF
    return prefix + suffix.to_bytes(4, "big")


def _gf128_mul(x: int, y: int) -> int:
    z = 0
    v = y
    reduction = 0xE1000000000000000000000000000000
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ reduction
        else:
            v >>= 1
    return z


def _iter_blocks(data: bytes) -> list[bytes]:
    if not data:
        return []
    return [data[i:i + 16].ljust(16, b"\x00") for i in range(0, len(data), 16)]


def _ghash(h: int, aad: bytes, ciphertext: bytes) -> bytes:
    y = 0
    for block in _iter_blocks(aad) + _iter_blocks(ciphertext):
        y = _gf128_mul(y ^ int.from_bytes(block, "big"), h)
    length_block = (len(aad) * 8).to_bytes(8, "big") + (len(ciphertext) * 8).to_bytes(8, "big")
    y = _gf128_mul(y ^ int.from_bytes(length_block, "big"), h)
    return y.to_bytes(16, "big")


def _crypt_ctr(aes: AES128, j0: bytes, data: bytes) -> bytes:
    counter = _inc32(j0)
    parts: list[bytes] = []
    for offset in range(0, len(data), 16):
        block = data[offset:offset + 16]
        stream = aes.encrypt_block(counter)
        parts.append(_xor_bytes(block, stream[:len(block)]))
        counter = _inc32(counter)
    return b"".join(parts)


def encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    """Encrypt plaintext and return (ciphertext, tag)."""
    if len(key) != 16:
        raise ValueError("AES-128-GCM requires a 16-byte key")
    if len(nonce) != 12:
        raise ValueError("This implementation expects a 12-byte GCM nonce")

    aes = AES128(key)
    h = int.from_bytes(aes.encrypt_block(b"\x00" * 16), "big")
    j0 = nonce + b"\x00\x00\x00\x01"
    ciphertext = _crypt_ctr(aes, j0, plaintext)
    tag = _xor_bytes(aes.encrypt_block(j0), _ghash(h, aad, ciphertext))
    return ciphertext, tag


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
    """Decrypt ciphertext."""
    if len(key) != 16:
        raise ValueError("AES-128-GCM requires a 16-byte key")
    if len(nonce) != 12:
        raise ValueError("This implementation expects a 12-byte GCM nonce")

    aes = AES128(key)
    h = int.from_bytes(aes.encrypt_block(b"\x00" * 16), "big")
    j0 = nonce + b"\x00\x00\x00\x01"
    expected_tag = _xor_bytes(aes.encrypt_block(j0), _ghash(h, aad, ciphertext))
    if not hmac.compare_digest(expected_tag, tag):
        raise InvalidTag("AES-GCM authentication failed")
    return _crypt_ctr(aes, j0, ciphertext)


def seal(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    ciphertext, tag = encrypt(key, nonce, plaintext, aad)
    return ciphertext + tag


def open_sealed(key: bytes, nonce: bytes, sealed: bytes, aad: bytes = b"") -> bytes:
    if len(sealed) < 16:
        raise InvalidTag("sealed message is too short")
    return decrypt(key, nonce, sealed[:-16], sealed[-16:], aad)
