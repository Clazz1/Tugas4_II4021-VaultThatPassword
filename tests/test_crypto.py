from pwmanager.aes_gcm import AES128, InvalidTag, decrypt, encrypt
from pwmanager.shamir import recover_secret, split_secret


def test_aes128_block_vector():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    assert AES128(key).encrypt_block(plaintext).hex() == "69c4e0d86a7b0430d8cdb78070b4c55a"


def test_aes_gcm_empty_plaintext_vector():
    key = bytes(16)
    nonce = bytes(12)
    ciphertext, tag = encrypt(key, nonce, b"")
    assert ciphertext == b""
    assert tag.hex() == "58e2fccefa7e3061367f1d57a4e7455a"


def test_aes_gcm_single_block_vector():
    key = bytes(16)
    nonce = bytes(12)
    plaintext = bytes(16)
    ciphertext, tag = encrypt(key, nonce, plaintext)
    assert ciphertext.hex() == "0388dace60b6a392f328c2b971b2fe78"
    assert tag.hex() == "ab6e47d42cec13bdf53a67b21257bddf"
    assert decrypt(key, nonce, ciphertext, tag) == plaintext


def test_aes_gcm_rejects_tampering():
    key = b"K" * 16
    nonce = b"N" * 12
    ciphertext, tag = encrypt(key, nonce, b"secret")
    bad = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
    try:
        decrypt(key, nonce, bad, tag)
    except InvalidTag:
        pass
    else:
        raise AssertionError("tampered ciphertext should fail authentication")


def test_shamir_recovers_from_any_two_of_three_shares():
    secret = bytes.fromhex("00112233445566778899aabbccddeeff")
    shares = split_secret(secret, threshold=2, total=3)
    assert recover_secret([shares[0], shares[1]]) == secret
    assert recover_secret([shares[0], shares[2]]) == secret
    assert recover_secret([shares[1], shares[2]]) == secret
