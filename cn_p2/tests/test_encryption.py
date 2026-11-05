import os
import pytest
from cryptography.exceptions import InvalidTag
from crypto.encryption import decrypt, encrypt


def test_round_trip_and_nonce_uniqueness():
    key = os.urandom(32)
    a, b = encrypt(key, b"hello"), encrypt(key, b"hello")
    assert decrypt(key, a) == b"hello"
    assert a != b
    assert a[:12] != b[:12]


def test_wrong_key_and_tampering_rejected():
    key = os.urandom(32)
    sealed = encrypt(key, b"secret")
    with pytest.raises(InvalidTag):
        decrypt(os.urandom(32), sealed)
    changed = sealed[:-1] + bytes([sealed[-1] ^ 1])
    with pytest.raises(InvalidTag):
        decrypt(key, changed)


def test_short_ciphertext_rejected():
    with pytest.raises(ValueError):
        decrypt(os.urandom(32), b"tiny")
