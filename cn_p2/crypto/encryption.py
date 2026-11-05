"""AES-256-GCM authenticated encryption. Wire format: nonce || ciphertext || tag."""

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE = 12
KEY_SIZE = 32
TAG_SIZE = 16


def encrypt(key: bytes, data: bytes) -> bytes:
    if not isinstance(key, bytes) or len(key) != KEY_SIZE:
        raise ValueError("AES-256-GCM requires a 32-byte key")
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    nonce = os.urandom(NONCE_SIZE)
    return nonce + AESGCM(key).encrypt(nonce, data, None)


def decrypt(key: bytes, data: bytes) -> bytes:
    if not isinstance(key, bytes) or len(key) != KEY_SIZE:
        raise ValueError("AES-256-GCM requires a 32-byte key")
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if len(data) < NONCE_SIZE + TAG_SIZE:
        raise ValueError("ciphertext is malformed or truncated")
    return AESGCM(key).decrypt(data[:NONCE_SIZE], data[NONCE_SIZE:], None)
