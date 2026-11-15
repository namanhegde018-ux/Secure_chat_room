"""Readable SHA-256 public-key fingerprints."""

import hashlib


def fingerprint(pubkey: bytes) -> str:
    if not isinstance(pubkey, bytes) or not pubkey:
        raise ValueError("pubkey must be non-empty bytes")
    # 128 bits is a compact comparison fingerprint; show as four-hex-character groups.
    value = hashlib.sha256(pubkey).hexdigest()[:32].upper()
    return " ".join(value[i:i + 4] for i in range(0, len(value), 4))
