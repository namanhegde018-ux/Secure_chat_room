"""X25519 and HKDF session key derivation."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def derive_session_key(my_priv, their_pub, *, context: bytes = b"secure-messaging/v1") -> bytes:
    """Derive a 32-byte key. Include a unique session/transcript context at call sites."""
    if not isinstance(context, bytes) or not context:
        raise ValueError("context must be non-empty bytes")
    shared = my_priv.exchange(their_pub)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=context).derive(shared)
