"""
Cryptographic primitives for the client.

  Ed25519            long-term identity keys (signatures)
  X25519             per-session ephemeral keys (key agreement, forward secrecy)
  HKDF-SHA256        derives directional session keys from the shared secret
  ChaCha20-Poly1305  AEAD protecting every message

Primitives come from the `cryptography` package. The protocol that combines
them is in handshake.py.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import struct
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEY_LEN = 32
SIGNATURE_LEN = 64
MAX_SEQ = 2**32 - 1  # messages per direction before a session must be replaced

_RAW = serialization.Encoding.Raw
_RAW_PUBLIC = serialization.PublicFormat.Raw
_RAW_PRIVATE = serialization.PrivateFormat.Raw


class CryptoError(Exception):
    """Base class for cryptographic failures."""


class AuthenticationError(CryptoError):
    """Data failed authentication: wrong key, tampered, replayed, or out of order."""


def lp(data: bytes) -> bytes:
    """Length-prefix a field so concatenated fields cannot be parsed ambiguously."""
    return struct.pack("!I", len(data)) + data


def raw_public_key(private_key: Ed25519PrivateKey | X25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(_RAW, _RAW_PUBLIC)


# ----------------------------------------------------------------------
# Identity and fingerprints
# ----------------------------------------------------------------------
class Identity:
    """The client's long-term Ed25519 identity. Users verify its public key."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private = private_key
        self.public_key: bytes = raw_public_key(private_key)

    @classmethod
    def generate(cls) -> "Identity":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def load_or_create(cls, path: str | Path) -> "Identity":
        """
        Load the identity from `path`, or create it with owner-only permissions.
        The file is not encrypted. Protect it, or use an OS keystore in production.
        """
        path = Path(path).expanduser()
        if path.exists():
            try:
                return cls(Ed25519PrivateKey.from_private_bytes(path.read_bytes()))
            except ValueError as exc:
                raise CryptoError(f"identity file {path} is corrupt") from exc

        identity = cls.generate()
        raw = identity._private.private_bytes(
            _RAW, _RAW_PRIVATE, serialization.NoEncryption()
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
        return identity

    @property
    def fingerprint(self) -> str:
        return fingerprint_of(self.public_key)

    def sign(self, data: bytes) -> bytes:
        return self._private.sign(data)


def fingerprint_of(public_key: bytes) -> str:
    """160-bit fingerprint of one identity key, formatted as '3FA2C 91BD0 ...'."""
    digest = hashlib.sha256(b"fingerprint-v1" + public_key).hexdigest()[:40].upper()
    return " ".join(digest[i:i + 5] for i in range(0, 40, 5))


def normalize_fingerprint(text: str) -> str:
    """Accept fingerprints typed with or without spaces, colons, or dashes, in any case."""
    return re.sub(r"[\s:-]", "", text).upper()


def safety_number(key_a: bytes, key_b: bytes) -> str:
    """
    A single value both users should see identically. It is computed from both
    identity keys in sorted order, so it does not depend on who is "A" and "B".
    """
    first, second = sorted((key_a, key_b))
    digest = hashlib.sha256(
        b"safety-number-v1" + lp(first) + lp(second)
    ).hexdigest()[:60].upper()
    return " ".join(digest[i:i + 5] for i in range(0, 60, 5))


# ----------------------------------------------------------------------
# Primitive wrappers
# ----------------------------------------------------------------------
def verify_signature(public_key: bytes, signature: bytes, data: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, data)
        return True
    except (InvalidSignature, ValueError):
        return False


def ecdh(private_key: X25519PrivateKey, peer_public: bytes) -> bytes:
    try:
        shared = private_key.exchange(X25519PublicKey.from_public_bytes(peer_public))
    except ValueError as exc:
        raise AuthenticationError("invalid ephemeral public key") from exc
    if shared == bytes(KEY_LEN):
        raise AuthenticationError("ephemeral key produced an all-zero secret")
    return shared


def derive_keys(shared_secret: bytes, transcript: bytes) -> tuple[bytes, bytes]:
    """Return (initiator->responder key, responder->initiator key)."""
    okm = HKDF(
        algorithm=hashes.SHA256(),
        length=2 * KEY_LEN,
        salt=transcript,
        info=b"signaling-session-keys-v1",
    ).derive(shared_secret)
    return okm[:KEY_LEN], okm[KEY_LEN:]


def nonce_for(seq: int) -> bytes:
    """96-bit nonce: 32 zero bits followed by the 64-bit sequence number."""
    if not 0 <= seq <= MAX_SEQ:
        raise CryptoError("sequence number out of range")
    return b"\x00" * 4 + struct.pack("!Q", seq)


# ----------------------------------------------------------------------
# Secure channel
# ----------------------------------------------------------------------
class SecureChannel:
    """
    Authenticated encryption for one session, in both directions.

    * Each direction has its own key, so sequence number 0 in one direction
      never collides with sequence number 0 in the other.
    * The nonce is the sequence number. Under one key it only increases, so a
      nonce is never reused.
    * The receiver accepts only the next expected sequence number. This rejects
      replays, reordering, and dropped messages.
    * Session ID, sender, recipient, and sequence number are authenticated as
      associated data. A message cannot be moved to another session or
      redirected to another client.
    """

    def __init__(
        self,
        *,
        send_key: bytes,
        recv_key: bytes,
        session_id: str,
        local_id: str,
        peer_id: str,
    ) -> None:
        if len(send_key) != KEY_LEN or len(recv_key) != KEY_LEN:
            raise CryptoError("keys must be 32 bytes")
        self._send_aead = ChaCha20Poly1305(send_key)
        self._recv_aead = ChaCha20Poly1305(recv_key)
        self._session_id = session_id
        self._local_id = local_id
        self._peer_id = peer_id
        self._send_seq = 0
        self._recv_seq = 0

    @property
    def send_seq(self) -> int:
        return self._send_seq

    @property
    def recv_seq(self) -> int:
        return self._recv_seq

    def _aad(self, sender: str, recipient: str, seq: int) -> bytes:
        return (
            b"signaling-message-v1"
            + lp(self._session_id.encode("utf-8"))
            + lp(sender.encode("utf-8"))
            + lp(recipient.encode("utf-8"))
            + struct.pack("!Q", seq)
        )

    def encrypt(self, plaintext: bytes) -> tuple[int, bytes]:
        seq = self._send_seq
        if seq > MAX_SEQ:
            raise CryptoError("send sequence exhausted; establish a new session")
        ciphertext = self._send_aead.encrypt(
            nonce_for(seq),
            plaintext,
            self._aad(self._local_id, self._peer_id, seq),
        )
        self._send_seq = seq + 1
        return seq, ciphertext

    def decrypt(self, seq: int, ciphertext: bytes) -> bytes:
        if seq != self._recv_seq:
            raise AuthenticationError(
                f"unexpected sequence number {seq} (expected {self._recv_seq})"
            )
        try:
            plaintext = self._recv_aead.decrypt(
                nonce_for(seq),
                ciphertext,
                self._aad(self._peer_id, self._local_id, seq),
            )
        except InvalidTag as exc:
            raise AuthenticationError("message failed authentication") from exc
        # Advance only after successful authentication, so a forged message
        # cannot desynchronize the channel.
        self._recv_seq = seq + 1
        return plaintext

    def seal(self, body: dict) -> dict:
        """Encrypt a JSON object into a relayable envelope."""
        plaintext = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        seq, ciphertext = self.encrypt(plaintext)
        return {
            "kind": "secure",
            "seq": seq,
            "ct": base64.b64encode(ciphertext).decode("ascii"),
        }

    def unseal(self, envelope: dict) -> dict:
        """Decrypt and authenticate an envelope produced by the peer's seal()."""
        seq = envelope.get("seq")
        ct_text = envelope.get("ct")
        if (
            envelope.get("kind") != "secure"
            or isinstance(seq, bool)
            or not isinstance(seq, int)
            or not isinstance(ct_text, str)
        ):
            raise CryptoError("malformed secure envelope")
        try:
            ciphertext = base64.b64decode(ct_text, validate=True)
        except ValueError as exc:
            raise CryptoError("ciphertext is not valid base64") from exc

        plaintext = self.decrypt(seq, ciphertext)
        try:
            body = json.loads(plaintext.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CryptoError("decrypted payload is not JSON") from exc
        if not isinstance(body, dict):
            raise CryptoError("decrypted payload must be a JSON object")
        return body