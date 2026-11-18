"""Signed ephemeral X25519 handshake helpers."""

from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from .key_exchange import derive_session_key
from .replay import ReplayGuard


@dataclass
class EphemeralHandshake:
    private_key: X25519PrivateKey
    public_key: bytes
    signature: bytes
    session_id: str
    peer_identity: bytes

    @classmethod
    def create(cls, identity: Ed25519PrivateKey, session_id: str, peer_identity: bytes):
        if not session_id or not peer_identity:
            raise ValueError("session_id and peer identity are required")
        private = X25519PrivateKey.generate()
        public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        signed = b"sm-handshake-v1\0" + session_id.encode("utf-8") + b"\0" + peer_identity + b"\0" + public
        return cls(private, public, identity.sign(signed), session_id, peer_identity)

    def verify_peer(self, peer_key: Ed25519PublicKey, peer_ephemeral: bytes, signature: bytes, my_identity: bytes):
        expected_peer = peer_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        if expected_peer != self.peer_identity:
            raise ValueError("peer identity key does not match the previously verified fingerprint")
        signed = b"sm-handshake-v1\0" + self.session_id.encode("utf-8") + b"\0" + my_identity + b"\0" + peer_ephemeral
        peer_key.verify(signature, signed)

    def derive(self, their_ephemeral: bytes, transcript: bytes) -> bytes:
        if not transcript:
            raise ValueError("transcript must bind both signed handshake messages")
        their = X25519PublicKey.from_public_bytes(their_ephemeral)
        return derive_session_key(self.private_key, their, context=b"secure-messaging/session/v1\0" + transcript)

    def discard(self):
        # Python cannot promise zeroization of immutable/native key material; drop references promptly.
        self.private_key = None


class SessionSecurityContext:
    """Owns one session's ephemeral key, derived key, replay counter, and end cleanup."""

    def __init__(self, handshake: EphemeralHandshake):
        self.handshake = handshake
        self.session_id = handshake.session_id
        self.session_key: bytes | None = None
        self.replay = ReplayGuard(self.session_id)
        self.ended = False

    def derive_key(self, peer_ephemeral: bytes, transcript: bytes) -> bytes:
        if self.ended or self.session_key is not None:
            raise ValueError("session is ended or its key is already established")
        self.session_key = self.handshake.derive(peer_ephemeral, transcript)
        return self.session_key

    def accept_message(self, session_id: str, sequence: int) -> None:
        if self.ended:
            raise ValueError("session has ended")
        self.replay.accept(session_id, sequence)

    def close(self) -> None:
        if self.ended:
            return
        self.ended = True
        self.replay.end()
        self.session_key = None
        self.handshake.discard()
