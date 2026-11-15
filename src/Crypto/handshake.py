"""
Authenticated key establishment for one session.

Protocol (SIGMA-style, standard primitives only):

    I = initiator (the client with the smaller ID), R = responder
    Each side has a long-term Ed25519 identity key and a fresh X25519
    ephemeral key for this session.

    I -> R   hs1: I_eph, I_id
    R -> I   hs2: R_eph, R_id, sig_R = Sign(R_id, "responder-auth" || T)
    I -> R   hs3: sig_I = Sign(I_id, "initiator-auth" || T)

    T       = SHA-256(session_id, I, R, I_id, R_id, I_eph, R_eph)
    shared  = X25519(own_eph_private, peer_eph_public)
    k_I->R, k_R->I = HKDF-SHA256(shared, salt = T)

What this achieves:
  * Signatures prove each side controls the identity key it presented.
  * T binds the session, roles, identity keys, and both ephemerals. Changing any
    of them invalidates the signatures, so messages cannot be spliced across
    sessions or swapped.
  * Fresh ephemeral keys give every session different keys and forward secrecy.
  * Identity keys are not certified by any authority. A malicious server can
    present its own key to both sides on first contact. Pinning plus
    out-of-band fingerprint verification (trust.py) is what detects this.
"""

from __future__ import annotations

import base64
import binascii
import enum
import hashlib

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .crypto import (
    KEY_LEN,
    SIGNATURE_LEN,
    CryptoError,
    Identity,
    SecureChannel,
    derive_keys,
    ecdh,
    lp,
    raw_public_key,
    verify_signature,
)
from .trust import TrustStore

HANDSHAKE_KINDS = frozenset({"hs1", "hs2", "hs3"})


class HandshakeError(CryptoError):
    """A handshake message was invalid or unexpected, or the handshake failed."""


class HandshakeState(enum.Enum):
    IDLE = "idle"
    AWAITING_RESPONSE = "awaiting_response"   # initiator, after sending hs1
    AWAITING_FINISH = "awaiting_finish"       # responder, after sending hs2
    ESTABLISHED = "established"
    FAILED = "failed"


def transcript_hash(
    session_id: str,
    initiator_id: str,
    responder_id: str,
    initiator_key: bytes,
    responder_key: bytes,
    initiator_eph: bytes,
    responder_eph: bytes,
) -> bytes:
    h = hashlib.sha256()
    for field in (
        b"signaling-handshake-v1",
        session_id.encode("utf-8"),
        initiator_id.encode("utf-8"),
        responder_id.encode("utf-8"),
        initiator_key,
        responder_key,
        initiator_eph,
        responder_eph,
    ):
        h.update(lp(field))
    return h.digest()


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64_field(body: dict, name: str, length: int) -> bytes:
    value = body.get(name)
    if not isinstance(value, str):
        raise HandshakeError(f"field {name!r} must be base64 text")
    try:
        data = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HandshakeError(f"field {name!r} is not valid base64") from exc
    if len(data) != length:
        raise HandshakeError(f"field {name!r} must be {length} bytes")
    return data


class PeerSession:
    """Handshake and secure channel for one session between this client and one peer."""

    def __init__(
        self,
        session_id: str,
        local_id: str,
        peer_id: str,
        identity: Identity,
        trust: TrustStore,
    ) -> None:
        if local_id == peer_id:
            raise ValueError("a session needs two distinct clients")
        self.session_id = session_id
        self.local_id = local_id
        self.peer_id = peer_id
        self.is_initiator = local_id < peer_id
        self.state = HandshakeState.IDLE
        self.error: str | None = None
        self.peer_identity_key: bytes | None = None

        self._identity = identity
        self._trust = trust
        self._eph: X25519PrivateKey | None = None
        self._channel: SecureChannel | None = None
        self._init_key: bytes | None = None                # responder: initiator's key from hs1
        self._transcript: bytes | None = None
        self._keys: tuple[bytes, bytes] | None = None      # responder: keys held until hs3

    @property
    def established(self) -> bool:
        return self.state is HandshakeState.ESTABLISHED

    @property
    def channel(self) -> SecureChannel:
        if not self.established or self._channel is None:
            raise HandshakeError("secure channel is not established")
        return self._channel

    def start(self) -> dict:
        """Initiator only: create the hs1 body to send to the peer."""
        if not self.is_initiator:
            raise HandshakeError("only the initiator starts the handshake")
        if self.state is not HandshakeState.IDLE:
            raise HandshakeError("handshake already started")
        self._eph = X25519PrivateKey.generate()
        self.state = HandshakeState.AWAITING_RESPONSE
        return {
            "kind": "hs1",
            "eph": _b64(raw_public_key(self._eph)),
            "id": _b64(self._identity.public_key),
        }

    def handle(self, body: dict) -> dict | None:
        """
        Process one handshake message from the peer.
        Returns the reply body to send, or None. Raises CryptoError subclasses on failure.
        """
        kind = body.get("kind")
        try:
            if kind == "hs1" and self.state is HandshakeState.IDLE and not self.is_initiator:
                return self._on_hs1(body)
            if kind == "hs2" and self.state is HandshakeState.AWAITING_RESPONSE and self.is_initiator:
                return self._on_hs2(body)
            if kind == "hs3" and self.state is HandshakeState.AWAITING_FINISH and not self.is_initiator:
                self._on_hs3(body)
                return None
            raise HandshakeError(f"unexpected handshake message {kind!r} in state {self.state.value}")
        except CryptoError as exc:
            # An error after establishment must not tear down a working channel.
            if self.state not in (HandshakeState.ESTABLISHED, HandshakeState.FAILED):
                self._fail(str(exc))
            raise

    # ------------------------------------------------------------------
    def _transcript_for(
        self,
        initiator_key: bytes,
        responder_key: bytes,
        initiator_eph: bytes,
        responder_eph: bytes,
    ) -> bytes:
        if self.is_initiator:
            initiator_id, responder_id = self.local_id, self.peer_id
        else:
            initiator_id, responder_id = self.peer_id, self.local_id
        return transcript_hash(
            self.session_id,
            initiator_id,
            responder_id,
            initiator_key,
            responder_key,
            initiator_eph,
            responder_eph,
        )

    def _on_hs1(self, body: dict) -> dict:
        init_eph = _b64_field(body, "eph", KEY_LEN)
        init_key = _b64_field(body, "id", KEY_LEN)
        self._trust.check(self.peer_id, init_key)   # refuse early if the key changed

        self._eph = X25519PrivateKey.generate()
        resp_eph = raw_public_key(self._eph)
        transcript = self._transcript_for(init_key, self._identity.public_key, init_eph, resp_eph)

        self._keys = derive_keys(ecdh(self._eph, init_eph), transcript)
        self._init_key = init_key
        self._transcript = transcript
        self.state = HandshakeState.AWAITING_FINISH

        return {
            "kind": "hs2",
            "eph": _b64(resp_eph),
            "id": _b64(self._identity.public_key),
            "sig": _b64(self._identity.sign(b"responder-auth" + transcript)),
        }

    def _on_hs2(self, body: dict) -> dict:
        resp_eph = _b64_field(body, "eph", KEY_LEN)
        resp_key = _b64_field(body, "id", KEY_LEN)
        resp_sig = _b64_field(body, "sig", SIGNATURE_LEN)

        if self._eph is None:
            raise HandshakeError("no ephemeral key for this handshake")
        init_eph = raw_public_key(self._eph)
        transcript = self._transcript_for(self._identity.public_key, resp_key, init_eph, resp_eph)

        if not verify_signature(resp_key, resp_sig, b"responder-auth" + transcript):
            raise HandshakeError("responder signature is invalid")

        # Pin only after the signature proves the presenter holds this key.
        self._trust.pin(self.peer_id, resp_key)

        keys = derive_keys(ecdh(self._eph, resp_eph), transcript)
        hs3_sig = self._identity.sign(b"initiator-auth" + transcript)
        self._finish(keys, resp_key)
        return {"kind": "hs3", "sig": _b64(hs3_sig)}

    def _on_hs3(self, body: dict) -> None:
        init_sig = _b64_field(body, "sig", SIGNATURE_LEN)
        if self._init_key is None or self._transcript is None or self._keys is None:
            raise HandshakeError("no handshake in progress")

        if not verify_signature(self._init_key, init_sig, b"initiator-auth" + self._transcript):
            raise HandshakeError("initiator signature is invalid")

        self._trust.pin(self.peer_id, self._init_key)
        self._finish(self._keys, self._init_key)

    def _finish(self, keys: tuple[bytes, bytes], peer_key: bytes) -> None:
        k_i2r, k_r2i = keys
        send_key, recv_key = (k_i2r, k_r2i) if self.is_initiator else (k_r2i, k_i2r)
        self._channel = SecureChannel(
            send_key=send_key,
            recv_key=recv_key,
            session_id=self.session_id,
            local_id=self.local_id,
            peer_id=self.peer_id,
        )
        self.peer_identity_key = peer_key
        self.state = HandshakeState.ESTABLISHED
        self._clear_secrets()

    def _fail(self, reason: str) -> None:
        self.state = HandshakeState.FAILED
        self.error = reason
        self._clear_secrets()

    def _clear_secrets(self) -> None:
        # Python cannot reliably zero memory; dropping references is the best available.
        self._eph = None
        self._keys = None
        self._transcript = None
        self._init_key = None