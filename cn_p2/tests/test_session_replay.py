import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from crypto.session import EphemeralHandshake, SessionSecurityContext
from crypto.replay import ReplayGuard, ReplayError


def test_signed_ephemeral_handshake_derives_matching_key():
    alice_id, bob_id = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    from crypto.identity import public_bytes
    alice_pub, bob_pub = public_bytes(alice_id), public_bytes(bob_id)
    alice = EphemeralHandshake.create(alice_id, "sid", bob_pub)
    bob = EphemeralHandshake.create(bob_id, "sid", alice_pub)
    alice.verify_peer(bob_id.public_key(), bob.public_key, bob.signature, alice_pub)
    bob.verify_peer(alice_id.public_key(), alice.public_key, alice.signature, bob_pub)
    transcript = b"alice-signed-message||bob-signed-message"
    assert alice.derive(bob.public_key, transcript) == bob.derive(alice.public_key, transcript)
    with pytest.raises(InvalidSignature):
        alice.verify_peer(bob_id.public_key(), bob.public_key, bob.signature, b"different-identity")
    with pytest.raises(InvalidSignature):
        # A trusted key that signed a modified ephemeral key is rejected.
        alice.verify_peer(bob_id.public_key(), b"\0" * len(bob.public_key), bob.signature, alice_pub)
    with pytest.raises(ValueError):
        alice.verify_peer(Ed25519PrivateKey.generate().public_key(), bob.public_key, bob.signature, alice_pub)


def test_replay_guard_rejects_duplicates_out_of_order_and_ended_session():
    guard = ReplayGuard("sid")
    guard.accept("sid", 0)
    with pytest.raises(ReplayError):
        guard.accept("sid", 0)
    with pytest.raises(ReplayError):
        guard.accept("other", 1)
    guard.end()
    with pytest.raises(ReplayError):
        guard.accept("sid", 1)


def test_session_context_discards_ephemeral_and_session_key_on_close():
    alice_id, bob_id = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    from crypto.identity import public_bytes
    alice_pub, bob_pub = public_bytes(alice_id), public_bytes(bob_id)
    alice = EphemeralHandshake.create(alice_id, "sid", bob_pub)
    bob = EphemeralHandshake.create(bob_id, "sid", alice_pub)
    alice.verify_peer(bob_id.public_key(), bob.public_key, bob.signature, alice_pub)
    ctx = SessionSecurityContext(alice)
    key = ctx.derive_key(bob.public_key, b"signed transcript")
    assert len(key) == 32
    ctx.accept_message("sid", 0)
    ctx.close()
    assert ctx.session_key is None
    assert ctx.handshake.private_key is None
    with pytest.raises(ValueError):
        ctx.accept_message("sid", 1)
