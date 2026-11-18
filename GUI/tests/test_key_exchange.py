from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from crypto.key_exchange import derive_session_key
from crypto.fingerprint import fingerprint


def test_both_peers_derive_same_key_and_context_rotates_key():
    alice, bob = X25519PrivateKey.generate(), X25519PrivateKey.generate()
    assert derive_session_key(alice, bob.public_key(), context=b"session-1") == derive_session_key(bob, alice.public_key(), context=b"session-1")
    assert derive_session_key(alice, bob.public_key(), context=b"session-2") != derive_session_key(alice, bob.public_key(), context=b"session-1")


def test_fingerprint_grouping_is_stable():
    assert fingerprint(b"public") == fingerprint(b"public")
    assert len(fingerprint(b"public").split()) == 8
