"""
Tests for the cryptography layer.

Run from the project root:
    python -m unittest tests.test_crypto -v
"""

import base64
import os
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from client_core.crypto import (
    MAX_SEQ,
    AuthenticationError,
    CryptoError,
    Identity,
    SecureChannel,
    fingerprint_of,
    nonce_for,
    raw_public_key,
    safety_number,
)
from client_core.handshake import HandshakeError, HandshakeState, PeerSession
from client_core.trust import PeerKeyChanged, TrustStore


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(text: str) -> bytes:
    return base64.b64decode(text)


def make_pair(session_id, alice_id, bob_id, alice_trust=None, bob_trust=None):
    """Unstarted initiator ('alice') and responder ('bob') sessions."""
    return (
        PeerSession(
            session_id, "alice", "bob", alice_id,
            alice_trust if alice_trust is not None else TrustStore(),
        ),
        PeerSession(
            session_id, "bob", "alice", bob_id,
            bob_trust if bob_trust is not None else TrustStore(),
        ),
    )


def run_handshake(alice, bob):
    hs2 = bob.handle(alice.start())   # hs1 -> hs2
    hs3 = alice.handle(hs2)           # hs2 -> hs3
    bob.handle(hs3)                   # hs3 -> done
    return alice, bob


def establish(session_id, alice_id, bob_id, alice_trust=None, bob_trust=None):
    return run_handshake(*make_pair(session_id, alice_id, bob_id, alice_trust, bob_trust))


def make_channel():
    """A one-way sender/receiver pair with fresh random keys."""
    key_a, key_b = os.urandom(32), os.urandom(32)
    sender = SecureChannel(send_key=key_a, recv_key=key_b, session_id="s", local_id="alice", peer_id="bob")
    receiver = SecureChannel(send_key=key_b, recv_key=key_a, session_id="s", local_id="bob", peer_id="alice")
    return sender, receiver


# ----------------------------------------------------------------------
# Alice encrypts, Bob decrypts
# ----------------------------------------------------------------------
class MessagingTests(unittest.TestCase):
    def setUp(self):
        self.alice_id = Identity.generate()
        self.bob_id = Identity.generate()
        self.alice, self.bob = establish("session-1", self.alice_id, self.bob_id)

    def test_both_sides_establish_and_learn_each_others_keys(self):
        self.assertTrue(self.alice.established)
        self.assertTrue(self.bob.established)
        self.assertEqual(self.alice.peer_identity_key, self.bob_id.public_key)
        self.assertEqual(self.bob.peer_identity_key, self.alice_id.public_key)

    def test_alice_encrypts_and_bob_decrypts(self):
        envelope = self.alice.channel.seal({"text": "hello bob"})
        self.assertEqual(self.bob.channel.unseal(envelope), {"text": "hello bob"})

    def test_ciphertext_does_not_contain_plaintext(self):
        envelope = self.alice.channel.seal({"text": "hello bob"})
        self.assertNotIn(b"hello bob", unb64(envelope["ct"]))

    def test_bob_can_reply_to_alice(self):
        envelope = self.bob.channel.seal({"text": "hi alice"})
        self.assertEqual(self.alice.channel.unseal(envelope), {"text": "hi alice"})

    def test_conversation_in_both_directions(self):
        for i in range(20):
            sender, receiver = (self.alice, self.bob) if i % 2 == 0 else (self.bob, self.alice)
            envelope = sender.channel.seal({"i": i})
            self.assertEqual(receiver.channel.unseal(envelope), {"i": i})

    def test_channel_unavailable_before_handshake_completes(self):
        pending = PeerSession("s", "alice", "bob", self.alice_id, TrustStore())
        pending.start()
        with self.assertRaises(HandshakeError):
            _ = pending.channel


# ----------------------------------------------------------------------
# Incorrect keys fail authentication
# ----------------------------------------------------------------------
class IncorrectKeyTests(unittest.TestCase):
    def test_channel_with_other_keys_cannot_open_message(self):
        alice_id, bob_id, eve_id = Identity.generate(), Identity.generate(), Identity.generate()
        alice, _bob = establish("s1", alice_id, bob_id)
        # Eve holds a valid session with Bob, but not the keys for Alice's session.
        eve, _eve_bob = establish("s-eve", eve_id, bob_id)

        envelope = alice.channel.seal({"secret": "for bob only"})
        with self.assertRaises(AuthenticationError):
            eve.channel.unseal(envelope)

    def test_impersonator_fails_against_pinned_key(self):
        alice_id, bob_id, mallory_id = Identity.generate(), Identity.generate(), Identity.generate()
        alice_trust = TrustStore()
        establish("s1", alice_id, bob_id, alice_trust=alice_trust)   # Alice pins Bob's key

        # Mallory answers the next handshake as "bob" with her own key.
        alice2, mallory_as_bob = make_pair("s2", alice_id, mallory_id, alice_trust=alice_trust)
        hs2 = mallory_as_bob.handle(alice2.start())
        with self.assertRaises(PeerKeyChanged):
            alice2.handle(hs2)
        self.assertEqual(alice2.state, HandshakeState.FAILED)
        self.assertFalse(alice2.established)

    def test_forged_responder_signature_is_rejected(self):
        alice_id, bob_id, mallory_id = Identity.generate(), Identity.generate(), Identity.generate()
        alice, bob = make_pair("s1", alice_id, bob_id)
        hs2 = bob.handle(alice.start())

        # Mallory replaces the signature with one made by her own key.
        forged = dict(hs2, sig=b64(mallory_id.sign(b"responder-auth" + b"not the transcript")))
        with self.assertRaises(HandshakeError):
            alice.handle(forged)

    def test_substituted_ephemeral_key_breaks_signature(self):
        alice_id, bob_id = Identity.generate(), Identity.generate()
        alice, bob = make_pair("s1", alice_id, bob_id)
        hs2 = bob.handle(alice.start())

        attacker_eph = raw_public_key(X25519PrivateKey.generate())
        with self.assertRaises(HandshakeError):
            alice.handle(dict(hs2, eph=b64(attacker_eph)))

    def test_handshake_message_cannot_be_replayed_into_another_session(self):
        alice_id, bob_id = Identity.generate(), Identity.generate()
        alice1, bob1 = make_pair("s1", alice_id, bob_id)
        hs2_for_s1 = bob1.handle(alice1.start())

        alice2 = PeerSession("s2", "alice", "bob", alice_id, TrustStore())
        alice2.start()
        with self.assertRaises(HandshakeError):
            alice2.handle(hs2_for_s1)

    def test_recovery_after_verified_key_change(self):
        alice_id, bob_id = Identity.generate(), Identity.generate()
        alice_trust = TrustStore()
        establish("s1", alice_id, bob_id, alice_trust=alice_trust)

        new_bob_id = Identity.generate()
        with self.assertRaises(PeerKeyChanged):
            establish("s2", alice_id, new_bob_id, alice_trust=alice_trust)

        # After out-of-band verification, the user forgets the old key and reconnects.
        alice_trust.forget("bob")
        alice, bob = establish("s3", alice_id, new_bob_id, alice_trust=alice_trust)
        self.assertTrue(alice.established)
        self.assertEqual(alice_trust.pinned_key("bob"), new_bob_id.public_key)


# ----------------------------------------------------------------------
# Modified ciphertext is rejected
# ----------------------------------------------------------------------
class TamperingTests(unittest.TestCase):
    def setUp(self):
        self.alice, self.bob = establish("s1", Identity.generate(), Identity.generate())

    def test_flipped_ciphertext_bit_is_rejected(self):
        envelope = self.alice.channel.seal({"text": "pay 10"})
        ct = bytearray(unb64(envelope["ct"]))
        ct[0] ^= 0x01
        with self.assertRaises(AuthenticationError):
            self.bob.channel.unseal({**envelope, "ct": b64(bytes(ct))})

    def test_flipped_tag_bit_is_rejected(self):
        envelope = self.alice.channel.seal({"text": "pay 10"})
        ct = bytearray(unb64(envelope["ct"]))
        ct[-1] ^= 0x01
        with self.assertRaises(AuthenticationError):
            self.bob.channel.unseal({**envelope, "ct": b64(bytes(ct))})

    def test_truncated_ciphertext_is_rejected(self):
        envelope = self.alice.channel.seal({"text": "pay 10"})
        with self.assertRaises(AuthenticationError):
            self.bob.channel.unseal({**envelope, "ct": b64(unb64(envelope["ct"])[:-1])})

    def test_modified_sequence_number_is_rejected(self):
        envelope = self.alice.channel.seal({"text": "pay 10"})
        with self.assertRaises(AuthenticationError):
            self.bob.channel.unseal({**envelope, "seq": envelope["seq"] + 1})

    def test_replayed_message_is_rejected(self):
        envelope = self.alice.channel.seal({"text": "pay 10"})
        self.bob.channel.unseal(envelope)
        with self.assertRaises(AuthenticationError):
            self.bob.channel.unseal(envelope)

    def test_reflected_message_is_rejected(self):
        envelope = self.alice.channel.seal({"text": "pay 10"})
        with self.assertRaises(AuthenticationError):
            self.alice.channel.unseal(envelope)

    def test_forgery_does_not_advance_receive_state(self):
        envelope = self.alice.channel.seal({"text": "real"})
        ct = bytearray(unb64(envelope["ct"]))
        ct[0] ^= 0x01
        with self.assertRaises(AuthenticationError):
            self.bob.channel.unseal({**envelope, "ct": b64(bytes(ct))})

        # The genuine message is still accepted in sequence.
        self.assertEqual(self.bob.channel.unseal(envelope), {"text": "real"})


# ----------------------------------------------------------------------
# Different sessions use different keys
# ----------------------------------------------------------------------
class SessionKeyTests(unittest.TestCase):
    def test_different_sessions_use_different_keys(self):
        alice_id, bob_id = Identity.generate(), Identity.generate()
        a1, b1 = establish("session-1", alice_id, bob_id)
        a2, b2 = establish("session-2", alice_id, bob_id)

        env1 = a1.channel.seal({"text": "same text"})
        env2 = a2.channel.seal({"text": "same text"})

        self.assertNotEqual(env1["ct"], env2["ct"])
        self.assertEqual(b1.channel.unseal(env1), {"text": "same text"})
        with self.assertRaises(AuthenticationError):
            b2.channel.unseal(env1)   # session-1 traffic is useless in session-2

    def test_repeated_handshakes_never_repeat_keys(self):
        alice_id, bob_id = Identity.generate(), Identity.generate()
        ciphertexts = set()
        for i in range(10):
            alice, _bob = establish(f"session-{i}", alice_id, bob_id)
            ciphertexts.add(alice.channel.seal({"text": "identical"})["ct"])
        self.assertEqual(len(ciphertexts), 10)


# ----------------------------------------------------------------------
# Nonces are never reused with the same key
# ----------------------------------------------------------------------
class NonceTests(unittest.TestCase):
    def test_sequence_numbers_and_nonces_are_unique(self):
        alice, bob = establish("s1", Identity.generate(), Identity.generate())
        envelopes = [alice.channel.seal({"i": i}) for i in range(5000)]

        seqs = [e["seq"] for e in envelopes]
        self.assertEqual(seqs, list(range(5000)))
        self.assertEqual(len({nonce_for(s) for s in seqs}), 5000)
        self.assertEqual(len({e["ct"] for e in envelopes}), 5000)

        # All of them decrypt in order.
        for i, envelope in enumerate(envelopes):
            self.assertEqual(bob.channel.unseal(envelope), {"i": i})

    def test_same_plaintext_never_yields_same_ciphertext(self):
        alice, _bob = establish("s1", Identity.generate(), Identity.generate())
        envelopes = [alice.channel.seal({"text": "same"}) for _ in range(100)]
        self.assertEqual(len({e["ct"] for e in envelopes}), 100)

    def test_both_directions_start_at_zero_without_collision(self):
        alice, bob = establish("s1", Identity.generate(), Identity.generate())
        a_env = alice.channel.seal({"x": 1})
        b_env = bob.channel.seal({"x": 1})

        self.assertEqual(a_env["seq"], 0)
        self.assertEqual(b_env["seq"], 0)
        # Same sequence number, different directional keys: different ciphertexts.
        self.assertNotEqual(a_env["ct"], b_env["ct"])

    def test_nonce_for_is_bounded(self):
        self.assertEqual(len(nonce_for(0)), 12)
        self.assertEqual(len(nonce_for(MAX_SEQ)), 12)
        with self.assertRaises(CryptoError):
            nonce_for(-1)
        with self.assertRaises(CryptoError):
            nonce_for(MAX_SEQ + 1)

    def test_sending_stops_when_sequence_space_is_exhausted(self):
        channel, _ = make_channel()
        channel._send_seq = MAX_SEQ + 1
        with self.assertRaises(CryptoError):
            channel.encrypt(b"x")


# ----------------------------------------------------------------------
# Fingerprints, safety numbers, and pinning
# ----------------------------------------------------------------------
class FingerprintAndTrustTests(unittest.TestCase):
    def test_fingerprint_format(self):
        self.assertRegex(Identity.generate().fingerprint, r"^(?:[0-9A-F]{5} ){7}[0-9A-F]{5}$")

    def test_safety_number_is_symmetric(self):
        a, b = Identity.generate(), Identity.generate()
        self.assertEqual(
            safety_number(a.public_key, b.public_key),
            safety_number(b.public_key, a.public_key),
        )

    def test_handshake_pins_peer_key_as_unverified(self):
        alice_id, bob_id = Identity.generate(), Identity.generate()
        alice_trust = TrustStore()
        establish("s1", alice_id, bob_id, alice_trust=alice_trust)
        self.assertEqual(alice_trust.pinned_key("bob"), bob_id.public_key)
        self.assertFalse(alice_trust.is_verified("bob"))

    def test_matching_fingerprint_verifies_in_any_format(self):
        alice_id, bob_id = Identity.generate(), Identity.generate()
        trust = TrustStore()
        establish("s1", alice_id, bob_id, alice_trust=trust)

        typed = bob_id.fingerprint.lower().replace(" ", "")
        self.assertTrue(trust.verify("bob", typed))
        self.assertTrue(trust.is_verified("bob"))

    def test_wrong_fingerprint_does_not_verify(self):
        alice_id, bob_id = Identity.generate(), Identity.generate()
        trust = TrustStore()
        establish("s1", alice_id, bob_id, alice_trust=trust)

        wrong = fingerprint_of(Identity.generate().public_key)
        self.assertFalse(trust.verify("bob", wrong))
        self.assertFalse(trust.is_verified("bob"))

    def test_pins_and_verification_survive_restart(self):
        bob_id = Identity.generate()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trust.json"
            first = TrustStore(path)
            first.pin("bob", bob_id.public_key)
            first.verify("bob", bob_id.fingerprint)

            reloaded = TrustStore(path)
            self.assertEqual(reloaded.pinned_key("bob"), bob_id.public_key)
            self.assertTrue(reloaded.is_verified("bob"))

    def test_identity_is_stable_across_restarts(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "identity.key"
            first = Identity.load_or_create(path)
            second = Identity.load_or_create(path)
            self.assertEqual(first.public_key, second.public_key)


if __name__ == "__main__":
    unittest.main()

