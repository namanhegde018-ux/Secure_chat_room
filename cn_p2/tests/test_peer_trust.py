import pytest
from crypto.peer_trust import PeerTrustStore


def test_peer_trust_pins_fingerprint_and_detects_change(tmp_path):
    store = PeerTrustStore(tmp_path / "trusted-peers.json")
    assert store.check("alice", "ABCD 1234") == "new"
    store.trust("alice", "ABCD 1234")
    assert store.check("alice", "abcd 1234") == "match"
    assert store.check("alice", "FFFF 9999") == "changed"
    with pytest.raises(ValueError):
        store.trust("alice", "FFFF 9999")


def test_corrupt_peer_trust_file_fails_closed(tmp_path):
    path = tmp_path / "trusted-peers.json"
    path.write_text("not-json", encoding="utf-8")
    store = PeerTrustStore(path)
    with pytest.raises(ValueError):
        store.check("alice", "ABCD")
