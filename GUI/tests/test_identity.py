import pytest
import os
import subprocess
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from crypto.identity import load_identity, new_identity, public_bytes


def test_identity_encrypted_round_trip_and_bad_password(tmp_path):
    path = tmp_path / "identity.key"
    original = new_identity(path, "test password")
    loaded = load_identity(path, "test password")
    assert public_bytes(original) == public_bytes(loaded)
    with pytest.raises(ValueError):
        load_identity(path, "wrong password")
    with pytest.raises(FileExistsError):
        from crypto.identity import save_identity
        save_identity(path, Ed25519PrivateKey.generate(), "other")
    if os.name == "nt":
        acl = subprocess.run(["icacls", str(path)], check=True, capture_output=True, text=True).stdout
        assert os.environ["USERNAME"].casefold() in acl.casefold()
        assert "everyone:" not in acl.casefold()
