"""Password-encrypted Ed25519 identity storage (no database)."""

import base64
import json
import os
import subprocess
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .fingerprint import fingerprint

_MAGIC = b"SMID1\n"


def _key(password: str, salt: bytes) -> bytes:
    if not password:
        raise ValueError("A non-empty identity password is required")
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode("utf-8"))


def _restrict_windows_acl(path: Path) -> None:
    if os.name != "nt":
        return
    # Remove inherited access and grant the current account access only.
    subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r", f"{os.environ.get('USERDOMAIN', '')}\\{os.environ.get('USERNAME', '')}:(R,W)"], check=True, capture_output=True)


def save_identity(path, private_key: Ed25519PrivateKey, password: str) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    salt, nonce = os.urandom(16), os.urandom(12)
    raw = private_key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    encrypted = AESGCM(_key(password, salt)).encrypt(nonce, raw, _MAGIC)
    payload = {"salt": base64.b64encode(salt).decode(), "nonce": base64.b64encode(nonce).decode(), "private": base64.b64encode(encrypted).decode()}
    with path.open("xb") as f:
        f.write(_MAGIC + json.dumps(payload).encode("ascii"))
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    _restrict_windows_acl(path)


def load_identity(path, password: str) -> Ed25519PrivateKey:
    raw = Path(path).read_bytes()
    if not raw.startswith(_MAGIC):
        raise ValueError("Identity file has an unsupported or corrupted format")
    try:
        data = json.loads(raw[len(_MAGIC):])
        clear = AESGCM(_key(password, base64.b64decode(data["salt"], validate=True))).decrypt(
            base64.b64decode(data["nonce"], validate=True), base64.b64decode(data["private"], validate=True), _MAGIC)
        return Ed25519PrivateKey.from_private_bytes(clear)
    except Exception as exc:
        raise ValueError("Could not unlock identity; password may be wrong or file corrupted") from exc


def new_identity(path, password: str) -> Ed25519PrivateKey:
    key = Ed25519PrivateKey.generate()
    save_identity(path, key, password)
    return key


def public_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def identity_fingerprint(key: Ed25519PrivateKey) -> str:
    return fingerprint(public_bytes(key))
