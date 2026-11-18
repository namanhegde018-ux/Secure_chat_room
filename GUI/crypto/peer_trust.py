"""Small JSON trust-pin file; stores only peer labels and verified fingerprints, never messages."""

import json
import os
import subprocess
from pathlib import Path


class PeerTrustStore:
    def __init__(self, path):
        self.path = Path(path)

    def _read(self):
        if not self.path.exists():
            return {}
        try:
            data = json.loads(self.path.read_text("utf-8"))
            if not isinstance(data, dict) or any(not isinstance(v, str) for v in data.values()):
                raise ValueError("invalid trust file")
            return data
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            raise ValueError("Peer trust file is invalid; refusing automatic trust") from exc

    def check(self, peer_id: str, fingerprint: str) -> str:
        known = self._read().get(peer_id)
        if known is None:
            return "new"
        return "match" if known.casefold() == fingerprint.casefold() else "changed"

    def trust(self, peer_id: str, fingerprint: str) -> None:
        if not peer_id or not fingerprint:
            raise ValueError("peer id and fingerprint are required")
        records = self._read()
        existing = records.get(peer_id)
        if existing is not None and existing.casefold() != fingerprint.casefold():
            raise ValueError("peer fingerprint changed; explicit reset/reverification is required")
        records[peer_id] = fingerprint
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.path.with_name(self.path.name + ".tmp")
        with temp.open("w", encoding="utf-8") as f:
            json.dump(records, f, indent=2, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass
        if os.name == "nt":
            account = f"{os.environ.get('USERDOMAIN', '')}\\{os.environ.get('USERNAME', '')}"
            subprocess.run(["icacls", str(self.path), "/inheritance:r", "/grant:r", f"{account}:(R,W)"], check=True, capture_output=True)
