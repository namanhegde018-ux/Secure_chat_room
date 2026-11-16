"""Pinned identity keys for peers: trust on first use, plus explicit verification."""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path

from crypto import CryptoError, fingerprint_of, normalize_fingerprint


class PeerKeyChanged(CryptoError):
    """A peer presented an identity key different from the one pinned for them."""

    def __init__(self, peer_id: str, pinned: bytes, presented: bytes) -> None:
        super().__init__(
            f"identity key for {peer_id!r} changed. This may be a man-in-the-middle "
            "attack. Verify the new fingerprint out of band before forgetting the old key."
        )
        self.peer_id = peer_id
        self.pinned = pinned
        self.presented = presented


class TrustStore:
    """
    Maps peer client IDs to pinned identity keys.

    * First contact: the key is pinned but NOT verified.
    * Later contacts: the key must match the pin, or PeerKeyChanged is raised.
    * verify(): the user has compared fingerprints out of band.

    Pass a path to persist pins across restarts. Without a path, pins live
    only in memory.
    """

    def __init__(self, path: str | Path | None = None) -> None:
        self._path = Path(path).expanduser() if path else None
        self._lock = threading.RLock()
        self._entries: dict[str, dict] = {}
        if self._path is not None and self._path.exists():
            try:
                self._entries = json.loads(self._path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise CryptoError(f"trust store {self._path} is unreadable") from exc

    def pinned_key(self, peer_id: str) -> bytes | None:
        with self._lock:
            entry = self._entries.get(peer_id)
            return bytes.fromhex(entry["public_key"]) if entry else None

    def check(self, peer_id: str, public_key: bytes) -> None:
        """Raise PeerKeyChanged if a different key is pinned. Never writes."""
        with self._lock:
            pinned = self.pinned_key(peer_id)
        if pinned is not None and pinned != public_key:
            raise PeerKeyChanged(peer_id, pinned, public_key)

    def pin(self, peer_id: str, public_key: bytes) -> bool:
        """Pin a key on first contact. Returns True if it was newly pinned."""
        with self._lock:
            self.check(peer_id, public_key)
            if peer_id in self._entries:
                return False
            self._entries[peer_id] = {"public_key": public_key.hex(), "verified": False}
            self._save()
            return True

    def is_verified(self, peer_id: str) -> bool:
        with self._lock:
            entry = self._entries.get(peer_id)
            return bool(entry and entry.get("verified"))

    def verify(self, peer_id: str, fingerprint: str) -> bool:
        """Mark the pinned key verified if the user-supplied fingerprint matches it."""
        with self._lock:
            pinned = self.pinned_key(peer_id)
            if pinned is None:
                return False
            if normalize_fingerprint(fingerprint) != normalize_fingerprint(fingerprint_of(pinned)):
                return False
            self._entries[peer_id]["verified"] = True
            self._save()
            return True

    def forget(self, peer_id: str) -> bool:
        """Drop a pin. Use only after confirming a legitimate key change out of band."""
        with self._lock:
            removed = self._entries.pop(peer_id, None) is not None
            if removed:
                self._save()
            return removed

    def _save(self) -> None:
        if self._path is None:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_name(self._path.name + ".tmp")
        tmp.write_text(json.dumps(self._entries, indent=2), encoding="utf-8")
        os.replace(tmp, self._path)