"""
Temporary storage for received files and message logs (Phase 7).

Layout (one root per client id, one directory per session):

    <root>/<client_id>/<session_id>/
        .touched                 mtime = last activity in this session
        received/                partial and completed incoming files
        messages/messages.tmp    JSON lines

Limits:
- Removal is application-level. Deleting a file does not guarantee forensic
  erasure (SSD wear levelling, filesystem journals, snapshots, backups, swap).
  Do not describe this module as secure deletion.
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import tempfile
import threading
import time
from pathlib import Path

log = logging.getLogger(__name__)

DEFAULT_MAX_AGE = 24 * 60 * 60          # seconds of inactivity before orphaned data is removed
RECEIVED_DIR = "received"
MESSAGES_DIR = "messages"
MESSAGES_FILE = "messages.tmp"
_TOUCH_NAME = ".touched"
_SESSION_ID_RE = re.compile(r"[A-Za-z0-9_\-]{1,128}")
_UNSAFE_COMPONENT_RE = re.compile(r"[^A-Za-z0-9_.\-]")


class TempStorageError(Exception):
    """Temporary storage is unavailable or was misused."""


def default_temp_root() -> Path:
    """OS temporary directory, under an application-specific subdirectory."""
    return Path(tempfile.gettempdir()) / "signaling-client"


def _restrict(path: Path) -> None:
    if os.name == "posix":
        os.chmod(path, 0o700)


def _remove_path(path: Path) -> bool:
    try:
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink()
        return True
    except FileNotFoundError:
        return False
    except OSError:
        log.exception("could not remove temporary path %s", path)
        return False


def _last_activity(session_dir: Path) -> float:
    marker = session_dir / _TOUCH_NAME
    try:
        return marker.stat().st_mtime
    except FileNotFoundError:
        return session_dir.stat().st_mtime


class TempManager:
    """Owns the per-session temporary directories of one client."""

    def __init__(
        self,
        client_id: str,
        root: str | os.PathLike | None = None,
        *,
        max_age: float = DEFAULT_MAX_AGE,
        clock=time.time,
    ) -> None:
        if not client_id:
            raise ValueError("client_id is required")
        base = Path(root) if root is not None else default_temp_root()
        # Strip leading dots so an id such as ".." cannot escape the root.
        safe = _UNSAFE_COMPONENT_RE.sub("_", client_id).lstrip(".") or "client"
        self.root = base / safe
        self.max_age = max_age
        self._clock = clock
        self._lock = threading.RLock()
        self._active: set[str] = set()
        self.root.mkdir(parents=True, exist_ok=True)
        _restrict(self.root)

    # ----- paths -------------------------------------------------------------

    def _session_dir(self, session_id: str) -> Path:
        if not isinstance(session_id, str) or not _SESSION_ID_RE.fullmatch(session_id):
            raise TempStorageError("invalid session id")
        return self.root / session_id

    def is_open(self, session_id: str) -> bool:
        with self._lock:
            return session_id in self._active

    def open_session(self, session_id: str) -> Path:
        """Create the directory tree for a session and mark it active."""
        with self._lock:
            base = self._session_dir(session_id)
            for directory in (base, base / RECEIVED_DIR, base / MESSAGES_DIR):
                directory.mkdir(parents=True, exist_ok=True)
                _restrict(directory)
            self._active.add(session_id)
            self.touch(session_id)
            return base

    def received_dir(self, session_id: str) -> Path:
        with self._lock:
            if session_id not in self._active:
                raise TempStorageError("session storage is not open")
            return self._session_dir(session_id) / RECEIVED_DIR

    # ----- data --------------------------------------------------------------

    def touch(self, session_id: str) -> None:
        """Record activity so that expiry is measured from the last use."""
        try:
            base = self._session_dir(session_id)
            if not base.is_dir():
                return
            marker = base / _TOUCH_NAME
            fd = os.open(marker, os.O_CREAT | os.O_WRONLY, 0o600)
            os.close(fd)
            os.utime(marker, None)
        except (OSError, TempStorageError):
            log.debug("could not touch session %s", session_id, exc_info=True)

    def append_message(self, session_id: str, record: dict) -> None:
        line = json.dumps(record, separators=(",", ":"), ensure_ascii=False) + "\n"
        with self._lock:
            if session_id not in self._active:
                raise TempStorageError("session storage is not open")
            path = self._session_dir(session_id) / MESSAGES_DIR / MESSAGES_FILE
            fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as fh:
                fh.write(line)
        self.touch(session_id)

    # ----- cleanup -----------------------------------------------------------

    def cleanup_session(self, session_id: str) -> bool:
        """Scenario A/B: delete one session's data. Idempotent.

        Callers must close file handles first (FileTransferManager.close_session does).
        """
        with self._lock:
            self._active.discard(session_id)
            try:
                base = self._session_dir(session_id)
            except TempStorageError:
                return False
            return _remove_path(base)

    def cleanup_expired(self) -> list[str]:
        """Remove inactive session directories older than max_age. Returns removed ids."""
        now = self._clock()
        removed: list[str] = []
        with self._lock:
            for child in self._children():
                if child.name in self._active:
                    continue
                try:
                    if now - _last_activity(child) < self.max_age:
                        continue
                except OSError:
                    continue
                if _remove_path(child):
                    removed.append(child.name)
        return removed

    def cleanup_all(self) -> int:
        """Remove every session directory under this client's root."""
        with self._lock:
            self._active.clear()
            return self._clear_root()

    def cleanup_stale_on_startup(self) -> int:
        """Scenario C: remove leftovers from a previous run (crash or kill).

        Call once, before any session is opened. The root is per client id, and the
        server enforces unique client ids, so a live second instance with the same
        id cannot coexist with this one.
        """
        with self._lock:
            if self._active:
                raise TempStorageError("sessions are already open; cleanup must run first")
            return self._clear_root()

    def _children(self) -> list[Path]:
        if not self.root.is_dir():
            return []
        return list(self.root.iterdir())

    def _clear_root(self) -> int:
        self.root.mkdir(parents=True, exist_ok=True)
        return sum(1 for child in self._children() if _remove_path(child))