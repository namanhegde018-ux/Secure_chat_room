"""Local view of the active session."""

import threading
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class SessionSnapshot:
    session_id: str
    members: tuple[str, ...]
    started_at: float

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "members": list(self.members),
            "started_at": self.started_at,
        }


class LocalSessionManager:
    def __init__(self, client_id: str) -> None:
        self.client_id = client_id
        self._current: SessionSnapshot | None = None
        self._lock = threading.RLock()

    @property
    def current(self) -> SessionSnapshot | None:
        with self._lock:
            return self._current

    @property
    def current_session_id(self) -> str | None:
        with self._lock:
            return self._current.session_id if self._current else None

    def is_active(self, session_id: str | None = None) -> bool:
        with self._lock:
            if self._current is None:
                return False
            return session_id is None or self._current.session_id == session_id

    def apply_server_event(self, message: dict) -> bool:
        """Update local state from a server session event. Returns True if changed."""
        event_type = message.get("type")

        if event_type == "session_started":
            session_id = message.get("session_id")
            members = message.get("members")

            if (
                not isinstance(session_id, str)
                or not session_id
                or not isinstance(members, list)
                or not all(isinstance(member, str) for member in members)
                or self.client_id not in members
            ):
                return False

            snapshot = SessionSnapshot(
                session_id=session_id,
                members=tuple(sorted(set(members))),
                started_at=time.monotonic(),
            )
            with self._lock:
                self._current = snapshot
            return True

        if event_type in {"session_ended", "session_expired"}:
            session_id = message.get("session_id")
            with self._lock:
                if self._current and self._current.session_id == session_id:
                    self._current = None
                    return True

        return False

    def clear(self) -> bool:
        with self._lock:
            had_session = self._current is not None
            self._current = None
            return had_session