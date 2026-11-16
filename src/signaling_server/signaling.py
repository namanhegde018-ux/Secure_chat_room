"""
Protocol logic: maps incoming client messages to actions and pushes events.

Every method here is synchronous. Handlers never await, and asyncio runs one
task at a time, so each handler is atomic with respect to other clients and
no locks are needed.
"""

from __future__ import annotations

import logging
import re
from typing import Any

try:  # Package execution
    from . import configuration as config
    from .connection import Connection
    from .session_manager import (
        BadRequest, Conflict, NotFound, NotRegistered, SessionManager, SignalingError,
    )
except ImportError:  # Direct execution from this directory
    import configuration as config
    from connection import Connection
    from session_manager import (
        BadRequest, Conflict, NotFound, NotRegistered, SessionManager, SignalingError,
    )

log = logging.getLogger("signaling")

_CLIENT_ID_RE = re.compile(r"[A-Za-z0-9_.\-]+")
_PRE_REGISTRATION = {"register", "ping"}   # the only messages allowed before registering


class ClientRegistry:
    """client_id -> live Connection. An entry exists only while the client is connected."""

    def __init__(self) -> None:
        self._clients: dict[str, Connection] = {}

    def get(self, client_id: str) -> Connection | None:
        return self._clients.get(client_id)

    def add(self, client_id: str, conn: Connection) -> None:
        self._clients[client_id] = conn

    def remove(self, client_id: str, conn: Connection) -> None:
        # Only remove the entry if this connection still owns the name.
        if self._clients.get(client_id) is conn:
            del self._clients[client_id]

    def __len__(self) -> int:
        return len(self._clients)


def _str_field(msg: dict[str, Any], key: str) -> str:
    value = msg.get(key)
    if not isinstance(value, str) or not value:
        raise BadRequest(f"field {key!r} must be a non-empty string")
    return value


class SignalingService:
    def __init__(self, registry: ClientRegistry, sessions: SessionManager):
        self.registry = registry
        self.sessions = sessions
        self._handlers = {
            "register": self._on_register,
            "ping": self._on_ping,
            "invite": self._on_invite,
            "accept": self._on_accept,
            "reject": self._on_reject,
            "message": self._on_message,
            "end_session": self._on_end_session,
        }

    # ------------------------------------------------------------------
    # Entry points called by server.py
    # ------------------------------------------------------------------
    def handle(self, conn: Connection, msg: dict[str, Any]) -> None:
        msg_type = msg.get("type")
        try:
            handler = self._handlers.get(msg_type) if isinstance(msg_type, str) else None
            if handler is None:
                raise BadRequest(f"unknown message type: {msg_type!r}")
            if conn.client_id is None and msg_type not in _PRE_REGISTRATION:
                raise NotRegistered("send 'register' before any other message")
            handler(conn, msg)
        except SignalingError as exc:
            # Errors go back to the sender only. The connection stays open.
            conn.send({
                "type": "error",
                "request": msg_type,
                "code": exc.code,
                "message": exc.message,
            })

    def handle_disconnect(self, conn: Connection) -> None:
        """Clean up everything that belonged to a client that has gone away."""
        client_id = conn.client_id
        if client_id is None:
            return  # never registered, nothing to clean up

        self.registry.remove(client_id, conn)

        for inv in self.sessions.cancel_invitations_for(client_id):
            other = inv.invitee if inv.inviter == client_id else inv.inviter
            self._notify(other, {
                "type": "invitation_cancelled",
                "invitation_id": inv.invitation_id,
                "reason": "peer_disconnected",
            })

        session = self.sessions.end_session_of(client_id, reason="peer_disconnected")
        if session is not None:
            for member in session.members - {client_id}:
                self._notify(member, {
                    "type": "session_ended",
                    "session_id": session.session_id,
                    "reason": "peer_disconnected",
                })

        log.info("client %r unregistered", client_id)

    def sweep(self) -> None:
        """Expire stale invitations and sessions, and tell the affected clients."""
        for inv in self.sessions.expire_stale_invitations():
            event = {"type": "invitation_expired", "invitation_id": inv.invitation_id}
            self._notify(inv.inviter, event)
            self._notify(inv.invitee, event)

        for session in self.sessions.expire_idle_sessions():
            event = {"type": "session_expired", "session_id": session.session_id, "reason": "idle"}
            for member in session.members:
                self._notify(member, event)

        self.sessions.purge_finished()

    # ------------------------------------------------------------------
    # Message handlers
    # ------------------------------------------------------------------
    def _on_register(self, conn: Connection, msg: dict[str, Any]) -> None:
        if conn.client_id is not None:
            raise Conflict("this connection is already registered")

        client_id = _str_field(msg, "client_id")
        if len(client_id) > config.MAX_CLIENT_ID_LENGTH or not _CLIENT_ID_RE.fullmatch(client_id):
            raise BadRequest(
                f"client_id must be 1-{config.MAX_CLIENT_ID_LENGTH} characters: "
                "letters, digits, '_', '.', '-'"
            )
        if self.registry.get(client_id) is not None:
            raise Conflict(f"client_id {client_id!r} is already in use")

        self.registry.add(client_id, conn)
        conn.client_id = client_id
        conn.send({"type": "registered", "client_id": client_id})
        log.info("client %r registered from %s", client_id, conn.peer)

    def _on_ping(self, conn: Connection, msg: dict[str, Any]) -> None:
        conn.send({"type": "pong"})

    def _on_invite(self, conn: Connection, msg: dict[str, Any]) -> None:
        invitee_id = _str_field(msg, "to")
        if self.registry.get(invitee_id) is None:
            raise NotFound(f"client {invitee_id!r} is not online")

        invitation = self.sessions.create_invitation(conn.client_id, invitee_id)
        self._notify(invitee_id, {
            "type": "invitation",
            "invitation_id": invitation.invitation_id,
            "from": conn.client_id,
            "ttl": config.INVITATION_TTL,
        })
        conn.send({
            "type": "invite_sent",
            "invitation_id": invitation.invitation_id,
            "to": invitee_id,
        })

    def _on_accept(self, conn: Connection, msg: dict[str, Any]) -> None:
        invitation_id = _str_field(msg, "invitation_id")
        session = self.sessions.accept_invitation(conn.client_id, invitation_id)
        event = {
            "type": "session_started",
            "session_id": session.session_id,
            "members": sorted(session.members),
        }
        for member in session.members:
            self._notify(member, event)

    def _on_reject(self, conn: Connection, msg: dict[str, Any]) -> None:
        invitation_id = _str_field(msg, "invitation_id")
        invitation = self.sessions.reject_invitation(conn.client_id, invitation_id)
        self._notify(invitation.inviter, {
            "type": "invitation_rejected",
            "invitation_id": invitation.invitation_id,
            "by": conn.client_id,
        })

    def _on_message(self, conn: Connection, msg: dict[str, Any]) -> None:
        session_id = _str_field(msg, "session_id")
        if "body" not in msg:
            raise BadRequest("field 'body' is required")

        # Raises Forbidden / InvalidState unless the sender is an active member.
        recipients = self.sessions.authorize_relay(conn.client_id, session_id)

        event = {
            "type": "message",
            "session_id": session_id,
            "from": conn.client_id,
            "body": msg["body"],
        }
        for peer in recipients:
            self._notify(peer, event)

    def _on_end_session(self, conn: Connection, msg: dict[str, Any]) -> None:
        session_id = _str_field(msg, "session_id")
        session = self.sessions.end_session(conn.client_id, session_id, reason="terminated")
        event = {
            "type": "session_ended",
            "session_id": session.session_id,
            "reason": "terminated",
            "by": conn.client_id,
        }
        for member in session.members:
            self._notify(member, event)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _notify(self, client_id: str, message: dict[str, Any]) -> None:
        """Push an event to a client if it is online. Offline clients are skipped."""
        conn = self.registry.get(client_id)
        if conn is not None:
            conn.send(message)