"""Request handling for the signalling server.

SignalingService routes client requests to the SessionManager (pure logic)
and the ClientRegistry (name -> connection mapping), then delivers the
resulting notices to the right connections.
"""

from __future__ import annotations

import logging
import re
import time

import configuration as config
from session_manager import (
    BadRequest,
    Conflict,
    InvalidState,
    NotFound,
    NotRegistered,
    SessionManager,
    SignalingError,
)

log = logging.getLogger("signaling")

_NAME_PATTERN = r"[A-Za-z0-9_.\-]+"
PRE_REGISTRATION = frozenset({"register", "ping"})


class ClientRegistry:
    """Maps client ids to connections and back. Entries exist only while connected."""

    def __init__(self):
        self._conns: dict[str, object] = {}
        self._names: dict[object, str] = {}

    def get(self, name):
        return self._conns.get(name)

    def name_of(self, conn):
        return self._names.get(conn)

    def add(self, name, conn):
        self._conns[name] = conn
        self._names[conn] = name

    def remove(self, conn):
        """Remove the registration for conn. Returns the client id, or None."""
        name = self._names.pop(conn, None)
        if name is not None:
            self._conns.pop(name, None)
        return name

    def __len__(self):
        return len(self._conns)


def _str_field(msg, key):
    value = msg.get(key)
    if not isinstance(value, str) or not value:
        raise BadRequest(f"'{key}' must be a non-empty string")
    return value


def _targets_field(msg):
    value = msg.get("to")
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(v, str) and v for v in value)
    ):
        raise BadRequest("'to' must be a non-empty list of client ids")
    if len(set(value)) != len(value):
        raise BadRequest("duplicate recipients in 'to'")
    return value


class SignalingService:
    def __init__(self, *, manager=None, registry=None):
        self.manager = manager if manager is not None else SessionManager(
            time.monotonic,
            max_group_size=config.MAX_GROUP_SIZE,
            invitation_ttl=config.INVITATION_TTL,
            session_idle_timeout=config.SESSION_IDLE_TIMEOUT,
            finished_retention=config.FINISHED_RETENTION,
        )
        self.registry = registry if registry is not None else ClientRegistry()

    # ----- entry points called by server.py -----

    def handle(self, conn, msg):
        msg_type = msg.get("type") if isinstance(msg, dict) else None
        try:
            if not isinstance(msg, dict) or not isinstance(msg_type, str):
                raise BadRequest("message must be an object with a 'type' string")

            name = self.registry.name_of(conn)
            if name is None and msg_type not in PRE_REGISTRATION:
                raise NotRegistered("register before sending this request")

            if msg_type == "register":
                self._register(conn, msg)
            elif msg_type == "ping":
                conn.send({"type": "pong"})
            elif msg_type == "invite":
                self._invite(name, msg)
            elif msg_type == "accept":
                self._deliver(
                    self.manager.accept_invitation(name, _str_field(msg, "invitation_id"))
                )
            elif msg_type == "reject":
                self._deliver(
                    self.manager.reject_invitation(name, _str_field(msg, "invitation_id"))
                )
            elif msg_type == "message":
                self._message(name, msg)
            elif msg_type == "end_session":
                self._deliver(
                    self.manager.end_session(name, _str_field(msg, "session_id"), "terminated")
                )
            else:
                raise BadRequest(f"unknown message type {msg_type!r}")

        except SignalingError as exc:
            conn.send({
                "type": "error",
                "request": msg_type,
                "code": exc.code,
                "message": str(exc),
            })
        except Exception:
            log.exception("internal error handling %r", msg_type)
            conn.send({
                "type": "error",
                "request": msg_type,
                "code": "internal",
                "message": "internal server error",
            })

    def handle_disconnect(self, conn):
        name = self.registry.remove(conn)
        if name is None:
            return
        log.info("client %r disconnected", name)
        notices = list(self.manager.cancel_invitations_for(name, reason="disconnected"))
        notices += list(self.manager.end_session_of(name, "peer_disconnected"))
        self._deliver(notices)

    def sweep(self):
        self._deliver(list(self.manager.expire_stale_invitations()))
        self._deliver(list(self.manager.expire_idle_sessions()))
        self.manager.purge_finished()

    # ----- request handlers -----

    def _register(self, conn, msg):
        if self.registry.name_of(conn) is not None:
            raise InvalidState("already registered on this connection")
        name = _str_field(msg, "client_id")
        if len(name) > config.MAX_CLIENT_ID_LENGTH or not re.fullmatch(_NAME_PATTERN, name):
            raise BadRequest("invalid client_id")
        if self.registry.get(name) is not None:
            raise Conflict(f"client id {name!r} is already in use")
        self.registry.add(name, conn)
        log.info("client %r registered", name)
        conn.send({"type": "registered", "client_id": name})

    def _invite(self, name, msg):
        targets = _targets_field(msg)
        if name in targets:
            raise BadRequest("cannot invite yourself")
        for target in targets:
            if self.registry.get(target) is None:
                raise NotFound(f"{target!r} is not online")

        batch_id, invitations = self.manager.create_invitations(name, targets)
        inviter_conn = self.registry.get(name)
        for inv in invitations:
            if inviter_conn is not None:
                inviter_conn.send({
                    "type": "invite_sent",
                    "invitation_id": inv.invitation_id,
                    "batch_id": batch_id,
                    "to": inv.invitee,
                })
            invitee_conn = self.registry.get(inv.invitee)
            if invitee_conn is not None:
                invitee_conn.send({
                    "type": "invitation",
                    "invitation_id": inv.invitation_id,
                    "batch_id": batch_id,
                    "from": name,
                    "group": inv.group,
                    "ttl": config.INVITATION_TTL,
                })

    def _message(self, name, msg):
        session_id = _str_field(msg, "session_id")
        to = _str_field(msg, "to")
        body = msg.get("body")
        if not isinstance(body, dict):
            raise BadRequest("'body' must be an object")
        recipient = self.manager.authorize_relay(name, session_id, to)
        conn = self.registry.get(recipient)
        if conn is None:
            raise NotFound(f"{recipient!r} is not online")
        conn.send({
            "type": "message",
            "session_id": session_id,
            "from": name,
            "body": body,
        })

    # ----- delivery -----

    def _deliver(self, notices):
        for notice in notices:
            conn = self.registry.get(notice.to)
            if conn is None:
                continue
            conn.send({"type": notice.type, **notice.payload})