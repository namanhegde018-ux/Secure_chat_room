"""
In-memory invitation and session management.

This module is pure logic. It does no I/O and uses no sockets or asyncio.
Each public method either completes or raises a SignalingError subclass,
which the signalling layer turns into an error reply.

Authorization model
-------------------
* A session is created only by accepting an invitation. There is no "join"
  operation that a client could abuse.
* Only members of a session may relay messages into it or end it.
* A client may belong to at most one active session at a time.
"""

from __future__ import annotations

import enum
import secrets
import time
from dataclasses import dataclass
from typing import Callable, Iterable, Optional

try:  # Package execution
    from . import configuration as config
except ImportError:  # Direct execution from this directory
    import configuration as config


# --------------------------------------------------------------------------
# Errors. Each carries a machine-readable code for the wire protocol.
# --------------------------------------------------------------------------
class SignalingError(Exception):
    code = "error"

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


class BadRequest(SignalingError):
    code = "bad_request"


class NotRegistered(SignalingError):
    code = "not_registered"


class NotFound(SignalingError):
    code = "not_found"


class Forbidden(SignalingError):
    code = "forbidden"


class Conflict(SignalingError):
    code = "conflict"


class InvalidState(SignalingError):
    code = "invalid_state"


# --------------------------------------------------------------------------
# Records
# --------------------------------------------------------------------------
class InvitationState(enum.Enum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


class SessionState(enum.Enum):
    ACTIVE = "active"
    ENDED = "ended"
    EXPIRED = "expired"


@dataclass
class Invitation:
    invitation_id: str
    inviter: str
    invitee: str
    created_at: float
    expires_at: float
    state: InvitationState = InvitationState.PENDING
    finished_at: Optional[float] = None

    @property
    def is_pending(self) -> bool:
        return self.state is InvitationState.PENDING


@dataclass
class Session:
    session_id: str
    members: frozenset
    created_at: float
    last_activity: float
    state: SessionState = SessionState.ACTIVE
    end_reason: Optional[str] = None
    finished_at: Optional[float] = None

    @property
    def is_active(self) -> bool:
        return self.state is SessionState.ACTIVE


# --------------------------------------------------------------------------
# Manager
# --------------------------------------------------------------------------
class SessionManager:
    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self._clock = clock                                    # injectable for tests
        self._sessions: dict[str, Session] = {}
        self._invitations: dict[str, Invitation] = {}
        self._pending_pairs: dict[tuple[str, str], str] = {}   # (inviter, invitee) -> invitation_id
        self._session_of: dict[str, str] = {}                  # client_id -> active session_id

    # ------------------------------------------------------------------
    # Invitations
    # ------------------------------------------------------------------
    def create_invitation(self, inviter: str, invitee: str) -> Invitation:
        now = self._clock()
        if inviter == invitee:
            raise BadRequest("you cannot invite yourself")
        if self._in_session(inviter) or self._in_session(invitee):
            raise Conflict("one of the clients is already in a session")
        # Duplicate prevention: block a second pending invite in either direction.
        if self._has_live_pending(inviter, invitee, now) or self._has_live_pending(invitee, inviter, now):
            raise Conflict("a pending invitation already exists between these clients")

        invitation = Invitation(
            invitation_id=secrets.token_urlsafe(config.INVITATION_ID_BYTES),
            inviter=inviter,
            invitee=invitee,
            created_at=now,
            expires_at=now + config.INVITATION_TTL,
        )
        self._invitations[invitation.invitation_id] = invitation
        self._pending_pairs[(inviter, invitee)] = invitation.invitation_id
        return invitation

    def get_invitation(self, invitation_id: str) -> Invitation:
        invitation = self._invitations.get(invitation_id)
        if invitation is None:
            raise NotFound("no such invitation")
        return invitation

    def accept_invitation(self, client_id: str, invitation_id: str) -> Session:
        invitation = self._take_pending(client_id, invitation_id)
        if self._in_session(invitation.inviter) or self._in_session(invitation.invitee):
            raise Conflict("one of the clients is already in a session")
        self._finish_invitation(invitation, InvitationState.ACCEPTED)
        return self.create_session({invitation.inviter, invitation.invitee})

    def reject_invitation(self, client_id: str, invitation_id: str) -> Invitation:
        invitation = self._take_pending(client_id, invitation_id)
        self._finish_invitation(invitation, InvitationState.REJECTED)
        return invitation

    def cancel_invitations_for(self, client_id: str) -> list[Invitation]:
        """Cancel every pending invitation the client sent or received (used on disconnect)."""
        cancelled = []
        for inv in list(self._invitations.values()):
            if inv.is_pending and client_id in (inv.inviter, inv.invitee):
                self._finish_invitation(inv, InvitationState.CANCELLED)
                cancelled.append(inv)
        return cancelled

    def expire_stale_invitations(self) -> list[Invitation]:
        now = self._clock()
        expired = []
        for inv in list(self._invitations.values()):
            if inv.is_pending and inv.expires_at <= now:
                self._finish_invitation(inv, InvitationState.EXPIRED)
                expired.append(inv)
        return expired

    # ------------------------------------------------------------------
    # Sessions
    # ------------------------------------------------------------------
    def create_session(self, members: Iterable[str]) -> Session:
        members = frozenset(members)
        if len(members) < 2:
            raise BadRequest("a session needs at least two members")
        if any(self._in_session(m) for m in members):
            raise Conflict("a member is already in an active session")

        now = self._clock()
        session = Session(
            session_id=secrets.token_urlsafe(config.SESSION_ID_BYTES),
            members=members,
            created_at=now,
            last_activity=now,
        )
        self._sessions[session.session_id] = session
        for member in members:
            self._session_of[member] = session.session_id
        return session

    def get_session(self, session_id: str) -> Session:
        session = self._sessions.get(session_id)
        if session is None:
            raise NotFound("no such session")
        return session

    def end_session(self, client_id: str, session_id: str, reason: str = "terminated") -> Session:
        """Explicit termination by a member."""
        session = self._require_active_member(client_id, session_id)
        self._close(session, SessionState.ENDED, reason)
        return session

    def end_session_of(self, client_id: str, reason: str) -> Optional[Session]:
        """End whatever session the client is in (used on disconnect)."""
        session_id = self._session_of.get(client_id)
        if session_id is None:
            return None
        session = self._sessions[session_id]
        self._close(session, SessionState.ENDED, reason)
        return session

    def expire_session(self, session_id: str, reason: str = "idle") -> Session:
        session = self.get_session(session_id)
        if session.is_active:
            self._close(session, SessionState.EXPIRED, reason)
        return session

    def expire_idle_sessions(self) -> list[Session]:
        now = self._clock()
        stale = [
            s.session_id
            for s in self._sessions.values()
            if s.is_active and now - s.last_activity >= config.SESSION_IDLE_TIMEOUT
        ]
        return [self.expire_session(sid) for sid in stale]

    def authorize_relay(self, client_id: str, session_id: str) -> list[str]:
        """
        Check that the sender may relay into this session. Refreshes the session's
        activity timestamp and returns the recipients (every other member).
        """
        session = self._require_active_member(client_id, session_id)
        session.last_activity = self._clock()
        return sorted(session.members - {client_id})

    def purge_finished(self) -> None:
        """Drop ended/expired/finished records after FINISHED_RETENTION to bound memory."""
        cutoff = self._clock() - config.FINISHED_RETENTION
        for sid in [
            s.session_id for s in self._sessions.values()
            if not s.is_active and s.finished_at is not None and s.finished_at <= cutoff
        ]:
            del self._sessions[sid]
        for iid in [
            i.invitation_id for i in self._invitations.values()
            if not i.is_pending and i.finished_at is not None and i.finished_at <= cutoff
        ]:
            del self._invitations[iid]

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _take_pending(self, client_id: str, invitation_id: str) -> Invitation:
        """Return the invitation only if it is pending, unexpired, and addressed to client_id."""
        invitation = self.get_invitation(invitation_id)
        if invitation.invitee != client_id:
            raise Forbidden("this invitation was not sent to you")
        if not invitation.is_pending:
            raise InvalidState(f"invitation is already {invitation.state.value}")
        if invitation.expires_at <= self._clock():
            raise InvalidState("invitation has expired")
        return invitation

    def _has_live_pending(self, inviter: str, invitee: str, now: float) -> bool:
        inv_id = self._pending_pairs.get((inviter, invitee))
        if inv_id is None:
            return False
        inv = self._invitations[inv_id]
        # An expired record that the sweeper hasn't reached yet doesn't block a new invite.
        return inv.is_pending and inv.expires_at > now

    def _finish_invitation(self, inv: Invitation, state: InvitationState) -> None:
        inv.state = state
        inv.finished_at = self._clock()
        key = (inv.inviter, inv.invitee)
        if self._pending_pairs.get(key) == inv.invitation_id:
            del self._pending_pairs[key]

    def _require_active_member(self, client_id: str, session_id: str) -> Session:
        session = self.get_session(session_id)
        if client_id not in session.members:
            raise Forbidden("you are not a member of this session")
        if not session.is_active:
            raise InvalidState(f"session is {session.state.value}")
        return session

    def _close(self, session: Session, state: SessionState, reason: str) -> None:
        session.state = state
        session.end_reason = reason
        session.finished_at = self._clock()
        for member in session.members:
            if self._session_of.get(member) == session.session_id:
                del self._session_of[member]

    def _in_session(self, client_id: str) -> bool:
        return client_id in self._session_of