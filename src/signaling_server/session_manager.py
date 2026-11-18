"""
Session and invitation rules for the signaling server. Pure logic, no I/O.

Rules
- A group forms from one invitation batch: one inviter and 1 to MAX_GROUP_SIZE-1
  invitees. Each invitee gets its own invitation_id; all share a batch_id.
- The session starts only when every invitee in the batch has accepted.
- A rejection, expiry, cancellation or disconnect cancels the whole batch.
- A client belongs to at most one session.
- An inviter has at most one pending batch. An invitee already in a session
  cannot be invited.
- When a client enters a session, every open batch it belongs to is cancelled.
  So a pending invitation never involves a client who is in a session.
- Membership is fixed. Any member leaving ends the session for everyone.
- A message is relayed only between two members of an active session.

Methods that change state return a list of Notice objects. The caller delivers
them. This module never touches sockets.
"""
from __future__ import annotations

import enum
import secrets
import time
from dataclasses import dataclass
from typing import Callable, NamedTuple, Optional

import configuration as config


class SignalingError(Exception):
    """Base class. The message is returned to the client that caused it."""

    code = "error"

    def __init__(self, message: str) -> None:
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
    batch_id: str
    inviter: str
    invitee: str
    group: tuple          # sorted member names, including the inviter
    created_at: float
    state: InvitationState = InvitationState.PENDING
    finished_at: Optional[float] = None


@dataclass
class Session:
    session_id: str
    members: tuple        # sorted member names
    state: SessionState
    created_at: float
    last_activity: float
    finished_at: Optional[float] = None
    reason: Optional[str] = None


class Notice(NamedTuple):
    """One message to deliver: recipient client id, message type, payload fields."""
    to: str
    type: str
    payload: dict


class SessionManager:
    def __init__(
        self,
        clock: Callable[[], float] = time.monotonic,
        *,
        max_group_size: int = config.MAX_GROUP_SIZE,
        invitation_ttl: float = config.INVITATION_TTL,
        session_idle_timeout: float = config.SESSION_IDLE_TIMEOUT,
        finished_retention: float = config.FINISHED_RETENTION,
    ) -> None:
        self._clock = clock
        self.max_group_size = max_group_size
        self.invitation_ttl = invitation_ttl
        self.session_idle_timeout = session_idle_timeout
        self.finished_retention = finished_retention
        self._invitations: dict[str, Invitation] = {}
        self._sessions: dict[str, Session] = {}
        self._member_of: dict[str, str] = {}        # client id -> active session id

    # ----- queries -----------------------------------------------------------

    def session_of(self, client_id: str) -> Optional[str]:
        return self._member_of.get(client_id)

    def get_session(self, session_id: str) -> Optional[Session]:
        return self._sessions.get(session_id)

    def get_invitation(self, invitation_id: str) -> Optional[Invitation]:
        return self._invitations.get(invitation_id)

    # ----- invitations -------------------------------------------------------

    def create_invitations(self, inviter: str, invitees: list) -> tuple:
        if not invitees:
            raise BadRequest("at least one invitee is required")
        if len(set(invitees)) != len(invitees):
            raise BadRequest("duplicate invitee")
        if inviter in invitees:
            raise BadRequest("you cannot invite yourself")
        if len(invitees) + 1 > self.max_group_size:
            raise BadRequest(f"a group can hold at most {self.max_group_size} members")
        if self.session_of(inviter) is not None:
            raise Conflict("you are already in a session")
        if self._has_pending_batch(inviter):
            raise Conflict("you already have a pending invitation; wait for it to finish")
        for name in invitees:
            if self.session_of(name) is not None:
                raise Conflict(f"'{name}' is already in a session")

        now = self._clock()
        group = tuple(sorted([inviter, *invitees]))
        batch_id = secrets.token_urlsafe(config.INVITATION_ID_BYTES)
        created = []
        for name in invitees:
            inv = Invitation(
                invitation_id=self._fresh_id(self._invitations, config.INVITATION_ID_BYTES),
                batch_id=batch_id,
                inviter=inviter,
                invitee=name,
                group=group,
                created_at=now,
            )
            self._invitations[inv.invitation_id] = inv
            created.append(inv)
        return batch_id, created

    def accept_invitation(self, client_id: str, invitation_id: str) -> list:
        inv = self._invitation_for(client_id, invitation_id)
        if inv.state is not InvitationState.PENDING:
            raise InvalidState("invitation is no longer pending")
        if self._is_expired(inv):
            raise InvalidState("invitation has expired")
        if self.session_of(client_id) is not None:
            raise Conflict("you are already in a session")

        inv.state = InvitationState.ACCEPTED
        inv.finished_at = self._clock()
        notices = [Notice(inv.inviter, "invitation_accepted", {
            "invitation_id": inv.invitation_id, "batch_id": inv.batch_id, "by": client_id,
        })]
        if all(i.state is InvitationState.ACCEPTED for i in self._batch(inv.batch_id)):
            _, formed = self.create_session(list(inv.group))
            notices.extend(formed)
        return notices

    def reject_invitation(self, client_id: str, invitation_id: str) -> list:
        inv = self._invitation_for(client_id, invitation_id)
        if inv.state is not InvitationState.PENDING:
            raise InvalidState("invitation is no longer pending")
        return self._close_batch(inv, InvitationState.REJECTED, "rejected", by=client_id)

    def expire_stale_invitations(self) -> list:
        notices: list = []
        for inv in list(self._invitations.values()):
            if inv.state is InvitationState.PENDING and self._is_expired(inv):
                notices += self._close_batch(inv, InvitationState.EXPIRED, "expired")
        return notices

    def cancel_invitations_for(self, client_id: str, reason: str = "disconnected") -> list:
        """Cancel every open batch that includes client_id."""
        batch_ids = {
            inv.batch_id for inv in self._invitations.values()
            if client_id in (inv.inviter, inv.invitee)
        }
        notices: list = []
        for bid in batch_ids:
            pending = [i for i in self._batch(bid) if i.state is InvitationState.PENDING]
            if pending:
                notices += self._close_batch(pending[0], InvitationState.CANCELLED, reason)
        return notices

    # ----- sessions ----------------------------------------------------------

    def create_session(self, members: list) -> tuple:
        """Create an active session. Returns (Session, notices)."""
        members = sorted(set(members))
        if not 2 <= len(members) <= self.max_group_size:
            raise BadRequest(f"a group needs 2 to {self.max_group_size} members")
        for m in members:
            if self.session_of(m) is not None:
                raise Conflict(f"'{m}' is already in a session")

        notices: list = []
        for m in members:
            notices += self.cancel_invitations_for(m, reason="participant_busy")

        now = self._clock()
        sid = self._fresh_id(self._sessions, config.SESSION_ID_BYTES)
        session = Session(
            session_id=sid,
            members=tuple(members),
            state=SessionState.ACTIVE,
            created_at=now,
            last_activity=now,
        )
        self._sessions[sid] = session
        for m in members:
            self._member_of[m] = sid
        notices += [
            Notice(m, "session_started", {"session_id": sid, "members": list(members)})
            for m in members
        ]
        return session, notices

    def end_session(self, client_id: str, session_id: str, reason: str = "terminated") -> list:
        sess = self._sessions.get(session_id)
        if sess is None:
            raise NotFound("no such session")
        if sess.state is not SessionState.ACTIVE:
            raise InvalidState("session is not active")
        if client_id not in sess.members:
            raise Forbidden("you are not a member of this session")
        return self._finish_session(sess, SessionState.ENDED, reason, by=client_id)

    def end_session_of(self, client_id: str, reason: str) -> list:
        sid = self._member_of.get(client_id)
        if sid is None:
            return []
        return self._finish_session(self._sessions[sid], SessionState.ENDED, reason, by=client_id)

    def expire_session(self, session_id: str, reason: str = "idle") -> list:
        sess = self._sessions.get(session_id)
        if sess is None or sess.state is not SessionState.ACTIVE:
            return []
        return self._finish_session(sess, SessionState.EXPIRED, reason)

    def expire_idle_sessions(self) -> list:
        now = self._clock()
        notices: list = []
        for sess in list(self._sessions.values()):
            if sess.state is SessionState.ACTIVE and now - sess.last_activity > self.session_idle_timeout:
                notices += self._finish_session(sess, SessionState.EXPIRED, "idle")
        return notices

    def authorize_relay(self, client_id: str, session_id: str, to: str) -> str:
        """Check that client_id may send to 'to' in session_id. Returns the recipient."""
        sess = self._sessions.get(session_id)
        if sess is None:
            raise NotFound("no such session")
        if sess.state is not SessionState.ACTIVE:
            raise InvalidState("session is not active")
        if client_id not in sess.members:
            raise Forbidden("you are not a member of this session")
        if to == client_id or to not in sess.members:
            raise Forbidden("recipient is not another member of this session")
        sess.last_activity = self._clock()
        return to

    def purge_finished(self) -> int:
        now = self._clock()
        removed = 0
        for sid, sess in list(self._sessions.items()):
            if (sess.state is not SessionState.ACTIVE and sess.finished_at is not None
                    and now - sess.finished_at > self.finished_retention):
                del self._sessions[sid]
                removed += 1
        for iid, inv in list(self._invitations.items()):
            if (inv.state is not InvitationState.PENDING and inv.finished_at is not None
                    and now - inv.finished_at > self.finished_retention):
                del self._invitations[iid]
                removed += 1
        return removed

    # ----- internals ---------------------------------------------------------

    def _close_batch(self, anchor: Invitation, state: InvitationState, reason: str,
                     *, by: Optional[str] = None) -> list:
        """Move one invitation to a terminal state and close the rest of its batch."""
        now = self._clock()
        notices: list = []
        anchor.state = state
        anchor.finished_at = now
        ref = {"invitation_id": anchor.invitation_id, "batch_id": anchor.batch_id}

        if state is InvitationState.REJECTED:
            notices.append(Notice(anchor.inviter, "invitation_rejected", {**ref, "by": by}))
        elif state is InvitationState.EXPIRED:
            notices.append(Notice(anchor.inviter, "invitation_expired", ref))
            notices.append(Notice(anchor.invitee, "invitation_expired", ref))
        else:
            notices += self._cancel_notices(anchor, reason)

        for sib in self._batch(anchor.batch_id):
            if sib is anchor or sib.state not in (InvitationState.PENDING, InvitationState.ACCEPTED):
                continue
            sib.state = InvitationState.CANCELLED
            sib.finished_at = now
            notices += self._cancel_notices(sib, reason)
        return notices

    @staticmethod
    def _cancel_notices(inv: Invitation, reason: str) -> list:
        payload = {"invitation_id": inv.invitation_id, "batch_id": inv.batch_id, "reason": reason}
        return [
            Notice(inv.inviter, "invitation_cancelled", payload),
            Notice(inv.invitee, "invitation_cancelled", payload),
        ]

    def _finish_session(self, sess: Session, state: SessionState, reason: str,
                        *, by: Optional[str] = None) -> list:
        sess.state = state
        sess.reason = reason
        sess.finished_at = self._clock()
        for m in sess.members:
            if self._member_of.get(m) == sess.session_id:
                del self._member_of[m]
        notices: list = []
        for m in sess.members:
            if state is SessionState.EXPIRED:
                notices.append(Notice(m, "session_expired",
                                      {"session_id": sess.session_id, "reason": reason}))
            else:
                notices.append(Notice(m, "session_ended",
                                      {"session_id": sess.session_id, "reason": reason, "by": by}))
        return notices

    def _invitation_for(self, client_id: str, invitation_id: str) -> Invitation:
        inv = self._invitations.get(invitation_id)
        if inv is None:
            raise NotFound("no such invitation")
        if inv.invitee != client_id:
            raise Forbidden("this invitation is addressed to someone else")
        return inv

    def _batch(self, batch_id: str) -> list:
        return [i for i in self._invitations.values() if i.batch_id == batch_id]

    def _has_pending_batch(self, inviter: str) -> bool:
        return any(i.inviter == inviter and i.state is InvitationState.PENDING
                   for i in self._invitations.values())

    def _is_expired(self, inv: Invitation) -> bool:
        return self._clock() - inv.created_at > self.invitation_ttl

    @staticmethod
    def _fresh_id(taken: dict, nbytes: int) -> str:
        while True:
            candidate = secrets.token_urlsafe(nbytes)
            if candidate not in taken:
                return candidate