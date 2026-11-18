"""
client_core/core.py

Public, UI-independent API for the messaging client.

- Commands return concurrent.futures.Future and run on a private asyncio loop
  in a daemon thread. Frontends never touch the loop directly.
- Events are emitted on the loop thread through EventEmitter.
- Outgoing frames go through one asyncio.Queue drained by a single pump task,
  so frames leave in the order they were queued.

Groups: a session holds up to MAX_GROUP_SIZE members. Each pair of members runs
its own handshake and secure channel, bound to the session id. A message is
sealed separately for each other member and relayed by the server to that
member only. Any failure in any pair fails the whole session.
"""
from __future__ import annotations

import asyncio
import base64
import concurrent.futures
import json
import logging
import threading
from typing import Any, Callable, Optional, Sequence, Union

from crypto import CryptoError, Identity, fingerprint_of, safety_number
from events import EventEmitter
from file_transfer import DEFAULT_CHUNK_SIZE, DEFAULT_MAX_FILE_SIZE, FileTransferManager
from handshake import PeerSession
from network import NetworkError, NetworkManager, NotConnectedError
from session import LocalSessionManager
from temp_manager import TempManager
from trust import PeerKeyChanged, TrustStore

log = logging.getLogger(__name__)

__all__ = ["ClientCore", "SecurityError", "MAX_GROUP_SIZE"]

MAX_GROUP_SIZE = 20             # must match the server's MAX_GROUP_SIZE
FILE_SESSION_MAX_MEMBERS = 2    # file transfer is only available in two-person sessions
HANDSHAKE_KINDS = frozenset({"hs1", "hs2", "hs3"})
ROUTED_PREFIXES = ("file_", "export_")
MAINTENANCE_INTERVAL = 5.0      # seconds between transfer sweeps and temp cleanup
CALL_TIMEOUT = 10.0             # seconds a blocking query may wait for the loop


class SecurityError(Exception):
    """A requested action violates a security precondition."""


def _check_app_body(body: Any) -> None:
    """Reject application bodies that would be read as protocol messages."""
    if not isinstance(body, dict):
        raise ValueError("message body must be a dict")
    kind = body.get("kind")
    if isinstance(kind, str) and (
        kind.startswith(ROUTED_PREFIXES) or kind in HANDSHAKE_KINDS or kind == "secure"
    ):
        raise ValueError(f"message kind '{kind}' is reserved")


def _as_fingerprint(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        return fingerprint_of(bytes(value))
    return str(value)


class ClientCore:
    """Client API for one user. Create one instance per client identity."""

    _PASSTHROUGH = {
        "pong": "pong",
        "invitation": "invitation",
        "invite_sent": "invite_sent",
        "invitation_accepted": "invitation_accepted",
        "invitation_rejected": "invitation_rejected",
        "invitation_cancelled": "invitation_cancelled",
        "invitation_expired": "invitation_expired",
        "error": "error",
    }

    def __init__(
        self,
        host: str,
        port: int,
        client_id: str,
        *,
        dispatch_to_ui: Optional[Callable[[Callable[[], None]], None]] = None,
        download_dir: str = "downloads",
        identity_path: Optional[str] = None,
        trust_path: Optional[str] = None,
        temp_root: Optional[str] = None,
        require_verified_peers: bool = True,
        handshake_timeout: float = 15.0,
        max_message_size: int = 1024 * 1024,
        connect_timeout: float = 10.0,
        registration_timeout: float = 10.0,
        heartbeat_interval: float = 20.0,
        heartbeat_timeout: float = 50.0,
        file_chunk_size: int = DEFAULT_CHUNK_SIZE,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    ) -> None:
        if not isinstance(client_id, str) or not client_id:
            raise ValueError("client_id is required")

        self.host = host
        self.port = port
        self.client_id = client_id
        self.require_verified_peers = require_verified_peers
        self.handshake_timeout = handshake_timeout
        self._net_options = {
            "max_message_size": max_message_size,
            "connect_timeout": connect_timeout,
            "registration_timeout": registration_timeout,
            "heartbeat_interval": heartbeat_interval,
            "heartbeat_timeout": heartbeat_timeout,
        }

        self._identity = (
            Identity.load_or_create(identity_path) if identity_path else Identity.generate()
        )
        self._trust = TrustStore(trust_path)
        self._events = EventEmitter(dispatch_to_ui=dispatch_to_ui)
        self._session = LocalSessionManager(client_id)

        self._temp = TempManager(client_id, root=temp_root)
        self._temp.cleanup_stale_on_startup()

        self._file_transfers = FileTransferManager(
            send_body=self._send_secure,
            emit=self._events.emit,
            temp=self._temp,
            download_dir=download_dir,
            chunk_size=file_chunk_size,
            max_file_size=max_file_size,
            send_backlog=self._outbound_backlog,
        )

        self._network: Optional[NetworkManager] = None
        self._outbox: Optional[asyncio.Queue] = None
        self._pump_task: Optional[asyncio.Task] = None
        self._online = False
        self._closing = False
        # session id -> sorted member names (including this client)
        self._session_members: dict[str, tuple] = {}
        # (session id, peer id) -> pairwise secure channel
        self._peers: dict[tuple, PeerSession] = {}
        # (session id, peer id) -> handshake timeout
        self._timers: dict[tuple, asyncio.TimerHandle] = {}

        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._run_loop, name=f"client-core-{client_id}", daemon=True
        )
        self._thread.start()

    # ================================================================ loop ==

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.create_task(self._maintenance_loop())
        try:
            self._loop.run_forever()
        finally:
            pending = asyncio.all_tasks(self._loop)
            for task in pending:
                task.cancel()
            if pending:
                self._loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            self._loop.close()

    async def _maintenance_loop(self) -> None:
        while True:
            await asyncio.sleep(MAINTENANCE_INTERVAL)
            try:
                self._file_transfers.sweep()
                self._temp.cleanup_expired()
            except Exception:
                log.exception("maintenance step failed")

    def _submit_coro(self, coro) -> concurrent.futures.Future:
        if self._closing or not self._thread.is_alive():
            coro.close()
            raise RuntimeError("client core has been shut down")
        return asyncio.run_coroutine_threadsafe(coro, self._loop)

    def _submit(self, fn: Callable[..., Any], *args: Any) -> concurrent.futures.Future:
        async def runner() -> Any:
            return fn(*args)
        return self._submit_coro(runner())

    def _call_sync(self, fn: Callable[..., Any], *args: Any) -> Any:
        if threading.current_thread() is self._thread:
            return fn(*args)
        return self._submit(fn, *args).result(timeout=CALL_TIMEOUT)

    # ============================================================ commands ==

    def connect(self) -> concurrent.futures.Future:
        return self._submit_coro(self._connect())

    def disconnect(self) -> concurrent.futures.Future:
        return self._submit_coro(self._disconnect("client disconnected"))

    def shutdown(self) -> concurrent.futures.Future:
        if self._closing:
            done: concurrent.futures.Future = concurrent.futures.Future()
            done.set_result(None)
            return done
        self._closing = True
        return asyncio.run_coroutine_threadsafe(self._shutdown(), self._loop)

    def invite(self, to: Union[str, Sequence[str]]) -> concurrent.futures.Future:
        """Invite one or more people to a new group. Every invitee must accept."""
        targets = [to] if isinstance(to, str) else list(to)
        return self._submit(self._invite, targets)

    def accept_invitation(self, invitation_id: str) -> concurrent.futures.Future:
        return self._submit(self._control, {"type": "accept", "invitation_id": invitation_id})

    def reject_invitation(self, invitation_id: str) -> concurrent.futures.Future:
        return self._submit(self._control, {"type": "reject", "invitation_id": invitation_id})

    def send_message(self, body: dict, session_id: Optional[str] = None) -> concurrent.futures.Future:
        return self._submit(self._send_message, body, session_id)

    def send_file(self, path: str, session_id: Optional[str] = None) -> concurrent.futures.Future:
        return self._submit_coro(self._send_file(path, session_id))

    def end_session(self, session_id: Optional[str] = None) -> concurrent.futures.Future:
        return self._submit(self._end_session, session_id)

    def request_export(self, transfer_id: str) -> concurrent.futures.Future:
        return self._submit(self._file_transfers.request_export, transfer_id)

    def respond_export(self, transfer_id: str, approved: bool) -> concurrent.futures.Future:
        return self._submit(self._file_transfers.respond_export, transfer_id, approved)

    def export_file(self, transfer_id: str, dest_dir: Optional[str] = None) -> concurrent.futures.Future:
        return self._submit_coro(self._file_transfers.export_file(transfer_id, dest_dir))

    # ============================================================= queries ==

    def on(self, event: str, callback: Callable[[dict], None]) -> None:
        self._events.on(event, callback)

    def off(self, event: str, callback: Callable[[dict], None]) -> None:
        self._events.off(event, callback)

    def drain_events(self, limit: Optional[int] = None):
        return self._events.drain(limit)

    def join(self, timeout: Optional[float] = None) -> bool:
        self._thread.join(timeout)
        return not self._thread.is_alive()

    def verify_peer(self, peer_id: str, fingerprint: str) -> bool:
        return self._call_sync(self._verify_peer, peer_id, fingerprint)

    def forget_peer_key(self, peer_id: str) -> bool:
        return self._call_sync(self._forget_peer_key, peer_id)

    def peer_status(self, session_id: Optional[str] = None) -> Optional[dict]:
        return self._call_sync(self._peer_status, session_id)

    def received_files(self, session_id: Optional[str] = None) -> list[dict]:
        return self._call_sync(self._file_transfers.received_files, session_id)

    def sent_files(self, session_id: Optional[str] = None) -> list[dict]:
        return self._call_sync(self._file_transfers.sent_files, session_id)

    @property
    def is_connected(self) -> bool:
        return self._network is not None and self._network.connected

    @property
    def current_session(self) -> Optional[dict]:
        snap = self._session.current
        return snap.to_dict() if snap is not None else None

    @property
    def fingerprint(self) -> str:
        return self._identity.fingerprint

    # ========================================================= connection ==

    async def _connect(self) -> None:
        if self.is_connected:
            return
        network = NetworkManager(
            self.host,
            self.port,
            self.client_id,
            on_message=self._on_server_message,
            on_state=self._on_network_state,
            **self._net_options,
        )
        try:
            await network.connect()
        except Exception as exc:
            self._events.emit("connection_error", {"reason": str(exc)})
            raise
        self._network = network
        self._online = True
        self._start_outbox(network)
        self._events.emit("connected", {"client_id": self.client_id, "host": self.host, "port": self.port})
        self._events.emit("registered", {"client_id": self.client_id})

    async def _disconnect(self, reason: str) -> None:
        network = self._network
        if network is not None and network.connected:
            try:
                await network.close(reason)
            except Exception:
                log.exception("error while closing the connection")
        self._teardown(reason)

    async def _shutdown(self) -> None:
        await self._disconnect("client shut down")
        self._loop.call_soon(self._loop.stop)

    def _on_network_state(self, state: str, reason: str = "") -> None:
        if state == "disconnected":
            self._teardown(reason or "connection lost")

    def _teardown(self, reason: str) -> None:
        """Drop every local session and stop sending. Idempotent."""
        if self._pump_task is not None:
            self._pump_task.cancel()
            self._pump_task = None
        self._outbox = None
        for sid in list(self._session_members):
            self._drop_session(sid, reason)
        self._emit_session_state(self._session.clear())
        if self._online:
            self._online = False
            self._events.emit("disconnected", {"reason": reason})

    def _net(self) -> NetworkManager:
        if self._network is None or not self._network.connected:
            raise NotConnectedError("not connected to the server")
        return self._network

    # ========================================================= outbox ==

    def _start_outbox(self, network: NetworkManager) -> None:
        self._outbox = asyncio.Queue()
        self._pump_task = self._loop.create_task(self._pump_outbox(network, self._outbox))

    async def _pump_outbox(self, network: NetworkManager, outbox: asyncio.Queue) -> None:
        while True:
            message = await outbox.get()
            try:
                await network.send(message)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning("send failed: %s", exc)
                self._loop.create_task(self._disconnect(f"send failed: {exc}"))
                return

    def _enqueue(self, message: dict) -> None:
        """Queue one frame for sending. Loop thread only. Never blocks."""
        if self._outbox is None or not self.is_connected:
            raise NotConnectedError("not connected to the server")
        self._outbox.put_nowait(message)

    def _outbound_backlog(self) -> int:
        return self._outbox.qsize() if self._outbox is not None else 0

    def _control(self, message: dict) -> None:
        self._enqueue(message)

    # ===================================================== invitations ==

    def _invite(self, targets: list) -> None:
        if not targets or not all(isinstance(t, str) and t for t in targets):
            raise ValueError("invite needs at least one recipient name")
        if len(set(targets)) != len(targets):
            raise ValueError("duplicate recipient")
        if self.client_id in targets:
            raise ValueError("you cannot invite yourself")
        if len(targets) + 1 > MAX_GROUP_SIZE:
            raise ValueError(f"a group holds at most {MAX_GROUP_SIZE} members")
        self._control({"type": "invite", "to": list(targets)})

    # ============================================================ sessions ==

    def _others(self, sid: str) -> list:
        return [m for m in self._session_members.get(sid, ()) if m != self.client_id]

    def _pair_established(self, sid: str, peer: str) -> bool:
        ps = self._peers.get((sid, peer))
        return ps is not None and ps.established

    def _active_session_id(self, session_id: Optional[str] = None) -> str:
        sid = session_id if session_id is not None else self._session.current_session_id
        if not isinstance(sid, str) or not self._session.is_active(sid):
            raise SecurityError("no active session")
        return sid

    def _usable_session(self, session_id: Optional[str] = None) -> tuple:
        """Return (session id, other members). Every pair must be established and verified."""
        sid = self._active_session_id(session_id)
        peers = self._others(sid)
        for peer in peers:
            if not self._pair_established(sid, peer):
                raise SecurityError(f"secure channel to '{peer}' is not established yet")
            if self.require_verified_peers and not self._trust.is_verified(peer):
                raise SecurityError(f"peer '{peer}' has not been verified; compare fingerprints first")
        return sid, peers

    def _end_session(self, session_id: Optional[str]) -> None:
        sid = self._active_session_id(session_id)
        self._control({"type": "end_session", "session_id": sid})

    def _on_session_started(self, msg: dict) -> None:
        sid = msg.get("session_id")
        members = msg.get("members")
        valid = (
            isinstance(sid, str)
            and isinstance(members, list)
            and all(isinstance(m, str) and m for m in members)
            and self.client_id in members
            and 2 <= len(members) <= MAX_GROUP_SIZE
        )
        if not valid:
            self._events.emit("error", {"request": "session_started", "message": "malformed session_started"})
            return
        if sid in self._session_members:
            log.warning("duplicate session_started for %s", sid)
            return

        others = sorted(m for m in members if m != self.client_id)
        try:
            self._temp.open_session(sid)
        except Exception as exc:
            self._events.emit("error", {"request": "session_started", "message": f"local storage: {exc}"})
            return

        self._emit_session_state(self._session.apply_server_event(msg))
        self._session_members[sid] = tuple(sorted(members))
        self._events.emit("session_started", {"session_id": sid, "members": members, "peers": others})

        for peer in others:
            self._peers[(sid, peer)] = PeerSession(sid, self.client_id, peer, self._identity, self._trust)
            self._timers[(sid, peer)] = self._loop.call_later(
                self.handshake_timeout, self._on_handshake_timeout, sid, peer
            )

        # For each pair, the smaller client id initiates the handshake.
        for peer in others:
            if self.client_id < peer:
                try:
                    self._send_handshake(sid, peer, self._peers[(sid, peer)].start())
                except Exception as exc:
                    log.exception("could not start handshake")
                    self._handshake_failed(sid, peer, f"could not start handshake: {exc}")
                    return

    def _on_session_closed(self, msg: dict, event: str) -> None:
        sid = msg.get("session_id")
        if not isinstance(sid, str):
            self._events.emit("error", {"request": event, "message": "malformed session event"})
            return
        self._drop_session(sid, str(msg.get("reason", event)))
        self._emit_session_state(self._session.apply_server_event(msg))
        self._events.emit(event, self._payload(msg))

    def _drop_session(self, sid: str, reason: str) -> None:
        """Remove all local state for a session. Idempotent."""
        for key in [k for k in self._timers if k[0] == sid]:
            self._cancel_timer(key)
        for key in [k for k in self._peers if k[0] == sid]:
            del self._peers[key]
        self._session_members.pop(sid, None)
        self._file_transfers.close_session(sid, reason)

    def _fail_session(self, sid: str, reason: str) -> None:
        """Local failure in any pair: drop the group and ask the server to end it for everyone."""
        self._drop_session(sid, reason)
        try:
            self._enqueue({"type": "end_session", "session_id": sid})
        except NetworkError:
            log.debug("could not send end_session for %s", sid)

    def _emit_session_state(self, changed: bool) -> None:
        if changed:
            snap = self._session.current
            self._events.emit("session_state_changed", {"session": snap.to_dict() if snap is not None else None})

    # ============================================================ handshake ==

    def _send_handshake(self, sid: str, peer: str, body: Optional[dict]) -> None:
        if body is not None:
            self._enqueue({"type": "message", "session_id": sid, "to": peer, "body": body})

    def _handle_handshake(self, sid: str, peer: str, ps: PeerSession, body: dict) -> None:
        was_established = ps.established
        try:
            reply = ps.handle(body)
            self._send_handshake(sid, peer, reply)
        except PeerKeyChanged as exc:
            return self._on_key_changed(sid, exc)
        except CryptoError as exc:
            return self._handshake_failed(sid, peer, str(exc))
        except Exception:
            log.exception("unexpected handshake error")
            return self._handshake_failed(sid, peer, "internal error")
        if ps.established and not was_established:
            self._on_established(sid, peer, ps)

    def _on_established(self, sid: str, peer: str, ps: PeerSession) -> None:
        self._cancel_timer((sid, peer))
        self._events.emit("secure_session_established", {
            "session_id": sid,
            "peer": peer,
            "local_fingerprint": self._identity.fingerprint,
            "peer_fingerprint": fingerprint_of(ps.peer_identity_key),
            "safety_number": safety_number(self._identity.public_key, ps.peer_identity_key),
            "verified": self._trust.is_verified(peer),
        })
        if all(self._pair_established(sid, p) for p in self._others(sid)):
            self._events.emit("session_ready", {
                "session_id": sid,
                "members": list(self._session_members.get(sid, ())),
            })

    def _on_key_changed(self, sid: str, exc: PeerKeyChanged) -> None:
        self._events.emit("peer_key_changed", {
            "session_id": sid,
            "peer": exc.peer_id,
            "message": "peer's identity key differs from the pinned key; verify out of band before trusting it",
            "pinned_fingerprint": _as_fingerprint(exc.pinned),
            "presented_fingerprint": _as_fingerprint(exc.presented),
        })
        self._fail_session(sid, "peer key changed")

    def _handshake_failed(self, sid: str, peer: str, reason: str) -> None:
        self._events.emit("handshake_failed", {"session_id": sid, "peer": peer, "reason": reason})
        self._fail_session(sid, "handshake failed")

    def _on_handshake_timeout(self, sid: str, peer: str) -> None:
        self._timers.pop((sid, peer), None)
        ps = self._peers.get((sid, peer))
        if ps is None or ps.established:
            return
        self._handshake_failed(sid, peer, "handshake timed out")

    def _cancel_timer(self, key: tuple) -> None:
        timer = self._timers.pop(key, None)
        if timer is not None:
            timer.cancel()

    # ================================================ encrypted messaging ==

    def _send_secure(self, session_id: str, body: dict) -> None:
        """Seal one body for every other member and queue it. Raises on failure."""
        self._net()                                   # check before any sequence number is used
        peers = self._others(session_id)
        if not peers:
            raise SecurityError("no active session")
        for peer in peers:
            if not self._pair_established(session_id, peer):
                raise SecurityError(f"secure channel to '{peer}' is not established")
        for peer in peers:
            envelope = self._peers[(session_id, peer)].channel.seal(body)
            self._enqueue({"type": "message", "session_id": session_id, "to": peer, "body": envelope})

    def _send_message(self, body: dict, session_id: Optional[str]) -> None:
        _check_app_body(body)
        sid, _peers = self._usable_session(session_id)
        self._send_secure(sid, body)

    async def _send_file(self, path: str, session_id: Optional[str]) -> str:
        self._net()
        sid, peers = self._usable_session(session_id)
        if len(peers) + 1 > FILE_SESSION_MAX_MEMBERS:
            raise SecurityError("File Transfer is Not available in Group chat")
        return await self._file_transfers.send_file(path, sid, peers[0])

    @staticmethod
    def _open_secure(ps: PeerSession, body: dict) -> dict:
        return ps.channel.unseal(body)            # raises CryptoError on bad input

    def _reject(self, sid: Optional[str], reason: str, sender: Optional[str] = None) -> None:
        self._events.emit("message_rejected", {"session_id": sid, "from": sender, "reason": reason})

    def _on_relay(self, msg: dict) -> None:
        sid = msg.get("session_id")
        sender = msg.get("from")
        body = msg.get("body")
        if not isinstance(sid, str) or sid not in self._session_members:
            return self._reject(sid, "no active session", sender)
        if not isinstance(sender, str) or sender not in self._others(sid):
            return self._reject(sid, "message from non-member", sender)
        ps = self._peers.get((sid, sender))
        if ps is None:
            return self._reject(sid, "no secure channel to sender", sender)
        if not isinstance(body, dict):
            return self._reject(sid, "malformed message", sender)

        kind = body.get("kind")
        if isinstance(kind, str) and kind in HANDSHAKE_KINDS:
            return self._handle_handshake(sid, sender, ps, body)
        if kind != "secure":
            return self._reject(sid, "unencrypted message refused", sender)
        if not ps.established:
            return self._reject(sid, "secure channel is not established", sender)
        if self.require_verified_peers and not self._trust.is_verified(sender):
            return self._reject(sid, "peer is not verified", sender)
        try:
            inner = self._open_secure(ps, body)
        except (CryptoError, ValueError):
            return self._reject(sid, "authentication failed", sender)
        self._route_inner(sid, sender, inner)

    def _route_inner(self, sid: str, sender: str, inner: dict) -> None:
        kind = inner.get("kind")
        if isinstance(kind, str) and kind.startswith(ROUTED_PREFIXES):
            if len(self._session_members.get(sid, ())) > FILE_SESSION_MAX_MEMBERS:
                return self._reject(sid, "file transfer is only available in two-person sessions", sender)
            if not self._file_transfers.handle_relay(sid, sender, inner):
                self._reject(sid, "unknown file message", sender)
            return
        if isinstance(kind, str) and (kind in HANDSHAKE_KINDS or kind == "secure"):
            return self._reject(sid, "nested protocol message refused", sender)
        self._events.emit("message", {"session_id": sid, "from": sender, "body": inner})

    # ================================================================ peers ==

    def _verify_peer(self, peer_id: str, fingerprint: str) -> bool:
        ok = bool(self._trust.verify(peer_id, fingerprint))
        if ok:
            self._events.emit("peer_verified", {"peer": peer_id})
        return ok

    def _forget_peer_key(self, peer_id: str) -> bool:
        removed = bool(self._trust.forget(peer_id))
        if removed:
            self._events.emit("peer_key_forgotten", {"peer": peer_id})
        return removed

    def _peer_status(self, session_id: Optional[str]) -> Optional[dict]:
        try:
            sid = self._active_session_id(session_id)
        except SecurityError:
            return None
        peers = []
        for peer in self._others(sid):
            ps = self._peers.get((sid, peer))
            key = ps.peer_identity_key if ps is not None else None
            peers.append({
                "peer": peer,
                "state": ps.state.name if ps is not None else "MISSING",
                "established": ps is not None and ps.established,
                "verified": self._trust.is_verified(peer),
                "peer_fingerprint": fingerprint_of(key) if key else None,
            })
        return {
            "session_id": sid,
            "members": list(self._session_members.get(sid, ())),
            "local_fingerprint": self._identity.fingerprint,
            "peers": peers,
            "all_established": all(p["established"] for p in peers),
            "all_verified": all(p["verified"] for p in peers),
        }

    # ========================================================= server events ==

    @staticmethod
    def _payload(msg: dict) -> dict:
        return {k: v for k, v in msg.items() if k != "type"}

    def _on_server_message(self, msg: dict) -> None:
        mtype = msg.get("type")
        try:
            if mtype == "registered":
                return
            if mtype == "session_started":
                self._on_session_started(msg)
            elif mtype == "session_ended":
                self._on_session_closed(msg, "session_ended")
            elif mtype == "session_expired":
                self._on_session_closed(msg, "session_expired")
            elif mtype == "message":
                self._on_relay(msg)
            elif mtype in self._PASSTHROUGH:
                self._events.emit(self._PASSTHROUGH[mtype], self._payload(msg))
            else:
                self._events.emit("protocol_message", msg)
        except Exception:
            log.exception("error handling server message %r", mtype)