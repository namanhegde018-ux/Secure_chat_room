"""
client_core/core.py

Public, UI-independent API for the messaging client.

- Commands return concurrent.futures.Future and run on a private asyncio loop
  in a daemon thread. Frontends never touch the loop directly.
- Events are emitted on the loop thread through EventEmitter, which dispatches
  them to the UI (dispatch_to_ui) or queues them for drain_events().
- Every application message and file body is sealed end to end. The server
  relays ciphertext only.
- Outgoing frames go through one asyncio.Queue drained by a single pump task.
  Frames are sent in the order they were queued, so secure-channel sequence
  numbers match wire order.
"""
from __future__ import annotations

import asyncio
import base64
import concurrent.futures
import json
import logging
import threading
from typing import Any, Callable, Optional

from crypto import CryptoError, Identity, fingerprint_of, safety_number
from events import EventEmitter
from file_transfer import DEFAULT_CHUNK_SIZE, DEFAULT_MAX_FILE_SIZE, FileTransferManager
from handshake import PeerSession
from network import NetworkError, NetworkManager, NotConnectedError
from session import LocalSessionManager
from temp_manager import TempManager
from trust import PeerKeyChanged, TrustStore

log = logging.getLogger(__name__)

__all__ = ["ClientCore", "SecurityError"]

HANDSHAKE_KINDS = frozenset({"hs1", "hs2", "hs3"})
ROUTED_PREFIXES = ("file_", "export_")
MAINTENANCE_INTERVAL = 5.0      # seconds between transfer sweeps and temp cleanup
CALL_TIMEOUT = 10.0             # seconds a blocking query may wait for the loop


class SecurityError(Exception):
    """A requested action violates a security precondition."""


def _check_app_body(body: Any) -> None:
    """Reject application bodies that would be interpreted as protocol messages."""
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

        # Identity: a new key is generated per run unless identity_path is given.
        self._identity = (
            Identity.load_or_create(identity_path) if identity_path else Identity.generate()
        )
        self._trust = TrustStore(trust_path)
        self._events = EventEmitter(dispatch_to_ui=dispatch_to_ui)
        self._session = LocalSessionManager(client_id)

        self._temp = TempManager(client_id, root=temp_root)
        self._temp.cleanup_stale_on_startup()                 # Scenario C

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
        self._peers: dict[str, PeerSession] = {}
        self._session_peer: dict[str, str] = {}
        self._timers: dict[str, asyncio.TimerHandle] = {}

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
        """Run fn on the loop and wait for the result. For short, read-mostly queries."""
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

    def invite(self, to: str) -> concurrent.futures.Future:
        return self._submit(self._invite, to)

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
        """Call from the UI thread when dispatch_to_ui is not supplied."""
        return self._events.drain(limit)

    def join(self, timeout: Optional[float] = None) -> bool:
        """Wait for the background thread to exit. Returns True if it has stopped."""
        self._thread.join(timeout)
        return not self._thread.is_alive()

    def verify_peer(self, peer_id: str, fingerprint: str) -> bool:
        """Record that the user compared fingerprints out of band and they match."""
        return self._call_sync(self._verify_peer, peer_id, fingerprint)

    def forget_peer_key(self, peer_id: str) -> bool:
        """Remove the pinned key for a peer. The next handshake pins a new key."""
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
        for sid in list(self._peers):
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
        """Send queued frames one at a time, in the order they were queued."""
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

    def _invite(self, to: str) -> None:
        if not isinstance(to, str) or not to or to == self.client_id:
            raise ValueError("invalid recipient")
        self._control({"type": "invite", "to": to})

    # ============================================================ sessions ==

    def _active_session_id(self, session_id: Optional[str] = None) -> str:
        sid = session_id if session_id is not None else self._session.current_session_id
        if not isinstance(sid, str) or not self._session.is_active(sid):
            raise SecurityError("no active session")
        return sid

    def _usable_session(self, session_id: Optional[str] = None) -> tuple[str, str]:
        sid = self._active_session_id(session_id)
        ps = self._peers.get(sid)
        if ps is None or not ps.established:
            raise SecurityError("secure channel is not established for this session")
        peer = self._session_peer[sid]
        if self.require_verified_peers and not self._trust.is_verified(peer):
            raise SecurityError(f"peer '{peer}' has not been verified; compare fingerprints first")
        return sid, peer

    def _end_session(self, session_id: Optional[str]) -> None:
        sid = self._active_session_id(session_id)
        self._control({"type": "end_session", "session_id": sid})

    def _on_session_started(self, msg: dict) -> None:
        sid = msg.get("session_id")
        members = msg.get("members")
        others = [m for m in members if m != self.client_id] if isinstance(members, list) else []
        if not isinstance(sid, str) or len(others) != 1 or not isinstance(others[0], str):
            self._events.emit("error", {"request": "session_started", "message": "malformed session_started"})
            return
        if sid in self._peers:
            log.warning("duplicate session_started for %s", sid)
            return

        peer = others[0]
        try:
            self._temp.open_session(sid)
        except Exception as exc:
            self._events.emit("error", {"request": "session_started", "message": f"local storage: {exc}"})
            return

        self._emit_session_state(self._session.apply_server_event(msg))
        self._session_peer[sid] = peer
        self._peers[sid] = PeerSession(sid, self.client_id, peer, self._identity, self._trust)
        self._events.emit("session_started", {"session_id": sid, "members": members, "peer": peer})
        self._timers[sid] = self._loop.call_later(self.handshake_timeout, self._on_handshake_timeout, sid)

        # Smaller client id initiates the handshake.
        if self.client_id < peer:
            try:
                self._send_handshake(sid, self._peers[sid].start())
            except Exception as exc:
                log.exception("could not start handshake")
                self._handshake_failed(sid, f"could not start handshake: {exc}")

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
        self._cancel_timer(sid)
        self._peers.pop(sid, None)
        self._session_peer.pop(sid, None)
        self._file_transfers.close_session(sid, reason)      # Scenarios A and B

    def _fail_session(self, sid: str, reason: str) -> None:
        """Local failure: drop the session and ask the server to end it for both sides."""
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

    def _send_handshake(self, sid: str, body: Optional[dict]) -> None:
        if body is not None:
            self._enqueue({"type": "message", "session_id": sid, "body": body})

    def _handle_handshake(self, sid: str, ps: PeerSession, body: dict) -> None:
        was_established = ps.established
        try:
            reply = ps.handle(body)
            self._send_handshake(sid, reply)
        except PeerKeyChanged as exc:
            return self._on_key_changed(sid, exc)
        except CryptoError as exc:
            return self._handshake_failed(sid, str(exc))
        except Exception:
            log.exception("unexpected handshake error")
            return self._handshake_failed(sid, "internal error")
        if ps.established and not was_established:
            self._on_established(sid, ps)

    def _on_established(self, sid: str, ps: PeerSession) -> None:
        self._cancel_timer(sid)
        peer = self._session_peer[sid]
        self._events.emit("secure_session_established", {
            "session_id": sid,
            "peer": peer,
            "local_fingerprint": self._identity.fingerprint,
            "peer_fingerprint": fingerprint_of(ps.peer_identity_key),
            "safety_number": safety_number(self._identity.public_key, ps.peer_identity_key),
            "verified": self._trust.is_verified(peer),
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

    def _handshake_failed(self, sid: str, reason: str) -> None:
        self._events.emit("handshake_failed", {
            "session_id": sid, "peer": self._session_peer.get(sid), "reason": reason,
        })
        self._fail_session(sid, "handshake failed")

    def _on_handshake_timeout(self, sid: str) -> None:
        self._timers.pop(sid, None)
        ps = self._peers.get(sid)
        if ps is None or ps.established:
            return
        self._handshake_failed(sid, "handshake timed out")

    def _cancel_timer(self, sid: str) -> None:
        timer = self._timers.pop(sid, None)
        if timer is not None:
            timer.cancel()

    # ================================================ encrypted messaging ==

    def _send_secure(self, session_id: str, body: dict) -> None:
        """Seal one body for the session and queue it. Raises on failure."""
        ps = self._peers.get(session_id)
        if ps is None or not ps.established:
            raise SecurityError("secure channel is not established for this session")
        envelope = ps.channel.seal(body)          # returns {"kind": "secure", "seq", "ct"}
        self._enqueue({"type": "message", "session_id": session_id, "body": envelope})

    def _send_message(self, body: dict, session_id: Optional[str]) -> None:
        _check_app_body(body)
        sid, _peer = self._usable_session(session_id)
        self._send_secure(sid, body)

    async def _send_file(self, path: str, session_id: Optional[str]) -> str:
        self._net()
        sid, peer = self._usable_session(session_id)
        return await self._file_transfers.send_file(path, sid, peer)

    @staticmethod
    def _open_secure(ps: PeerSession, body: dict) -> dict:
        return ps.channel.unseal(body)            # raises CryptoError on bad input

    def _reject(self, sid: Optional[str], reason: str) -> None:
        self._events.emit("message_rejected", {"session_id": sid, "reason": reason})

    def _on_relay(self, msg: dict) -> None:
        sid = msg.get("session_id")
        sender = msg.get("from")
        body = msg.get("body")
        ps = self._peers.get(sid) if isinstance(sid, str) else None
        if ps is None:
            return self._reject(sid, "no active secure session")
        if sender != self._session_peer[sid]:
            return self._reject(sid, "message from unexpected sender")
        if not isinstance(body, dict):
            return self._reject(sid, "malformed message")

        kind = body.get("kind")
        if isinstance(kind, str) and kind in HANDSHAKE_KINDS:
            return self._handle_handshake(sid, ps, body)
        if kind != "secure":
            return self._reject(sid, "unencrypted message refused")
        if not ps.established:
            return self._reject(sid, "secure channel is not established")
        if self.require_verified_peers and not self._trust.is_verified(sender):
            return self._reject(sid, "peer is not verified")
        try:
            inner = self._open_secure(ps, body)
        except (CryptoError, ValueError):
            return self._reject(sid, "authentication failed")
        self._route_inner(sid, sender, inner)

    def _route_inner(self, sid: str, sender: str, inner: dict) -> None:
        kind = inner.get("kind")
        if isinstance(kind, str) and kind.startswith(ROUTED_PREFIXES):
            if not self._file_transfers.handle_relay(sid, sender, inner):
                self._reject(sid, "unknown file message")
            return
        if isinstance(kind, str) and (kind in HANDSHAKE_KINDS or kind == "secure"):
            return self._reject(sid, "nested protocol message refused")
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
        ps = self._peers.get(sid)
        if ps is None:
            return None
        peer = self._session_peer[sid]
        peer_key = ps.peer_identity_key
        return {
            "session_id": sid,
            "peer": peer,
            "state": ps.state.name,
            "established": ps.established,
            "verified": self._trust.is_verified(peer),
            "local_fingerprint": self._identity.fingerprint,
            "peer_fingerprint": fingerprint_of(peer_key) if peer_key else None,
        }

    # ========================================================= server events ==

    @staticmethod
    def _payload(msg: dict) -> dict:
        return {k: v for k, v in msg.items() if k != "type"}

    def _on_server_message(self, msg: dict) -> None:
        mtype = msg.get("type")
        try:
            if mtype == "registered":
                return                              # consumed by connect()
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