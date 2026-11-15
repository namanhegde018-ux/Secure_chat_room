"""Public, UI-independent API for the signalling client."""

import asyncio
import concurrent.futures
import logging
import threading
from pathlib import Path
from typing import Any, Callable

from .crypto import CryptoError, Identity, fingerprint_of, safety_number
from gui_core.events import EventEmitter, UiDispatcher
from gui_core.file_transfer import FileTransferManager
from .handshake import HANDSHAKE_KINDS, PeerSession
from gui_core.network import NetworkError, NetworkManager
from gui_core.session import LocalSessionManager, SessionSnapshot
from gui_core.transport import DEFAULT_MAX_MESSAGE_SIZE
from .trust import PeerKeyChanged, TrustStore

log = logging.getLogger(__name__)

SESSION_EVENTS = frozenset({"session_started", "session_ended", "session_expired"})


class SecurityError(Exception):
    """A security precondition is not met: no secure channel, or the peer is unverified."""


class ClientCore:
    def __init__(
        self,
        host: str,
        port: int,
        client_id: str,
        *,
        dispatch_to_ui: UiDispatcher | None = None,
        download_dir: str | Path = "downloads",
        identity_path: str | Path | None = None,
        trust_path: str | Path | None = None,
        require_verified_peers: bool = True,
        handshake_timeout: float = 15.0,
        max_message_size: int = DEFAULT_MAX_MESSAGE_SIZE,
        connect_timeout: float = 10.0,
        registration_timeout: float = 10.0,
        heartbeat_interval: float = 20.0,
        heartbeat_timeout: float = 50.0,
        file_chunk_size: int = 48 * 1024,
        max_file_size: int = 1024 * 1024 * 1024,
    ) -> None:
        self.host = host
        self.port = port
        self.client_id = client_id

        self.events = EventEmitter(dispatch_to_ui=dispatch_to_ui)
        self.session_manager = LocalSessionManager(client_id)

        # Without identity_path, a new identity is created on every run, and peers
        # will see a key change after restart. Pass identity_path in real use.
        self.identity = (
            Identity.load_or_create(identity_path) if identity_path else Identity.generate()
        )
        self.trust = TrustStore(trust_path)
        self.require_verified_peers = require_verified_peers
        self._handshake_timeout = handshake_timeout
        self._peer_sessions: dict[str, PeerSession] = {}
        self._peer_lock = threading.RLock()
        self._secure_send_lock = asyncio.Lock()

        self._max_message_size = max_message_size
        self._connect_timeout = connect_timeout
        self._registration_timeout = registration_timeout
        self._heartbeat_interval = heartbeat_interval
        self._heartbeat_timeout = heartbeat_timeout

        self.file_transfers = FileTransferManager(
            send_body=self._send_secure,
            emit=self.events.emit,
            download_dir=download_dir,
            chunk_size=file_chunk_size,
            max_file_size=max_file_size,
        )

        self._network: NetworkManager | None = None
        self._connect_lock: asyncio.Lock | None = None
        self._maintenance_task: asyncio.Task | None = None

        self._connected = False
        self._state_lock = threading.RLock()

        self._loop: asyncio.AbstractEventLoop | None = None
        self._loop_ready: threading.Event | None = None
        self._thread: threading.Thread | None = None
        self._lifecycle_lock = threading.RLock()
        self._shutdown_requested = False
        self._shutdown_future: concurrent.futures.Future | None = None

    # ------------------------------------------------------------------
    # Public properties and events
    # ------------------------------------------------------------------
    @property
    def is_connected(self) -> bool:
        with self._state_lock:
            return self._connected

    @property
    def current_session(self) -> SessionSnapshot | None:
        return self.session_manager.current

    @property
    def fingerprint(self) -> str:
        """This client's identity fingerprint. Show it to the user."""
        return self.identity.fingerprint

    def on(self, event_name: str, callback: Callable[[dict[str, Any]], None]):
        return self.events.on(event_name, callback)

    def off(self, event_name: str, callback: Callable[[dict[str, Any]], None]) -> None:
        self.events.off(event_name, callback)

    def drain_events(self, limit: int | None = None) -> int:
        return self.events.drain(limit)

    # ------------------------------------------------------------------
    # Verification (synchronous, safe to call from the UI thread)
    # ------------------------------------------------------------------
    def peer_status(self, session_id: str | None = None) -> dict[str, Any] | None:
        """
        Security details for a session: both fingerprints, the safety number,
        and whether the peer has been verified.
        """
        sid = session_id or self.session_manager.current_session_id
        if sid is None:
            return None
        with self._peer_lock:
            ps = self._peer_sessions.get(sid)
        if ps is None:
            return None

        key = ps.peer_identity_key
        return {
            "session_id": sid,
            "peer": ps.peer_id,
            "state": ps.state.value,
            "established": ps.established,
            "verified": self.trust.is_verified(ps.peer_id),
            "local_fingerprint": self.identity.fingerprint,
            "peer_fingerprint": fingerprint_of(key) if key else None,
            "safety_number": safety_number(self.identity.public_key, key) if key else None,
        }

    def verify_peer(self, peer_id: str, fingerprint: str) -> bool:
        """
        Confirm a peer's fingerprint after comparing it through a separate channel
        (in person, by phone, and so on). Returns True if it matches the pinned key.
        """
        ok = self.trust.verify(peer_id, fingerprint)
        if ok:
            self.events.emit("peer_verified", {"peer": peer_id})
        return ok

    def forget_peer_key(self, peer_id: str) -> bool:
        """
        Drop a pinned key after a legitimate key change has been verified out of band.
        Any session with that peer should be ended first.
        """
        removed = self.trust.forget(peer_id)
        if removed:
            self.events.emit("peer_key_forgotten", {"peer": peer_id})
        return removed

    # ------------------------------------------------------------------
    # Commands
    # ------------------------------------------------------------------
    def connect(self) -> concurrent.futures.Future:
        return self._submit(self._connect_async)

    def invite(self, to_client_id: str) -> concurrent.futures.Future:
        return self._submit(
            lambda: self._send_command({"type": "invite", "to": to_client_id})
        )

    def accept_invitation(self, invitation_id: str) -> concurrent.futures.Future:
        return self._submit(
            lambda: self._send_command({"type": "accept", "invitation_id": invitation_id})
        )

    def reject_invitation(self, invitation_id: str) -> concurrent.futures.Future:
        return self._submit(
            lambda: self._send_command({"type": "reject", "invitation_id": invitation_id})
        )

    def send_message(
        self,
        body: dict[str, Any],
        session_id: str | None = None,
    ) -> concurrent.futures.Future:
        if not isinstance(body, dict):
            raise TypeError("message body must be a dict")

        async def operation() -> None:
            sid = self._require_session_id(session_id)
            await self._send_secure(sid, body)

        return self._submit(operation)

    def send_file(
        self,
        path: str | Path,
        session_id: str | None = None,
    ) -> concurrent.futures.Future:
        async def operation() -> str:
            sid = self._require_session_id(session_id)
            return await self.file_transfers.send_file(sid, path)

        return self._submit(operation)

    def end_session(self, session_id: str | None = None) -> concurrent.futures.Future:
        async def operation() -> None:
            sid = self._require_session_id(session_id)
            await self._send_command({"type": "end_session", "session_id": sid})

        return self._submit(operation)

    def disconnect(self) -> concurrent.futures.Future:
        return self._submit(self._disconnect_async)

    def shutdown(self) -> concurrent.futures.Future:
        loop = self._ensure_loop()

        with self._lifecycle_lock:
            if self._shutdown_future is not None:
                return self._shutdown_future

            self._shutdown_requested = True
            coroutine = self._shutdown_async()

            try:
                future = asyncio.run_coroutine_threadsafe(coroutine, loop)
            except RuntimeError:
                coroutine.close()
                raise

            self._shutdown_future = future

            def stop_loop(_):
                try:
                    loop.call_soon_threadsafe(loop.stop)
                except RuntimeError:
                    pass

            future.add_done_callback(stop_loop)
            return future

    def join(self, timeout: float | None = None) -> None:
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout)

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------
    async def _connect_async(self) -> None:
        if self._connect_lock is None:
            self._connect_lock = asyncio.Lock()

        async with self._connect_lock:
            if self._network is not None and self._network.connected:
                raise NetworkError("already connected")

            if self._network is not None:
                await self._network.close("reconnecting")

            if self._maintenance_task is None or self._maintenance_task.done():
                self._maintenance_task = asyncio.create_task(
                    self._maintenance_loop(),
                    name=f"client-maintenance-{self.client_id}",
                )

            self._network = NetworkManager(
                self.host,
                self.port,
                self.client_id,
                on_message=self._handle_server_message,
                on_state=self._handle_network_state,
                max_message_size=self._max_message_size,
                connect_timeout=self._connect_timeout,
                registration_timeout=self._registration_timeout,
                heartbeat_interval=self._heartbeat_interval,
                heartbeat_timeout=self._heartbeat_timeout,
            )

            try:
                await self._network.connect()
            except Exception as exc:
                self.events.emit("connection_error", {"message": str(exc)})
                raise

    async def _disconnect_async(self) -> None:
        if self._network is not None:
            await self._network.close("client disconnected")

        self._clear_secure_sessions()
        self.session_manager.clear()
        await self.file_transfers.abort_all("client disconnected")

    async def _shutdown_async(self) -> None:
        if self._maintenance_task is not None:
            self._maintenance_task.cancel()
            await asyncio.gather(self._maintenance_task, return_exceptions=True)
            self._maintenance_task = None

        await self._disconnect_async()

    async def _maintenance_loop(self) -> None:
        while True:
            await asyncio.sleep(60)
            try:
                await self.file_transfers.expire_stale()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("file-transfer cleanup failed")

    # ------------------------------------------------------------------
    # Sending
    # ------------------------------------------------------------------
    async def _send_command(self, message: dict[str, Any]) -> None:
        if self._network is None:
            raise NetworkError("call connect() before sending messages")
        await self._network.send(message)

    def _usable_session(self, session_id: str) -> PeerSession:
        with self._peer_lock:
            ps = self._peer_sessions.get(session_id)
        if ps is None or not ps.established:
            raise SecurityError("secure channel is not established for this session yet")
        if self.require_verified_peers and not self.trust.is_verified(ps.peer_id):
            raise SecurityError(
                f"verify {ps.peer_id!r}'s fingerprint before sending messages"
            )
        return ps

    async def _send_secure(self, session_id: str, body: dict[str, Any]) -> None:
        """Encrypt an application body and relay it. Used for messages and file chunks."""
        async with self._secure_send_lock:
            ps = self._usable_session(session_id)
            # Seal and enqueue under one lock, so sequence numbers match wire order.
            envelope = ps.channel.seal(body)
            await self._send_command(
                {"type": "message", "session_id": session_id, "body": envelope}
            )

    def _require_session_id(self, requested: str | None) -> str:
        current = self.session_manager.current

        if requested is None:
            if current is None:
                raise NetworkError("there is no active session")
            return current.session_id

        if current is None or current.session_id != requested:
            raise NetworkError("the requested session is not active on this client")

        return requested

    # ------------------------------------------------------------------
    # Receiving
    # ------------------------------------------------------------------
    async def _handle_server_message(self, message: dict[str, Any]) -> None:
        message_type = message.get("type")

        if message_type == "message":
            await self._handle_relayed(message)
            return

        if message_type in SESSION_EVENTS:
            session_id = message.get("session_id")
            changed = self.session_manager.apply_server_event(message)

            if message_type == "session_started":
                if changed:
                    self._emit_session_changed()
                    await self._start_secure_session(message)
            else:
                if isinstance(session_id, str):
                    self._drop_secure_session(session_id)
                    await self.file_transfers.abort_session(
                        session_id,
                        reason=message.get("reason", message_type),
                    )
                if changed:
                    self._emit_session_changed()

        event_name = message_type if isinstance(message_type, str) else "protocol_message"
        self.events.emit(event_name, message)

    async def _handle_relayed(self, message: dict[str, Any]) -> None:
        session_id = message.get("session_id")
        sender = message.get("from")
        body = message.get("body")

        if not (isinstance(session_id, str) and isinstance(sender, str) and isinstance(body, dict)):
            log.warning("malformed relayed message dropped")
            return

        if not self.session_manager.is_active(session_id):
            self._reject(session_id, "message is outside the local active session")
            return

        kind = body.get("kind")
        if kind in HANDSHAKE_KINDS:
            await self._handle_handshake(session_id, sender, body)
            return

        # Downgrade protection: once a session exists, plaintext is refused.
        if kind != "secure":
            self._reject(session_id, "unencrypted message refused")
            return

        with self._peer_lock:
            ps = self._peer_sessions.get(session_id)
        if ps is None or not ps.established or ps.peer_id != sender:
            self._reject(session_id, "no established secure channel with the sender")
            return
        if self.require_verified_peers and not self.trust.is_verified(sender):
            self._reject(session_id, "sender's identity key is not verified")
            return

        try:
            inner = ps.channel.unseal(body)
        except CryptoError as exc:
            self._reject(session_id, f"message failed authentication: {exc}")
            return

        inner_kind = inner.get("kind")
        if inner_kind in HANDSHAKE_KINDS or inner_kind == "secure":
            self._reject(session_id, "nested protocol message refused")
            return

        if isinstance(inner_kind, str) and inner_kind.startswith("file_"):
            await self.file_transfers.handle_relay(session_id, sender, inner)
            return

        self.events.emit(
            "message",
            {"session_id": session_id, "from": sender, "body": inner},
        )

    # ------------------------------------------------------------------
    # Handshake orchestration
    # ------------------------------------------------------------------
    async def _start_secure_session(self, message: dict[str, Any]) -> None:
        session_id = message["session_id"]
        others = [member for member in message["members"] if member != self.client_id]
        if len(others) != 1:
            self.events.emit(
                "handshake_failed",
                {"session_id": session_id, "message": "secure sessions need exactly two members"},
            )
            return

        peer_id = others[0]
        ps = PeerSession(session_id, self.client_id, peer_id, self.identity, self.trust)
        with self._peer_lock:
            self._peer_sessions[session_id] = ps

        asyncio.get_running_loop().call_later(
            self._handshake_timeout, self._on_handshake_timeout, session_id
        )

        if not ps.is_initiator:
            return  # the responder waits for hs1

        try:
            hs1 = ps.start()
            await self._send_command(
                {"type": "message", "session_id": session_id, "body": hs1}
            )
        except (NetworkError, CryptoError) as exc:
            self.events.emit(
                "handshake_failed",
                {"session_id": session_id, "peer": peer_id, "message": str(exc)},
            )
            await self._abort_handshake(session_id)

    async def _handle_handshake(self, session_id: str, sender: str, body: dict[str, Any]) -> None:
        with self._peer_lock:
            ps = self._peer_sessions.get(session_id)
        if ps is None or ps.peer_id != sender:
            self._reject(session_id, "handshake message from an unexpected sender")
            return

        was_established = ps.established
        try:
            reply = ps.handle(body)
        except PeerKeyChanged as exc:
            self.events.emit(
                "peer_key_changed",
                {
                    "session_id": session_id,
                    "peer": sender,
                    "message": str(exc),
                    "pinned_fingerprint": fingerprint_of(exc.pinned),
                    "presented_fingerprint": fingerprint_of(exc.presented),
                },
            )
            await self._abort_handshake(session_id)
            return
        except CryptoError as exc:
            self.events.emit(
                "handshake_failed",
                {"session_id": session_id, "peer": sender, "message": str(exc)},
            )
            if not ps.established:
                await self._abort_handshake(session_id)
            return

        if reply is not None:
            try:
                await self._send_command(
                    {"type": "message", "session_id": session_id, "body": reply}
                )
            except NetworkError as exc:
                self.events.emit(
                    "handshake_failed",
                    {
                        "session_id": session_id,
                        "peer": sender,
                        "message": f"could not send handshake reply: {exc}",
                    },
                )
                await self._abort_handshake(session_id)
                return

        if ps.established and not was_established:
            self._announce_established(ps)

    async def _abort_handshake(self, session_id: str) -> None:
        """Drop local secure state and ask the server to end the session."""
        self._drop_secure_session(session_id)
        try:
            await self._send_command({"type": "end_session", "session_id": session_id})
        except NetworkError:
            pass

    def _on_handshake_timeout(self, session_id: str) -> None:
        with self._peer_lock:
            ps = self._peer_sessions.get(session_id)
        if ps is None or ps.established:
            return
        self.events.emit(
            "handshake_failed",
            {"session_id": session_id, "peer": ps.peer_id, "message": "handshake timed out"},
        )
        asyncio.get_running_loop().create_task(self._abort_handshake(session_id))

    def _announce_established(self, ps: PeerSession) -> None:
        peer_key = ps.peer_identity_key
        assert peer_key is not None
        self.events.emit(
            "secure_session_established",
            {
                "session_id": ps.session_id,
                "peer": ps.peer_id,
                "local_fingerprint": self.identity.fingerprint,
                "peer_fingerprint": fingerprint_of(peer_key),
                "safety_number": safety_number(self.identity.public_key, peer_key),
                "verified": self.trust.is_verified(ps.peer_id),
            },
        )

    def _drop_secure_session(self, session_id: str) -> None:
        with self._peer_lock:
            self._peer_sessions.pop(session_id, None)

    def _clear_secure_sessions(self) -> None:
        with self._peer_lock:
            self._peer_sessions.clear()

    def _reject(self, session_id: Any, reason: str) -> None:
        log.warning("message rejected in session %s: %s", session_id, reason)
        self.events.emit("message_rejected", {"session_id": session_id, "reason": reason})

    def _emit_session_changed(self) -> None:
        current = self.session_manager.current
        self.events.emit(
            "session_state_changed",
            {"session": current.to_dict() if current else None},
        )

    def _handle_network_state(self, event_name: str, payload: dict[str, Any]) -> None:
        with self._state_lock:
            self._connected = event_name == "connected"

        if event_name == "disconnected":
            self._clear_secure_sessions()
            if self.session_manager.clear():
                self.events.emit("session_state_changed", {"session": None})

            try:
                asyncio.get_running_loop().create_task(
                    self.file_transfers.abort_all("connection lost")
                )
            except RuntimeError:
                pass

        self.events.emit(event_name, payload)

    # ------------------------------------------------------------------
    # Background loop plumbing
    # ------------------------------------------------------------------
    def _submit(self, coroutine_factory: Callable[[], Any]) -> concurrent.futures.Future:
        loop = self._ensure_loop()

        with self._lifecycle_lock:
            if self._shutdown_requested:
                raise RuntimeError("client core has been shut down")

            coroutine = coroutine_factory()
            try:
                return asyncio.run_coroutine_threadsafe(coroutine, loop)
            except RuntimeError:
                coroutine.close()
                raise

    def _ensure_loop(self) -> asyncio.AbstractEventLoop:
        with self._lifecycle_lock:
            if self._loop is not None:
                if self._loop.is_closed():
                    raise RuntimeError("client event loop has stopped")
                return self._loop

            if self._thread is None:
                self._loop_ready = threading.Event()
                self._thread = threading.Thread(
                    target=self._run_loop,
                    name=f"client-core-{self.client_id}",
                    daemon=True,
                )
                self._thread.start()

            ready = self._loop_ready

        assert ready is not None
        ready.wait()

        if self._loop is None:
            raise RuntimeError("client event loop failed to start")

        return self._loop

    def _run_loop(self) -> None:
        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)

        assert self._loop_ready is not None
        self._loop_ready.set()

        try:
            loop.run_forever()
        finally:
            pending = asyncio.all_tasks(loop)
            for task in pending:
                task.cancel()

            if pending:
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))

            loop.run_until_complete(loop.shutdown_asyncgens())

            try:
                loop.run_until_complete(loop.shutdown_default_executor())
            except Exception:
                log.exception("error shutting down client executor")

            loop.close()