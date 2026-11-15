"""Public, UI-independent API for the signalling client."""

import asyncio
import concurrent.futures
import logging
import threading
from pathlib import Path
from typing import Any, Callable

from .events import EventEmitter, UiDispatcher
from .file_transfer import FileTransferManager
from .network import NetworkError, NetworkManager
from .session import LocalSessionManager, SessionSnapshot
from .transport import DEFAULT_MAX_MESSAGE_SIZE

log = logging.getLogger(__name__)


class ClientCore:
    def __init__(
        self,
        host: str,
        port: int,
        client_id: str,
        *,
        dispatch_to_ui: UiDispatcher | None = None,
        download_dir: str | Path = "downloads",
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

        self._max_message_size = max_message_size
        self._connect_timeout = connect_timeout
        self._registration_timeout = registration_timeout
        self._heartbeat_interval = heartbeat_interval
        self._heartbeat_timeout = heartbeat_timeout

        self.file_transfers = FileTransferManager(
            send_body=self._send_file_body,
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

    @property
    def is_connected(self) -> bool:
        with self._state_lock:
            return self._connected

    @property
    def current_session(self) -> SessionSnapshot | None:
        return self.session_manager.current

    def on(self, event_name: str, callback: Callable[[dict[str, Any]], None]):
        """Subscribe to an event. The callback receives one payload dictionary."""
        return self.events.on(event_name, callback)

    def off(self, event_name: str, callback: Callable[[dict[str, Any]], None]) -> None:
        self.events.off(event_name, callback)

    def drain_events(self, limit: int | None = None) -> int:
        """Run queued callbacks in the calling thread when no UI dispatcher is set."""
        return self.events.drain(limit)

    def connect(self) -> concurrent.futures.Future:
        """Connect and register in the background."""
        return self._submit(self._connect_async)

    def invite(self, to_client_id: str) -> concurrent.futures.Future:
        return self._submit(
            lambda: self._send_command({"type": "invite", "to": to_client_id})
        )

    def accept_invitation(self, invitation_id: str) -> concurrent.futures.Future:
        return self._submit(
            lambda: self._send_command(
                {"type": "accept", "invitation_id": invitation_id}
            )
        )

    def reject_invitation(self, invitation_id: str) -> concurrent.futures.Future:
        return self._submit(
            lambda: self._send_command(
                {"type": "reject", "invitation_id": invitation_id}
            )
        )

    def send_message(
        self,
        body: Any,
        session_id: str | None = None,
    ) -> concurrent.futures.Future:
        async def operation() -> None:
            sid = self._require_session_id(session_id)
            await self._send_command(
                {"type": "message", "session_id": sid, "body": body}
            )

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

    def end_session(
        self,
        session_id: str | None = None,
    ) -> concurrent.futures.Future:
        async def operation() -> None:
            sid = self._require_session_id(session_id)
            await self._send_command(
                {"type": "end_session", "session_id": sid}
            )

        return self._submit(operation)

    def disconnect(self) -> concurrent.futures.Future:
        """Disconnect, but keep the background event loop available for reconnecting."""
        return self._submit(self._disconnect_async)

    def shutdown(self) -> concurrent.futures.Future:
        """Disconnect and stop the background event loop."""
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
        """Optionally wait for the background thread; do not call from the UI thread."""
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout)

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

    async def _send_command(self, message: dict[str, Any]) -> None:
        if self._network is None:
            raise NetworkError("call connect() before sending messages")
        await self._network.send(message)

    async def _send_file_body(self, session_id: str, body: dict[str, Any]) -> None:
        await self._send_command(
            {
                "type": "message",
                "session_id": session_id,
                "body": body,
            }
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

    async def _handle_server_message(self, message: dict[str, Any]) -> None:
        message_type = message.get("type")

        if message_type == "message":
            body = message.get("body")
            if isinstance(body, dict):
                kind = body.get("kind")
                if isinstance(kind, str) and kind.startswith("file_"):
                    session_id = message.get("session_id")
                    sender = message.get("from")

                    if (
                        not isinstance(session_id, str)
                        or not isinstance(sender, str)
                        or not self.session_manager.is_active(session_id)
                    ):
                        self.events.emit(
                            "file_transfer_error",
                            {
                                "message": "received a file message outside the local active session"
                            },
                        )
                    else:
                        await self.file_transfers.handle_relay(
                            session_id,
                            sender,
                            body,
                        )
                    return

        if message_type in {
            "session_started",
            "session_ended",
            "session_expired",
        }:
            changed = self.session_manager.apply_server_event(message)

            if message_type in {"session_ended", "session_expired"}:
                session_id = message.get("session_id")
                if isinstance(session_id, str):
                    await self.file_transfers.abort_session(
                        session_id,
                        reason=message.get("reason", message_type),
                    )

            if changed:
                current = self.session_manager.current
                self.events.emit(
                    "session_state_changed",
                    {"session": current.to_dict() if current else None},
                )

        event_name = (
            message_type
            if isinstance(message_type, str)
            else "protocol_message"
        )
        self.events.emit(event_name, message)

    def _handle_network_state(
        self,
        event_name: str,
        payload: dict[str, Any],
    ) -> None:
        with self._state_lock:
            self._connected = event_name == "connected"

        if event_name == "disconnected":
            if self.session_manager.clear():
                self.events.emit("session_state_changed", {"session": None})

            try:
                asyncio.get_running_loop().create_task(
                    self.file_transfers.abort_all("connection lost")
                )
            except RuntimeError:
                pass

        self.events.emit(event_name, payload)

    def _submit(
        self,
        coroutine_factory: Callable[[], Any],
    ) -> concurrent.futures.Future:
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
                loop.run_until_complete(
                    asyncio.gather(*pending, return_exceptions=True)
                )

            loop.run_until_complete(loop.shutdown_asyncgens())

            try:
                loop.run_until_complete(loop.shutdown_default_executor())
            except Exception:
                log.exception("error shutting down client executor")

            loop.close()