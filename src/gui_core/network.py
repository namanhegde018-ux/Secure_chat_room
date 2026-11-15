"""Async connection and protocol communication with the signalling server."""

import asyncio
import inspect
import logging
from typing import Any, Callable

from .transport import (
    DEFAULT_MAX_MESSAGE_SIZE,
    PeerClosed,
    TransportError,
    read_frame,
    write_frame,
)

log = logging.getLogger(__name__)


class NetworkError(Exception):
    """Network or registration failure."""


class NotConnectedError(NetworkError):
    """An operation was attempted without a registered connection."""


MessageHandler = Callable[[dict[str, Any]], Any]
StateHandler = Callable[[str, dict[str, Any]], None]


class NetworkManager:
    def __init__(
        self,
        host: str,
        port: int,
        client_id: str,
        on_message: MessageHandler,
        on_state: StateHandler,
        *,
        max_message_size: int = DEFAULT_MAX_MESSAGE_SIZE,
        connect_timeout: float = 10.0,
        registration_timeout: float = 10.0,
        heartbeat_interval: float = 20.0,
        heartbeat_timeout: float = 50.0,
    ) -> None:
        self.host = host
        self.port = port
        self.client_id = client_id
        self.on_message = on_message
        self.on_state = on_state

        self.max_message_size = max_message_size
        self.connect_timeout = connect_timeout
        self.registration_timeout = registration_timeout
        self.heartbeat_interval = heartbeat_interval
        self.heartbeat_timeout = heartbeat_timeout

        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._write_lock: asyncio.Lock | None = None
        self._registered: asyncio.Event | None = None

        self._reader_task: asyncio.Task | None = None
        self._heartbeat_task: asyncio.Task | None = None

        self._connected = False
        self._connected_reported = False
        self._closing = False
        self._close_reason: str | None = None
        self._registration_error: NetworkError | None = None
        self._last_pong = 0.0

    @property
    def connected(self) -> bool:
        return self._connected

    async def connect(self) -> None:
        if self._connected:
            raise NetworkError("already connected")

        self._closing = False
        self._close_reason = None
        self._registration_error = None
        self._connected_reported = False

        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=self.connect_timeout,
            )
        except asyncio.TimeoutError as exc:
            raise NetworkError("timed out connecting to the server") from exc
        except OSError as exc:
            raise NetworkError(f"could not connect to the server: {exc}") from exc

        self._write_lock = asyncio.Lock()
        self._registered = asyncio.Event()
        self._last_pong = asyncio.get_running_loop().time()

        self._reader_task = asyncio.create_task(
            self._read_loop(),
            name=f"client-reader-{self.client_id}",
        )

        try:
            await self._write_message(
                {"type": "register", "client_id": self.client_id}
            )
            await asyncio.wait_for(
                self._registered.wait(),
                timeout=self.registration_timeout,
            )

            if self._registration_error is not None:
                raise self._registration_error

            if self._reader_task.done():
                raise NetworkError("connection closed during registration")

            self._connected = True
            self._connected_reported = True
            self._report_state("connected", {"client_id": self.client_id})

            self._heartbeat_task = asyncio.create_task(
                self._heartbeat_loop(),
                name=f"client-heartbeat-{self.client_id}",
            )
        except BaseException:
            await self.close("connection or registration failed")
            raise

    async def send(self, message: dict[str, Any]) -> None:
        if not self._connected or self._closing:
            raise NotConnectedError("not connected to the server")
        await self._write_message(message)

    async def close(self, reason: str = "client disconnected") -> None:
        if self._closing:
            return

        self._closing = True
        self._close_reason = reason
        current = asyncio.current_task()

        tasks = (self._heartbeat_task, self._reader_task)
        for task in tasks:
            if task is not None and task is not current and not task.done():
                task.cancel()

        if self._writer is not None:
            self._writer.close()
            try:
                await asyncio.wait_for(self._writer.wait_closed(), timeout=2.0)
            except (asyncio.TimeoutError, OSError, ConnectionError):
                pass

        to_wait = [
            task for task in tasks
            if task is not None and task is not current
        ]
        if to_wait:
            await asyncio.gather(*to_wait, return_exceptions=True)

        self._connected = False
        self._report_disconnected(reason)

    async def _write_message(self, message: dict[str, Any]) -> None:
        if self._writer is None or self._writer.is_closing():
            raise NotConnectedError("TCP connection is not available")
        if self._write_lock is None:
            raise NotConnectedError("TCP connection is not initialized")

        async with self._write_lock:
            if self._writer.is_closing():
                raise NotConnectedError("TCP connection is closing")
            try:
                await write_frame(
                    self._writer,
                    message,
                    max_message_size=self.max_message_size,
                )
            except (OSError, ConnectionError):
                self._writer.close()
                raise

    async def _read_loop(self) -> None:
        reason = "server closed the connection"

        try:
            while not self._closing:
                if self._reader is None:
                    break

                message = await read_frame(
                    self._reader,
                    max_message_size=self.max_message_size,
                )

                message_type = message.get("type")
                if message_type == "pong":
                    self._last_pong = asyncio.get_running_loop().time()

                if message_type == "registered":
                    if message.get("client_id") != self.client_id:
                        self._registration_error = NetworkError(
                            "server registered a different client ID"
                        )
                    if self._registered is not None:
                        self._registered.set()
                elif (
                    message_type == "error"
                    and self._registered is not None
                    and not self._registered.is_set()
                ):
                    self._registration_error = NetworkError(
                        message.get("message", "registration was rejected")
                    )
                    self._registered.set()

                try:
                    result = self.on_message(message)
                    if inspect.isawaitable(result):
                        await result
                except Exception:
                    # A client-side event handler error should not kill the TCP reader.
                    log.exception("client message handler failed")

        except asyncio.CancelledError:
            reason = self._close_reason or "connection closed"
            raise
        except PeerClosed as exc:
            reason = str(exc)
        except TransportError as exc:
            reason = f"invalid server frame: {exc}"
            log.warning("%s", reason)
        except (OSError, ConnectionError) as exc:
            reason = f"network error: {exc}"
        except Exception as exc:
            reason = f"unexpected network error: {exc}"
            log.exception("unexpected error in network read loop")
        finally:
            if self._registered is not None and not self._registered.is_set():
                self._registration_error = self._registration_error or NetworkError(reason)
                self._registered.set()

            if self._close_reason:
                reason = self._close_reason

            self._connected = False
            self._closing = True

            if self._writer is not None and not self._writer.is_closing():
                self._writer.close()

            if (
                self._heartbeat_task is not None
                and self._heartbeat_task is not asyncio.current_task()
                and not self._heartbeat_task.done()
            ):
                self._heartbeat_task.cancel()

            self._report_disconnected(reason)

    async def _heartbeat_loop(self) -> None:
        try:
            while self._connected and not self._closing:
                await asyncio.sleep(self.heartbeat_interval)

                now = asyncio.get_running_loop().time()
                if now - self._last_pong > self.heartbeat_timeout:
                    raise NetworkError("server heartbeat timed out")

                await self.send({"type": "ping"})

        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._close_reason = f"heartbeat failed: {exc}"
            if self._writer is not None:
                self._writer.close()

    def _report_state(self, event: str, payload: dict[str, Any]) -> None:
        try:
            self.on_state(event, payload)
        except Exception:
            log.exception("network-state handler failed")

    def _report_disconnected(self, reason: str) -> None:
        if not self._connected_reported:
            return

        self._connected_reported = False
        self._report_state(
            "disconnected",
            {"client_id": self.client_id, "reason": reason},
        )