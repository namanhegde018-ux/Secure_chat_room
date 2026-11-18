"""
Async framing and the per-client connection wrapper.

Wire format (same as the blocking send_frame/receive_frame):
    [4-byte big-endian payload length][UTF-8 JSON object]
"""

from __future__ import annotations

import asyncio
import json
import logging
import struct

try:  # Package execution
    from . import config
except ImportError:  # Direct execution from this directory
    import config

log = logging.getLogger("signaling.connection")

HEADER = struct.Struct("!I")         # 4-byte unsigned int, network byte order
_CLOSE = None                        # sentinel placed on the outbox to request an orderly close


class FramingError(Exception):
    """Malformed frame. The stream can no longer be trusted."""


class ConnectionClosed(FramingError):
    """The peer closed the connection before a full frame arrived."""


class MessageTooLarge(FramingError):
    """Declared or actual payload size exceeds MAX_MESSAGE_SIZE."""


def encode_frame(message: dict) -> bytes:
    # ensure_ascii=False keeps non-ASCII as raw UTF-8, which is shorter than \uXXXX escapes.
    payload = json.dumps(message, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(payload) > config.MAX_MESSAGE_SIZE:
        raise MessageTooLarge(f"payload is {len(payload)} bytes; limit is {config.MAX_MESSAGE_SIZE}")
    return HEADER.pack(len(payload)) + payload


async def read_frame(reader: asyncio.StreamReader) -> dict:
    """
    Read exactly one frame and return it as a dict.

    readexactly() loops over partial reads internally, so a frame that arrives
    in several TCP segments is reassembled before it is returned.
    """
    try:
        header = await reader.readexactly(HEADER.size)
        (length,) = HEADER.unpack(header)

        # Validate before reading the body, so a bogus header can't force a huge read.
        if length > config.MAX_MESSAGE_SIZE:
            raise MessageTooLarge(f"declared {length} bytes; limit is {config.MAX_MESSAGE_SIZE}")

        payload = await reader.readexactly(length)
    except asyncio.IncompleteReadError as exc:
        raise ConnectionClosed("peer closed the connection") from exc

    try:
        obj = json.loads(payload.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise FramingError("payload is not valid UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise FramingError(f"payload is not valid JSON: {exc}") from exc

    if not isinstance(obj, dict):
        raise FramingError("payload must be a JSON object")
    return obj


class Connection:
    """
    One client socket.

    Reading happens in the client's handler task. Writing happens in a separate
    writer task fed by a bounded queue. A slow receiver therefore can't block
    the sender or any other client. If its queue fills up, it is disconnected.
    """

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        self.peer = writer.get_extra_info("peername")
        self.client_id: str | None = None      # set once the client registers
        self.closed = False
        self._outbox: asyncio.Queue = asyncio.Queue(maxsize=config.OUTBOUND_QUEUE_SIZE)
        self._writer_task = asyncio.create_task(self._write_loop())

    def __repr__(self) -> str:
        return f"<Connection {self.client_id or self.peer}>"

    def send(self, message: dict) -> bool:
        """Queue a message without blocking. Returns False if it could not be queued."""
        if self.closed:
            return False
        try:
            frame = encode_frame(message)
        except MessageTooLarge as exc:
            log.error("dropping outbound message to %s: %s", self, exc)
            return False
        try:
            self._outbox.put_nowait(frame)
        except asyncio.QueueFull:
            log.warning("outbound queue full; disconnecting slow client %s", self)
            self.abort()
            return False
        return True

    async def close(self) -> None:
        """Flush queued frames, then close. Use for orderly shutdown and error replies."""
        if self.closed:
            return
        self.closed = True                       # refuse new frames from now on
        try:
            self._outbox.put_nowait(_CLOSE)
        except asyncio.QueueFull:
            self.abort()
            return
        done, _ = await asyncio.wait({self._writer_task}, timeout=config.FLUSH_TIMEOUT)
        if not done:
            self.abort()

    def abort(self) -> None:
        """Immediate close. Queued frames are discarded."""
        self.closed = True
        if not self._writer_task.done():
            self._writer_task.cancel()
        self.writer.close()

    async def _write_loop(self) -> None:
        try:
            while True:
                frame = await self._outbox.get()
                if frame is _CLOSE:
                    break
                self.writer.write(frame)
                await self.writer.drain()
        except (ConnectionError, OSError) as exc:
            log.debug("write failed for %s: %s", self, exc)
        finally:
            self.closed = True
            self.writer.close()