"""Async TCP framing compatible with the signalling server."""

import asyncio
import json
import struct
from typing import Any

HEADER = struct.Struct("!I")
DEFAULT_MAX_MESSAGE_SIZE = 1024 * 1024  # 1 MiB


class TransportError(Exception):
    """The received or outgoing frame is invalid."""


class PeerClosed(TransportError):
    """The peer closed the connection before a full frame arrived."""


class MessageTooLarge(TransportError):
    """The frame exceeds the configured maximum size."""


def encode_frame(
    message: dict[str, Any],
    max_message_size: int = DEFAULT_MAX_MESSAGE_SIZE,
) -> bytes:
    if not isinstance(message, dict):
        raise TypeError("message must be a dictionary")

    try:
        payload = json.dumps(
            message,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise TransportError(f"message cannot be encoded as JSON: {exc}") from exc

    if len(payload) > max_message_size:
        raise MessageTooLarge(
            f"payload is {len(payload)} bytes; limit is {max_message_size}"
        )

    return HEADER.pack(len(payload)) + payload


async def read_frame(
    reader: asyncio.StreamReader,
    max_message_size: int = DEFAULT_MAX_MESSAGE_SIZE,
) -> dict[str, Any]:
    """Read one complete length-prefixed JSON object."""
    try:
        header = await reader.readexactly(HEADER.size)
    except asyncio.IncompleteReadError as exc:
        raise PeerClosed("peer closed while sending the frame header") from exc

    (length,) = HEADER.unpack(header)
    if length > max_message_size:
        raise MessageTooLarge(
            f"declared payload is {length} bytes; limit is {max_message_size}"
        )

    try:
        payload = await reader.readexactly(length)
    except asyncio.IncompleteReadError as exc:
        raise PeerClosed("peer closed while sending the frame payload") from exc

    try:
        value = json.loads(payload.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise TransportError("payload is not valid UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise TransportError(f"payload is not valid JSON: {exc}") from exc

    if not isinstance(value, dict):
        raise TransportError("JSON payload must be an object")

    return value


async def write_frame(
    writer: asyncio.StreamWriter,
    message: dict[str, Any],
    max_message_size: int = DEFAULT_MAX_MESSAGE_SIZE,
) -> None:
    """Write one complete frame. Callers should serialize concurrent writes."""
    writer.write(encode_frame(message, max_message_size))
    await writer.drain()