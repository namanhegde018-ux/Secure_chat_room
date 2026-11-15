"""File transfer over the server-relayed session message channel."""

import asyncio
import base64
import hashlib
import hmac
import math
import os
import re
import secrets
import stat
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

DEFAULT_CHUNK_SIZE = 48 * 1024
MAX_CHUNK_SIZE = 64 * 1024
MIN_CHUNK_SIZE = 1024
DEFAULT_MAX_FILE_SIZE = 1024 * 1024 * 1024  # 1 GiB
MAX_FILE_CHUNKS = 1_000_000
DEFAULT_INCOMING_TTL = 10 * 60


class FileTransferError(Exception):
    """Invalid or failed file transfer."""


@dataclass
class _IncomingTransfer:
    session_id: str
    sender: str
    transfer_id: str
    name: str
    size: int
    chunk_size: int
    chunks: int
    temp_path: Path
    received: int = 0
    next_index: int = 0
    last_activity: float = field(default_factory=time.monotonic)
    digest: Any = field(default_factory=hashlib.sha256)


class FileTransferManager:
    def __init__(
        self,
        send_body: Callable[[str, dict[str, Any]], Any],
        emit: Callable[[str, dict[str, Any]], None],
        *,
        download_dir: str | Path = "downloads",
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        incoming_ttl: float = DEFAULT_INCOMING_TTL,
    ) -> None:
        if not MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE:
            raise ValueError(
                f"chunk_size must be between {MIN_CHUNK_SIZE} and {MAX_CHUNK_SIZE}"
            )

        self._send_body = send_body
        self._emit_callback = emit
        self.download_dir = Path(download_dir).expanduser()
        self.chunk_size = chunk_size
        self.max_file_size = max_file_size
        self.incoming_ttl = incoming_ttl

        # Keyed by (session_id, sender_client_id, transfer_id).
        self._incoming: dict[tuple[str, str, str], _IncomingTransfer] = {}

    async def send_file(self, session_id: str, path: str | Path) -> str:
        """Stream a file through the server. Returns its transfer ID."""
        file_path = Path(path).expanduser()
        transfer_id: str | None = None
        file_obj = None
        start_sent = False

        try:
            file_obj, size = await asyncio.to_thread(_open_and_size, file_path)

            if size > self.max_file_size:
                raise FileTransferError(
                    f"file is {size} bytes; limit is {self.max_file_size}"
                )

            name = _safe_filename(file_path.name)
            transfer_id = secrets.token_urlsafe(12)
            chunks = math.ceil(size / self.chunk_size) if size else 0

            await self._send_body(
                session_id,
                {
                    "kind": "file_start",
                    "transfer_id": transfer_id,
                    "name": name,
                    "size": size,
                    "chunk_size": self.chunk_size,
                    "chunks": chunks,
                },
            )
            start_sent = True

            digest = hashlib.sha256()
            bytes_sent = 0
            index = 0

            while True:
                chunk = await asyncio.to_thread(file_obj.read, self.chunk_size)
                if not chunk:
                    break

                if bytes_sent + len(chunk) > size:
                    raise FileTransferError("file changed while it was being sent")

                await self._send_body(
                    session_id,
                    {
                        "kind": "file_chunk",
                        "transfer_id": transfer_id,
                        "index": index,
                        "data": base64.b64encode(chunk).decode("ascii"),
                    },
                )

                digest.update(chunk)
                bytes_sent += len(chunk)
                index += 1

                if index % 4 == 0 or bytes_sent == size:
                    self._emit(
                        "file_progress",
                        {
                            "direction": "outgoing",
                            "transfer_id": transfer_id,
                            "file_name": name,
                            "bytes_transferred": bytes_sent,
                            "total_bytes": size,
                        },
                    )

            if bytes_sent != size or index != chunks:
                raise FileTransferError("file changed while it was being sent")

            await self._send_body(
                session_id,
                {
                    "kind": "file_end",
                    "transfer_id": transfer_id,
                    "size": bytes_sent,
                    "chunks": index,
                    "sha256": digest.hexdigest(),
                },
            )

            self._emit(
                "file_sent",
                {
                    "transfer_id": transfer_id,
                    "file_name": name,
                    "size": size,
                },
            )
            return transfer_id

        except Exception as exc:
            if start_sent and transfer_id is not None:
                try:
                    await self._send_body(
                        session_id,
                        {
                            "kind": "file_abort",
                            "transfer_id": transfer_id,
                            "reason": "sender_error",
                        },
                    )
                except Exception:
                    pass

            self._emit(
                "file_transfer_error",
                {
                    "direction": "outgoing",
                    "transfer_id": transfer_id,
                    "file_name": file_path.name,
                    "message": str(exc),
                },
            )
            raise

        finally:
            if file_obj is not None:
                try:
                    await asyncio.to_thread(file_obj.close)
                except Exception:
                    pass

    async def handle_relay(
        self,
        session_id: str,
        sender: str,
        body: Any,
    ) -> bool:
        """
        Handle a relayed file-transfer body.

        Returns True if the body was a file-transfer message, including malformed
        file-transfer messages. Non-file application messages return False.
        """
        if not isinstance(body, dict):
            return False

        kind = body.get("kind")
        if not isinstance(kind, str) or not kind.startswith("file_"):
            return False

        if not session_id or not sender:
            self._emit(
                "file_transfer_error",
                {"message": "file message is missing its session or sender"},
            )
            return True

        transfer_id_value = body.get("transfer_id")
        transfer_id = transfer_id_value if isinstance(transfer_id_value, str) else ""
        key = (session_id, sender, transfer_id)

        try:
            await self.expire_stale()

            if kind == "file_start":
                await self._handle_start(key, session_id, sender, body)
            elif kind == "file_chunk":
                await self._handle_chunk(key, body)
            elif kind == "file_end":
                await self._handle_end(key, body)
            elif kind == "file_abort":
                await self._discard(key)
                self._emit(
                    "file_transfer_aborted",
                    {
                        "transfer_id": transfer_id,
                        "from": sender,
                        "reason": body.get("reason", "sender_aborted"),
                    },
                )
            else:
                raise FileTransferError(f"unknown file message kind: {kind}")

        except asyncio.CancelledError:
            raise
        except Exception as exc:
            try:
                await self._discard(key)
            except Exception:
                pass

            self._emit(
                "file_transfer_error",
                {
                    "transfer_id": transfer_id or None,
                    "from": sender,
                    "file_name": body.get("name"),
                    "message": str(exc),
                },
            )

        return True

    async def expire_stale(self) -> None:
        now = time.monotonic()
        stale_keys = [
            key
            for key, transfer in self._incoming.items()
            if now - transfer.last_activity >= self.incoming_ttl
        ]

        for key in stale_keys:
            transfer = self._incoming.get(key)
            await self._discard(key)
            if transfer is not None:
                self._emit(
                    "file_transfer_error",
                    {
                        "transfer_id": transfer.transfer_id,
                        "from": transfer.sender,
                        "file_name": transfer.name,
                        "message": "incoming transfer expired",
                    },
                )

    async def abort_session(self, session_id: str, reason: str = "session_ended") -> None:
        keys = [
            key for key, transfer in self._incoming.items()
            if transfer.session_id == session_id
        ]
        for key in keys:
            transfer = self._incoming.get(key)
            await self._discard(key)
            if transfer is not None:
                self._emit(
                    "file_transfer_aborted",
                    {
                        "transfer_id": transfer.transfer_id,
                        "from": transfer.sender,
                        "reason": reason,
                    },
                )

    async def abort_all(self, reason: str = "disconnected") -> None:
        keys = list(self._incoming)
        for key in keys:
            transfer = self._incoming.get(key)
            await self._discard(key)
            if transfer is not None:
                self._emit(
                    "file_transfer_aborted",
                    {
                        "transfer_id": transfer.transfer_id,
                        "from": transfer.sender,
                        "reason": reason,
                    },
                )

    async def _handle_start(
        self,
        key: tuple[str, str, str],
        session_id: str,
        sender: str,
        body: dict,
    ) -> None:
        transfer_id = _required_string(body, "transfer_id")
        if key[2] != transfer_id:
            raise FileTransferError("invalid transfer ID")

        if key in self._incoming:
            raise FileTransferError("duplicate transfer ID")

        raw_name = _required_string(body, "name")
        name = _safe_filename(raw_name)
        size = _nonnegative_int(body.get("size"), "size")
        chunk_size = _nonnegative_int(body.get("chunk_size"), "chunk_size")
        chunks = _nonnegative_int(body.get("chunks"), "chunks")

        if size > self.max_file_size:
            raise FileTransferError(
                f"incoming file is {size} bytes; limit is {self.max_file_size}"
            )
        if not MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE:
            raise FileTransferError("invalid chunk size")

        expected_chunks = math.ceil(size / chunk_size) if size else 0
        if chunks != expected_chunks or chunks > MAX_FILE_CHUNKS:
            raise FileTransferError("invalid chunk count")

        temp_path = await asyncio.to_thread(_create_temp_file, self.download_dir)
        self._incoming[key] = _IncomingTransfer(
            session_id=session_id,
            sender=sender,
            transfer_id=transfer_id,
            name=name,
            size=size,
            chunk_size=chunk_size,
            chunks=chunks,
            temp_path=temp_path,
        )

        self._emit(
            "file_receive_started",
            {
                "transfer_id": transfer_id,
                "from": sender,
                "file_name": name,
                "size": size,
            },
        )

    async def _handle_chunk(
        self,
        key: tuple[str, str, str],
        body: dict,
    ) -> None:
        transfer = self._incoming.get(key)
        if transfer is None:
            raise FileTransferError("chunk received for an unknown transfer")

        index = _nonnegative_int(body.get("index"), "index")
        if index != transfer.next_index or index >= transfer.chunks:
            raise FileTransferError("unexpected chunk index")

        encoded = body.get("data")
        if not isinstance(encoded, str):
            raise FileTransferError("chunk data must be Base64 text")

        expected_size = min(
            transfer.chunk_size,
            transfer.size - transfer.received,
        )
        if expected_size <= 0:
            raise FileTransferError("unexpected extra chunk")

        max_encoded_length = 4 * math.ceil(expected_size / 3) + 4
        if len(encoded) > max_encoded_length:
            raise FileTransferError("encoded chunk is too large")

        try:
            chunk = base64.b64decode(encoded, validate=True)
        except Exception as exc:
            raise FileTransferError("chunk is not valid Base64") from exc

        if len(chunk) != expected_size:
            raise FileTransferError("chunk has an unexpected size")

        await asyncio.to_thread(_append_bytes, transfer.temp_path, chunk)

        transfer.digest.update(chunk)
        transfer.received += len(chunk)
        transfer.next_index += 1
        transfer.last_activity = time.monotonic()

        if transfer.next_index % 4 == 0 or transfer.received == transfer.size:
            self._emit(
                "file_progress",
                {
                    "direction": "incoming",
                    "transfer_id": transfer.transfer_id,
                    "from": transfer.sender,
                    "file_name": transfer.name,
                    "bytes_transferred": transfer.received,
                    "total_bytes": transfer.size,
                },
            )

    async def _handle_end(
        self,
        key: tuple[str, str, str],
        body: dict,
    ) -> None:
        transfer = self._incoming.get(key)
        if transfer is None:
            raise FileTransferError("end received for an unknown transfer")

        final_size = _nonnegative_int(body.get("size"), "size")
        final_chunks = _nonnegative_int(body.get("chunks"), "chunks")
        digest_text = body.get("sha256")

        if (
            final_size != transfer.size
            or transfer.received != transfer.size
            or final_chunks != transfer.chunks
            or transfer.next_index != transfer.chunks
        ):
            raise FileTransferError("file transfer ended with missing or extra data")

        if (
            not isinstance(digest_text, str)
            or not re.fullmatch(r"[0-9a-fA-F]{64}", digest_text)
            or not hmac.compare_digest(transfer.digest.hexdigest(), digest_text.lower())
        ):
            raise FileTransferError("file checksum does not match")

        destination = await asyncio.to_thread(
            _publish_file,
            transfer.temp_path,
            self.download_dir,
            transfer.name,
        )
        self._incoming.pop(key, None)

        self._emit(
            "file_received",
            {
                "transfer_id": transfer.transfer_id,
                "from": transfer.sender,
                "file_name": transfer.name,
                "path": str(destination),
                "size": transfer.size,
            },
        )

    async def _discard(self, key: tuple[str, str, str]) -> None:
        transfer = self._incoming.pop(key, None)
        if transfer is not None:
            await asyncio.to_thread(_unlink_file, transfer.temp_path)

    def _emit(self, event_name: str, payload: dict[str, Any]) -> None:
        self._emit_callback(event_name, payload)


def _required_string(data: dict, key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise FileTransferError(f"field {key!r} must be a non-empty string")
    return value


def _nonnegative_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise FileTransferError(f"field {field_name!r} must be a non-negative integer")
    return value


def _safe_filename(name: str) -> str:
    name = name.replace("\\", "/").split("/")[-1]
    name = "".join(
        "_" if ord(char) < 32 or char in '<>:"/\\|?*' else char
        for char in name
    )
    name = name.strip().strip(".")

    if not name:
        name = "received-file"

    name = name[:180]
    reserved = {"CON", "PRN", "AUX", "NUL"}
    reserved.update(f"COM{i}" for i in range(1, 10))
    reserved.update(f"LPT{i}" for i in range(1, 10))
    if name.split(".", 1)[0].upper() in reserved:
        name = f"_{name}"

    return name


def _open_and_size(path: Path):
    file_obj = open(path, "rb")
    try:
        info = os.fstat(file_obj.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise FileTransferError("only regular files can be sent")
        return file_obj, info.st_size
    except Exception:
        file_obj.close()
        raise


def _create_temp_file(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    fd, filename = tempfile.mkstemp(
        prefix=".incoming-",
        suffix=".part",
        dir=str(directory),
    )
    os.close(fd)
    return Path(filename)


def _append_bytes(path: Path, data: bytes) -> None:
    with open(path, "ab") as file_obj:
        file_obj.write(data)


def _unlink_file(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def _publish_file(temp_path: Path, directory: Path, name: str) -> Path:
    """Reserve a non-existing destination name, then atomically move the file."""
    stem, suffix = os.path.splitext(name)

    for index in range(10_000):
        candidate_name = name if index == 0 else f"{stem} ({index}){suffix}"
        candidate = directory / candidate_name

        try:
            fd = os.open(
                str(candidate),
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                0o600,
            )
        except FileExistsError:
            continue

        os.close(fd)
        try:
            os.replace(temp_path, candidate)
        except BaseException:
            _unlink_file(candidate)
            raise

        return candidate

    raise FileTransferError("could not find an available destination filename")