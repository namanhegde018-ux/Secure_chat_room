"""
File transfer (Phase 5) and sender-approved export (Phase 6) for the client core.

All bodies in this module travel inside the end-to-end encrypted session channel.
The core seals every body whose kind starts with "file_" or "export_". The server
only relays ciphertext.

Transfer (sender -> receiver):
    file_start   receiver validates limits and creates a partial file in temp storage
    file_chunk*  receiver checks order and duplicates, writes, and hashes
    file_end     receiver verifies size and SHA-256, publishes the file, sends file_ack
    file_ack     sender marks the transfer delivered
    file_abort   either side cancels; the receiver deletes its partial file

Export (receiver asks, sender decides):
    export_request    receiver -> sender
    export_decision   sender -> receiver (approved or rejected)

Temporary storage and export are separate operations. Received files stay in temp
storage until the sender approves an export. Export is an application-level control
only. It cannot stop the recipient from photographing the screen, capturing memory,
or using a modified client. Do not describe it as copy protection.

Naming: the design document's file_id and total_chunks correspond to the wire
fields transfer_id and chunks.
"""
from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import hmac
import logging
import os
import re
import secrets
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO, Callable, Optional

from temp_manager import TempManager, TempStorageError

log = logging.getLogger(__name__)

MIN_CHUNK_SIZE = 1024
MAX_CHUNK_SIZE = 64 * 1024
DEFAULT_CHUNK_SIZE = 48 * 1024              # base64 inflates this to ~64 KiB, under the 1 MiB frame limit
DEFAULT_MAX_FILE_SIZE = 1024 ** 3
DEFAULT_MAX_CONCURRENT = 3
DEFAULT_STALL_TIMEOUT = 120.0               # no progress for this long -> transfer fails
DEFAULT_TRANSFER_TIMEOUT = 30 * 60.0        # hard limit for one transfer
MAX_QUEUED_FRAMES = 32                      # sender pauses while the outbound queue is longer
BACKPRESSURE_POLL = 0.02
PROGRESS_EVERY = 8                          # emit progress every N chunks
COPY_BLOCK = 64 * 1024
MAX_NAME_LENGTH = 200

_MAX_B64_LEN = ((MAX_CHUNK_SIZE + 2) // 3) * 4
_TRANSFER_ID_RE = re.compile(r"[A-Za-z0-9_\-]{8,64}")
_SHA256_HEX_RE = re.compile(r"[0-9a-f]{64}")
_UNSAFE_NAME_RE = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
_WINDOWS_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}

FILE_KINDS = frozenset({"file_start", "file_chunk", "file_end", "file_abort", "file_ack"})
EXPORT_KINDS = frozenset({"export_request", "export_decision"})
HANDLED_KINDS = FILE_KINDS | EXPORT_KINDS

_ACTIVE_OUT = ("sending", "awaiting_ack")


class FileTransferError(Exception):
    """Local transfer failure."""


class ProtocolError(FileTransferError):
    """The peer sent a malformed or unexpected message."""


class ExportError(FileTransferError):
    """Export request, decision, or copy failed."""


class _Cancelled(FileTransferError):
    """Internal: the transfer was cancelled while the sender loop was running."""


# ----- records ---------------------------------------------------------------

@dataclass
class _Outgoing:
    transfer_id: str
    session_id: str
    peer_id: str
    name: str
    size: int
    chunk_size: int
    chunks: int
    started_at: float
    last_activity: float
    state: str = "sending"          # sending | awaiting_ack | delivered | failed | aborted
    cancelled: bool = False
    export_state: str = "none"      # sender's view: none | requested | approved | rejected


@dataclass
class _Incoming:
    transfer_id: str
    session_id: str
    peer_id: str
    name: str
    size: int
    chunk_size: int
    chunks: int
    part_path: Path
    fh: BinaryIO
    started_at: float
    last_activity: float
    hasher: Any = field(default_factory=hashlib.sha256)
    digests: list = field(default_factory=list)     # SHA-256 of each accepted chunk, by index
    bytes_written: int = 0


@dataclass
class _Received:
    transfer_id: str
    session_id: str
    peer_id: str
    name: str
    size: int
    sha256: str
    path: Path                      # location in temporary storage
    export_state: str = "none"      # receiver's view: none | requested | approved | rejected


# ----- helpers ---------------------------------------------------------------

def _chunk_count(size: int, chunk_size: int) -> int:
    return (size + chunk_size - 1) // chunk_size


def _chunk_len(size: int, chunk_size: int, index: int, chunks: int) -> int:
    if index == chunks - 1:
        return size - index * chunk_size
    return chunk_size


def _safe_filename(name: str) -> str:
    base = os.path.basename(str(name).replace("\\", "/"))
    base = _UNSAFE_NAME_RE.sub("_", base).strip(" .")
    if not base:
        base = "file"
    stem, ext = os.path.splitext(base)
    if stem.upper() in _WINDOWS_RESERVED:
        stem = "_" + stem
    ext = ext[:20]
    stem = stem[: MAX_NAME_LENGTH - len(ext)] or "file"
    return stem + ext


def _publish_path(directory: Path, name: str) -> Path:
    """Create an empty file with a collision-free name and return its path.

    The caller replaces the placeholder atomically with os.replace().
    """
    stem, ext = os.path.splitext(name)
    candidate = directory / name
    counter = 1
    while True:
        try:
            fd = os.open(candidate, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            counter += 1
            candidate = directory / f"{stem} ({counter}){ext}"
            continue
        os.close(fd)
        return candidate


def _copy_verified(src: Path, target_dir: Path, name: str, expected_sha256: str) -> Path:
    """Copy src into target_dir, hashing while copying. Runs in a worker thread."""
    fd, tmp_name = tempfile.mkstemp(prefix=".export-", suffix=".part", dir=target_dir)
    tmp = Path(tmp_name)
    digest = hashlib.sha256()
    try:
        with os.fdopen(fd, "wb") as out, open(src, "rb") as inp:
            while True:
                block = inp.read(COPY_BLOCK)
                if not block:
                    break
                digest.update(block)
                out.write(block)
            out.flush()
            os.fsync(out.fileno())
        if not hmac.compare_digest(digest.hexdigest(), expected_sha256):
            raise ExportError("temporary file failed its integrity check")
        final = _publish_path(target_dir, name)
        os.replace(tmp, final)
        return final
    except BaseException:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise


def _str_field(body: dict, key: str, max_len: int = 256) -> str:
    value = body.get(key)
    if not isinstance(value, str) or not value or len(value) > max_len:
        raise ProtocolError(f"invalid field '{key}'")
    return value


def _int_field(body: dict, key: str, lo: int = 0, hi: Optional[int] = None) -> int:
    value = body.get(key)
    if type(value) is not int or value < lo or (hi is not None and value > hi):
        raise ProtocolError(f"invalid field '{key}'")
    return value


def _transfer_id(body: dict) -> str:
    value = body.get("transfer_id")
    if not isinstance(value, str) or not _TRANSFER_ID_RE.fullmatch(value):
        raise ProtocolError("invalid transfer_id")
    return value


def _b64_field(body: dict, key: str) -> bytes:
    value = body.get(key)
    if not isinstance(value, str) or len(value) > _MAX_B64_LEN:
        raise ProtocolError(f"invalid field '{key}'")
    try:
        return base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise ProtocolError("invalid base64 data") from exc


def _reason(body: dict) -> str:
    value = body.get("reason")
    return value[:200] if isinstance(value, str) else "aborted"


def _check_party(exp_session: str, exp_peer: str, session_id: str, peer: str) -> None:
    if exp_session != session_id or exp_peer != peer:
        raise ProtocolError("message from unexpected party")


# ----- manager ---------------------------------------------------------------

class FileTransferManager:
    """
    Sends and receives files and handles export approval for one client.

    Threading: every method runs on the asyncio loop thread of the client core.
    The core marshals UI commands onto that loop (run_coroutine_threadsafe or
    call_soon_threadsafe). Events are emitted on the loop thread; the EventEmitter
    forwards them to the UI thread.

    send_body(session_id, body): seals the body for the session and enqueues it.
        Must raise on failure. Called on the loop thread.
    emit(event_name, payload): publishes an event.
    send_backlog(): optional; returns the number of frames waiting in the outbound
        queue, so the sender can pause instead of flooding memory.
    """

    def __init__(
        self,
        send_body: Callable[[str, dict], None],
        emit: Callable[[str, dict], None],
        temp: TempManager,
        download_dir: str | os.PathLike = "downloads",
        *,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        max_concurrent: int = DEFAULT_MAX_CONCURRENT,
        stall_timeout: float = DEFAULT_STALL_TIMEOUT,
        transfer_timeout: float = DEFAULT_TRANSFER_TIMEOUT,
        send_backlog: Optional[Callable[[], int]] = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE:
            raise ValueError(f"chunk_size must be between {MIN_CHUNK_SIZE} and {MAX_CHUNK_SIZE}")
        if max_file_size <= 0 or max_concurrent < 1:
            raise ValueError("max_file_size must be positive and max_concurrent at least 1")

        self._send_body = send_body
        self._emit = emit
        self._temp = temp
        self.download_dir = Path(download_dir)
        self.chunk_size = chunk_size
        self.max_file_size = max_file_size
        self.max_concurrent = max_concurrent
        self.stall_timeout = stall_timeout
        self.transfer_timeout = transfer_timeout
        self._backlog = send_backlog
        self._clock = clock

        self._outgoing: dict[str, _Outgoing] = {}
        self._incoming: dict[str, _Incoming] = {}
        self._received: dict[str, _Received] = {}
        self._handlers = {
            "file_start": self._on_file_start,
            "file_chunk": self._on_file_chunk,
            "file_end": self._on_file_end,
            "file_abort": self._on_file_abort,
            "file_ack": self._on_file_ack,
            "export_request": self._on_export_request,
            "export_decision": self._on_export_decision,
        }

    # ===== sending (Phase 5) ================================================

    async def send_file(self, path: str | os.PathLike, session_id: str, peer_id: str) -> str:
        """Stream a file to the peer. Returns the transfer id once file_end is sent.

        The file is read in worker threads and hashed while streaming, so it is read once.
        """
        src = Path(path)
        if not src.is_file():
            raise FileTransferError(f"not a regular file: {src}")
        size = src.stat().st_size
        if size > self.max_file_size:
            raise FileTransferError("file exceeds the maximum allowed size")
        if self._count_active_outgoing() >= self.max_concurrent:
            raise FileTransferError("too many concurrent outgoing transfers")

        cs = self.chunk_size
        chunks = _chunk_count(size, cs)
        tid = secrets.token_urlsafe(16)
        now = self._clock()
        out = _Outgoing(
            transfer_id=tid, session_id=session_id, peer_id=peer_id,
            name=_safe_filename(src.name), size=size, chunk_size=cs, chunks=chunks,
            started_at=now, last_activity=now,
        )
        self._outgoing[tid] = out
        digest = hashlib.sha256()

        try:
            self._send_body(session_id, {
                "kind": "file_start", "transfer_id": tid, "name": out.name,
                "size": size, "chunk_size": cs, "chunks": chunks,
            })
            with open(src, "rb") as fh:
                for index in range(chunks):
                    await self._wait_for_capacity(out)
                    expected = _chunk_len(size, cs, index, chunks)
                    data = await asyncio.to_thread(fh.read, expected)
                    self._check_outgoing(out)
                    if len(data) != expected:
                        raise FileTransferError("file changed during transfer")
                    digest.update(data)
                    self._send_body(session_id, {
                        "kind": "file_chunk", "transfer_id": tid, "index": index,
                        "data": base64.b64encode(data).decode("ascii"),
                    })
                    out.last_activity = self._clock()
                    if index % PROGRESS_EVERY == 0 or index == chunks - 1:
                        self._progress("send", out, index + 1, min((index + 1) * cs, size))
                    await asyncio.sleep(0)   # let other loop work run between chunks
                if await asyncio.to_thread(fh.read, 1):
                    raise FileTransferError("file grew during transfer")
            self._check_outgoing(out)
            out.state = "awaiting_ack"
            out.last_activity = self._clock()
            self._send_body(session_id, {
                "kind": "file_end", "transfer_id": tid, "size": size,
                "chunks": chunks, "sha256": digest.hexdigest(),
            })
        except _Cancelled:
            return tid                       # the canceller already emitted the abort event
        except Exception as exc:
            reason = str(exc) if isinstance(exc, FileTransferError) else f"local error: {type(exc).__name__}"
            self._fail_outgoing(out, reason)
            raise
        return tid

    async def _wait_for_capacity(self, out: _Outgoing) -> None:
        self._check_outgoing(out)
        if self._backlog is None:
            return
        waited = 0.0
        while self._backlog() > MAX_QUEUED_FRAMES:
            if waited >= self.stall_timeout:
                raise FileTransferError("network congested; transfer stalled")
            await asyncio.sleep(BACKPRESSURE_POLL)
            waited += BACKPRESSURE_POLL
            self._check_outgoing(out)

    def _check_outgoing(self, out: _Outgoing) -> None:
        if out.cancelled:
            raise _Cancelled("cancelled")
        if self._clock() - out.started_at > self.transfer_timeout:
            raise FileTransferError("transfer timed out")

    def _fail_outgoing(self, out: _Outgoing, reason: str) -> None:
        if self._outgoing.get(out.transfer_id) is not out:
            return                           # already removed by close_session
        out.state = "failed"
        out.cancelled = True
        self._safe_send(out.session_id, {
            "kind": "file_abort", "transfer_id": out.transfer_id, "reason": reason[:200],
        })
        self._emit("file_transfer_error", {
            "transfer_id": out.transfer_id, "session_id": out.session_id, "peer": out.peer_id,
            "direction": "send", "name": out.name, "reason": reason,
        })

    def _count_active_outgoing(self) -> int:
        return sum(1 for o in self._outgoing.values() if o.state in _ACTIVE_OUT)

    # ===== receiving (Phase 5) ==============================================

    def handle_relay(self, session_id: str, sender_id: str, body: dict) -> bool:
        """Dispatch a decrypted file_* or export_* body. Returns True if it was handled."""
        if not isinstance(body, dict):
            return False
        kind = body.get("kind")
        if not isinstance(kind, str):
            return False
        handler = self._handlers.get(kind)
        if handler is None:
            return False
        try:
            handler(session_id, sender_id, body)
        except ProtocolError as exc:
            log.warning("protocol violation from %s: %s", sender_id, exc)
            self._emit("file_transfer_error", {
                "session_id": session_id, "peer": sender_id,
                "direction": "protocol", "reason": str(exc),
            })
        except Exception:
            log.exception("unexpected error handling %s", kind)
            self._emit("file_transfer_error", {
                "session_id": session_id, "peer": sender_id,
                "direction": "protocol", "reason": "internal error",
            })
        return True

    def _on_file_start(self, sid: str, peer: str, body: dict) -> None:
        tid = _transfer_id(body)
        if tid in self._incoming or tid in self._received or tid in self._outgoing:
            raise ProtocolError("duplicate transfer id")
        name = _safe_filename(_str_field(body, "name", 512))
        size = _int_field(body, "size", 0)
        cs = _int_field(body, "chunk_size", MIN_CHUNK_SIZE, MAX_CHUNK_SIZE)
        chunks = _int_field(body, "chunks", 0)
        if chunks != _chunk_count(size, cs):
            raise ProtocolError("chunk count does not match file size")

        if size > self.max_file_size:
            return self._reject_incoming(sid, peer, tid, name, "file exceeds the maximum allowed size")
        if len(self._incoming) >= self.max_concurrent:
            return self._reject_incoming(sid, peer, tid, name, "too many concurrent incoming transfers")
        try:
            fd, part = tempfile.mkstemp(prefix=".incoming-", suffix=".part",
                                        dir=self._temp.received_dir(sid))
        except (TempStorageError, OSError):
            return self._reject_incoming(sid, peer, tid, name, "local storage unavailable")

        now = self._clock()
        inc = _Incoming(
            transfer_id=tid, session_id=sid, peer_id=peer, name=name, size=size,
            chunk_size=cs, chunks=chunks, part_path=Path(part),
            fh=os.fdopen(fd, "wb"), started_at=now, last_activity=now,
        )
        self._incoming[tid] = inc
        self._temp.touch(sid)
        self._emit("file_receive_started", {
            "transfer_id": tid, "session_id": sid, "from": peer,
            "name": name, "size": size, "chunks": chunks,
        })

    def _on_file_chunk(self, sid: str, peer: str, body: dict) -> None:
        inc = self._incoming_for(sid, peer, body)
        if inc is None:
            return                            # late chunk after an abort: ignore
        index = _int_field(body, "index", 0)
        data = _b64_field(body, "data")
        digest = hashlib.sha256(data).digest()

        if index < len(inc.digests):          # duplicate detection
            if hmac.compare_digest(inc.digests[index], digest):
                return                        # identical duplicate: harmless
            return self._abort_incoming(inc, "conflicting duplicate chunk")
        if index != len(inc.digests):         # ordering
            return self._abort_incoming(inc, "chunk out of order")
        if index >= inc.chunks or len(data) != _chunk_len(inc.size, inc.chunk_size, index, inc.chunks):
            return self._abort_incoming(inc, "chunk has unexpected size")

        try:
            inc.fh.write(data)
        except OSError:
            return self._abort_incoming(inc, "local storage error")
        inc.hasher.update(data)
        inc.digests.append(digest)
        inc.bytes_written += len(data)
        inc.last_activity = self._clock()
        self._temp.touch(sid)
        done = len(inc.digests)
        if done % PROGRESS_EVERY == 0 or done == inc.chunks:
            self._progress("receive", inc, done, inc.bytes_written)

    def _on_file_end(self, sid: str, peer: str, body: dict) -> None:
        inc = self._incoming_for(sid, peer, body)
        if inc is None:
            return
        size = _int_field(body, "size", 0)
        chunks = _int_field(body, "chunks", 0)
        claimed = _str_field(body, "sha256", 64).lower()
        if not _SHA256_HEX_RE.fullmatch(claimed):
            raise ProtocolError("invalid sha256")

        if (size, chunks) != (inc.size, inc.chunks) or len(inc.digests) != inc.chunks \
                or inc.bytes_written != inc.size:
            return self._abort_incoming(inc, "incomplete transfer")
        if not hmac.compare_digest(inc.hasher.hexdigest(), claimed):
            return self._abort_incoming(inc, "hash mismatch")

        try:
            inc.fh.flush()
            os.fsync(inc.fh.fileno())
            inc.fh.close()
            final = _publish_path(self._temp.received_dir(sid), inc.name)
            os.replace(inc.part_path, final)
        except (OSError, TempStorageError):
            return self._abort_incoming(inc, "local storage error")

        del self._incoming[inc.transfer_id]
        self._received[inc.transfer_id] = _Received(
            transfer_id=inc.transfer_id, session_id=sid, peer_id=peer, name=inc.name,
            size=inc.size, sha256=claimed, path=final,
        )
        self._temp.touch(sid)
        self._safe_send(sid, {"kind": "file_ack", "transfer_id": inc.transfer_id})
        self._emit("file_received", {
            "transfer_id": inc.transfer_id, "session_id": sid, "from": peer,
            "name": inc.name, "size": inc.size, "path": str(final),
            "export_state": "none",
        })

    def _on_file_ack(self, sid: str, peer: str, body: dict) -> None:
        out = self._outgoing_for(sid, peer, body)
        if out is None:
            return
        if out.state != "awaiting_ack":
            raise ProtocolError("unexpected acknowledgement")
        out.state = "delivered"
        out.last_activity = self._clock()
        self._emit("file_sent", {
            "transfer_id": out.transfer_id, "session_id": sid, "peer": peer,
            "name": out.name, "size": out.size,
        })

    def _on_file_abort(self, sid: str, peer: str, body: dict) -> None:
        tid = _transfer_id(body)
        reason = _reason(body)
        inc = self._incoming.get(tid)
        if inc is not None:
            _check_party(inc.session_id, inc.peer_id, sid, peer)
            return self._abort_incoming(inc, f"peer aborted: {reason}", notify_peer=False)
        out = self._outgoing.get(tid)
        if out is not None and out.state in _ACTIVE_OUT:
            _check_party(out.session_id, out.peer_id, sid, peer)
            out.cancelled = True
            out.state = "aborted"
            self._emit("file_transfer_aborted", {
                "transfer_id": tid, "session_id": sid, "peer": peer,
                "direction": "send", "name": out.name, "reason": f"peer aborted: {reason}",
            })

    def _reject_incoming(self, sid: str, peer: str, tid: str, name: str, reason: str) -> None:
        self._safe_send(sid, {"kind": "file_abort", "transfer_id": tid, "reason": reason})
        self._emit("file_transfer_aborted", {
            "transfer_id": tid, "session_id": sid, "peer": peer,
            "direction": "receive", "name": name, "reason": reason,
        })

    def _abort_incoming(self, inc: _Incoming, reason: str, *, notify_peer: bool = True) -> None:
        if self._incoming.get(inc.transfer_id) is inc:
            del self._incoming[inc.transfer_id]
        with contextlib.suppress(Exception):
            inc.fh.close()
        with contextlib.suppress(OSError):
            inc.part_path.unlink()           # incomplete transfer cleanup
        if notify_peer:
            self._safe_send(inc.session_id, {
                "kind": "file_abort", "transfer_id": inc.transfer_id, "reason": reason[:200],
            })
        self._emit("file_transfer_aborted", {
            "transfer_id": inc.transfer_id, "session_id": inc.session_id, "peer": inc.peer_id,
            "direction": "receive", "name": inc.name, "reason": reason,
        })

    def _incoming_for(self, sid: str, peer: str, body: dict) -> Optional[_Incoming]:
        tid = _transfer_id(body)
        inc = self._incoming.get(tid)
        if inc is not None:
            _check_party(inc.session_id, inc.peer_id, sid, peer)
        return inc

    def _outgoing_for(self, sid: str, peer: str, body: dict) -> Optional[_Outgoing]:
        tid = _transfer_id(body)
        out = self._outgoing.get(tid)
        if out is not None:
            _check_party(out.session_id, out.peer_id, sid, peer)
        return out

    def _progress(self, direction: str, rec: Any, chunks_done: int, bytes_done: int) -> None:
        self._emit("file_progress", {
            "transfer_id": rec.transfer_id, "session_id": rec.session_id,
            "direction": direction, "chunks_done": chunks_done,
            "chunks_total": rec.chunks, "bytes_done": bytes_done, "size": rec.size,
        })

    def _safe_send(self, session_id: str, body: dict) -> None:
        try:
            self._send_body(session_id, body)
        except Exception:
            log.debug("could not send %s", body.get("kind"), exc_info=True)

    # ===== export (Phase 6) =================================================

    def request_export(self, transfer_id: str) -> None:
        """Receiver asks the sender for permission to export a received file."""
        rec = self._received.get(transfer_id)
        if rec is None:
            raise ExportError("unknown transfer")
        if rec.export_state == "requested":
            raise ExportError("export request already pending")
        if rec.export_state == "approved":
            raise ExportError("export already approved")
        self._send_body(rec.session_id, {"kind": "export_request", "transfer_id": transfer_id})
        rec.export_state = "requested"
        self._emit("export_request_sent", {
            "transfer_id": transfer_id, "session_id": rec.session_id,
            "peer": rec.peer_id, "name": rec.name,
        })

    def respond_export(self, transfer_id: str, approved: bool) -> None:
        """Sender approves or rejects a pending export request for a file it sent."""
        out = self._outgoing.get(transfer_id)
        if out is None:
            raise ExportError("unknown transfer")
        if out.export_state != "requested":
            raise ExportError("no pending export request for this transfer")
        decision = bool(approved)
        self._send_body(out.session_id, {
            "kind": "export_decision", "transfer_id": transfer_id, "approved": decision,
        })
        out.export_state = "approved" if decision else "rejected"
        self._emit("export_decided", {
            "transfer_id": transfer_id, "session_id": out.session_id,
            "peer": out.peer_id, "approved": decision,
        })

    async def export_file(self, transfer_id: str, dest_dir: str | os.PathLike | None = None) -> Path:
        """Copy an approved file from temporary storage to the permanent download folder.

        The copy is hashed and compared with the recorded SHA-256. The copy runs in a
        worker thread.
        """
        rec = self._received.get(transfer_id)
        if rec is None:
            raise ExportError("unknown transfer")
        if rec.export_state != "approved":
            raise ExportError("export has not been approved by the sender")
        if not rec.path.is_file():
            raise ExportError("temporary file is no longer available")
        target = Path(dest_dir) if dest_dir is not None else self.download_dir
        try:
            target.mkdir(parents=True, exist_ok=True)
            final = await asyncio.to_thread(_copy_verified, rec.path, target, rec.name, rec.sha256)
        except (OSError, ExportError) as exc:
            self._emit("export_error", {"transfer_id": transfer_id, "reason": str(exc)})
            raise ExportError(f"export failed: {exc}") from exc
        self._emit("file_exported", {
            "transfer_id": transfer_id, "session_id": rec.session_id,
            "name": rec.name, "path": str(final),
        })
        return final

    def _on_export_request(self, sid: str, peer: str, body: dict) -> None:
        # This client is the sender of the file.
        tid = _transfer_id(body)
        out = self._outgoing.get(tid)
        if out is None:
            raise ProtocolError("export requested for unknown transfer")
        _check_party(out.session_id, out.peer_id, sid, peer)
        if out.state != "delivered":
            raise ProtocolError("export requested before the transfer was confirmed")
        if out.export_state == "requested":
            return                            # duplicate request
        if out.export_state == "approved":
            self._safe_send(sid, {"kind": "export_decision", "transfer_id": tid, "approved": True})
            return
        out.export_state = "requested"
        self._emit("export_requested", {
            "transfer_id": tid, "session_id": sid, "peer": peer,
            "name": out.name, "size": out.size,
        })

    def _on_export_decision(self, sid: str, peer: str, body: dict) -> None:
        # This client is the receiver of the file.
        tid = _transfer_id(body)
        approved = body.get("approved")
        if type(approved) is not bool:
            raise ProtocolError("invalid field 'approved'")
        rec = self._received.get(tid)
        if rec is None:
            raise ProtocolError("export decision for unknown transfer")
        _check_party(rec.session_id, rec.peer_id, sid, peer)
        if rec.export_state != "requested":
            raise ProtocolError("unexpected export decision")
        rec.export_state = "approved" if approved else "rejected"
        self._emit("export_approved" if approved else "export_rejected", {
            "transfer_id": tid, "session_id": sid, "peer": peer, "name": rec.name,
        })

    # ===== lifecycle and queries ============================================

    def close_session(self, session_id: str, reason: str = "session_ended") -> None:
        """Scenarios A and B: stop transfers, close handles, delete temp data, drop state.

        Exported copies in the download folder are not touched. They were approved and
        are permanent by design.
        """
        for tid, out in list(self._outgoing.items()):
            if out.session_id != session_id:
                continue
            if out.state in _ACTIVE_OUT:
                out.cancelled = True
                out.state = "aborted"
                self._emit("file_transfer_aborted", {
                    "transfer_id": tid, "session_id": session_id, "peer": out.peer_id,
                    "direction": "send", "name": out.name, "reason": reason,
                })
            del self._outgoing[tid]
        for inc in list(self._incoming.values()):
            if inc.session_id == session_id:
                self._abort_incoming(inc, reason, notify_peer=False)
        for tid in [t for t, r in self._received.items() if r.session_id == session_id]:
            del self._received[tid]
        self._temp.cleanup_session(session_id)

    def sweep(self) -> list[str]:
        """Expire stalled transfers. Call periodically (for example from the heartbeat loop)."""
        now = self._clock()
        expired: list[str] = []
        for inc in list(self._incoming.values()):
            if now - inc.last_activity > self.stall_timeout or now - inc.started_at > self.transfer_timeout:
                self._abort_incoming(inc, "transfer timed out")
                expired.append(inc.transfer_id)
        for out in list(self._outgoing.values()):
            if out.state == "awaiting_ack" and now - out.last_activity > self.stall_timeout:
                out.state = "failed"
                self._emit("file_transfer_error", {
                    "transfer_id": out.transfer_id, "session_id": out.session_id,
                    "peer": out.peer_id, "direction": "send", "name": out.name,
                    "reason": "no acknowledgement from peer",
                })
                expired.append(out.transfer_id)
        return expired

    def received_files(self, session_id: str | None = None) -> list[dict]:
        return [
            {
                "transfer_id": r.transfer_id, "session_id": r.session_id, "peer": r.peer_id,
                "name": r.name, "size": r.size, "sha256": r.sha256,
                "path": str(r.path), "export_state": r.export_state,
            }
            for r in self._received.values()
            if session_id is None or r.session_id == session_id
        ]

    def sent_files(self, session_id: str | None = None) -> list[dict]:
        return [
            {
                "transfer_id": o.transfer_id, "session_id": o.session_id, "peer": o.peer_id,
                "name": o.name, "size": o.size, "state": o.state,
                "export_state": o.export_state,
            }
            for o in self._outgoing.values()
            if session_id is None or o.session_id == session_id
        ]