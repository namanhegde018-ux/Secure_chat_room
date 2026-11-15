"""Streaming 64 KiB AES-GCM chunks with transfer/session/index binding."""

import hashlib
import os
import struct
import tempfile
import time
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CHUNK_SIZE = 64 * 1024
MAX_FILE_SIZE = 2 * 1024 * 1024 * 1024
MAGIC = b"SMF1"
STALE_TEMP_AGE_SECONDS = 24 * 60 * 60


def cleanup_stale_transfer_files(directory, *, older_than_seconds=STALE_TEMP_AGE_SECONDS) -> int:
    """Best-effort cleanup of this module's abandoned staging files in one directory."""
    root = Path(directory)
    if not root.is_dir():
        return 0
    cutoff = time.time() - max(0, older_than_seconds)
    removed = 0
    for path in root.iterdir():
        if not (path.name.startswith("sm-recv-") or path.name.startswith("sm-send-")):
            continue
        try:
            if path.is_file() and path.stat().st_mtime < cutoff:
                path.unlink()
                removed += 1
        except OSError:
            # Another transfer may still hold the file, or permissions may prevent cleanup.
            continue
    return removed


def _aad(session_id: str, transfer_id: str, index: int, total: int) -> bytes:
    return f"sm-file-v1\0{session_id}\0{transfer_id}\0{index}\0{total}".encode("utf-8")


def encrypt_file(source, destination, key: bytes, session_id: str, transfer_id: str) -> int:
    size = Path(source).stat().st_size
    if size > MAX_FILE_SIZE or not session_id or not transfer_id:
        raise ValueError("file too large or missing transfer context")
    total = max(1, (size + CHUNK_SIZE - 1) // CHUNK_SIZE)
    digest = hashlib.sha256()
    target = Path(destination)
    target.parent.mkdir(parents=True, exist_ok=True)
    cleanup_stale_transfer_files(target.parent)
    fd, temp_path = tempfile.mkstemp(prefix="sm-send-", dir=str(target.parent))
    os.close(fd)
    temp_path = Path(temp_path)
    try:
        with open(source, "rb") as src, open(temp_path, "wb") as dst:
            dst.write(MAGIC + struct.pack(">QI", size, total))
            for index in range(total):
                block = src.read(CHUNK_SIZE)
                digest.update(block)
                nonce = os.urandom(12)
                sealed = nonce + AESGCM(key).encrypt(nonce, block, _aad(session_id, transfer_id, index, total))
                dst.write(struct.pack(">I", len(sealed)))
                dst.write(sealed)
            dst.write(digest.digest())
        os.replace(temp_path, target)
    finally:
        if temp_path.exists():
            temp_path.unlink()
    return total


def decrypt_file(source, destination, key: bytes, session_id: str, transfer_id: str) -> None:
    target = Path(destination)
    target.parent.mkdir(parents=True, exist_ok=True)
    cleanup_stale_transfer_files(target.parent)
    temp_path = None
    try:
        with open(source, "rb") as src:
            if src.read(4) != MAGIC:
                raise ValueError("unsupported file transfer format")
            size, total = struct.unpack(">QI", src.read(12))
            if size > MAX_FILE_SIZE or total != max(1, (size + CHUNK_SIZE - 1) // CHUNK_SIZE):
                raise ValueError("invalid file size or chunk count")
            fd, temp_path = tempfile.mkstemp(prefix="sm-recv-", dir=str(target.parent))
            digest = hashlib.sha256()
            with os.fdopen(fd, "wb") as dst:
                written = 0
                for index in range(total):
                    raw_len = src.read(4)
                    if len(raw_len) != 4:
                        raise ValueError("missing chunk")
                    clen, = struct.unpack(">I", raw_len)
                    if clen < 28 or clen > CHUNK_SIZE + 28:
                        raise ValueError("invalid chunk length")
                    sealed = src.read(clen)
                    if len(sealed) != clen:
                        raise ValueError("truncated chunk")
                    block = AESGCM(key).decrypt(sealed[:12], sealed[12:], _aad(session_id, transfer_id, index, total))
                    expected = CHUNK_SIZE if index < total - 1 else size - written
                    if len(block) != expected:
                        raise ValueError("invalid chunk ordering or length")
                    dst.write(block)
                    digest.update(block)
                    written += len(block)
                expected_digest = src.read(32)
                if written != size or len(expected_digest) != 32 or digest.digest() != expected_digest or src.read(1):
                    raise ValueError("file integrity check failed")
        os.replace(temp_path, target)
        temp_path = None
    finally:
        if temp_path and os.path.exists(temp_path):
            os.unlink(temp_path)
