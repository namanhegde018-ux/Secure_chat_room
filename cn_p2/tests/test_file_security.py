import os
import pytest
from cryptography.exceptions import InvalidTag
from file_security.secure_transfer import encrypt_file, decrypt_file


def test_chunked_file_round_trip_and_tampering(tmp_path):
    plain = tmp_path / "source.bin"
    sealed = tmp_path / "sealed.bin"
    restored = tmp_path / "restored.bin"
    plain.write_bytes(os.urandom(140_000))
    key = os.urandom(32)
    encrypt_file(plain, sealed, key, "session", "transfer")
    decrypt_file(sealed, restored, key, "session", "transfer")
    assert restored.read_bytes() == plain.read_bytes()
    broken = bytearray(sealed.read_bytes())
    broken[30] ^= 1
    bad = tmp_path / "broken.bin"
    bad.write_bytes(broken)
    with pytest.raises(InvalidTag):
        decrypt_file(bad, tmp_path / "should-not-exist", key, "session", "transfer")


def test_wrong_transfer_context_and_empty_file(tmp_path):
    plain = tmp_path / "empty"
    plain.write_bytes(b"")
    sealed = tmp_path / "empty.sealed"
    key = os.urandom(32)
    encrypt_file(plain, sealed, key, "session", "transfer")
    restored = tmp_path / "empty-restored"
    decrypt_file(sealed, restored, key, "session", "transfer")
    assert restored.read_bytes() == b""
    with pytest.raises(InvalidTag):
        decrypt_file(sealed, tmp_path / "wrong-context", key, "session", "other")


def _records(blob):
    total = int.from_bytes(blob[12:16], "big")
    offset = 16
    chunks = []
    for _ in range(total):
        length = int.from_bytes(blob[offset:offset + 4], "big")
        end = offset + 4 + length
        chunks.append(blob[offset:end])
        offset = end
    return blob[:16], chunks, blob[offset:]


def test_reordered_duplicated_and_missing_chunks_rejected(tmp_path):
    source, sealed = tmp_path / "source", tmp_path / "sealed"
    source.write_bytes(os.urandom(150_000))
    key = os.urandom(32)
    encrypt_file(source, sealed, key, "sid", "tid")
    header, chunks, digest = _records(sealed.read_bytes())
    variants = [header + chunks[1] + chunks[0] + chunks[2] + digest,
                header + chunks[0] + chunks[0] + chunks[2] + digest,
                header + chunks[0] + chunks[2] + digest]
    for i, variant in enumerate(variants):
        altered = tmp_path / f"altered-{i}"
        altered.write_bytes(variant)
        with pytest.raises((InvalidTag, ValueError)):
            decrypt_file(altered, tmp_path / f"out-{i}", key, "sid", "tid")


def test_stale_transfer_temp_files_are_scavenged(tmp_path):
    from file_security.secure_transfer import cleanup_stale_transfer_files
    stale = tmp_path / "sm-recv-abandoned"
    other = tmp_path / "keep-me.tmp"
    stale.write_bytes(b"partial")
    other.write_bytes(b"unrelated")
    assert cleanup_stale_transfer_files(tmp_path, older_than_seconds=0) == 1
    assert not stale.exists()
    assert other.exists()
