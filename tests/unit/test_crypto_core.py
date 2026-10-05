"""Unit tests for Phase 2 cryptographic core and HMAC integrity sealing."""

import os
import stat
from pathlib import Path

import pytest

from fim.core.hasher import FileHashingError, hash_bytes, hash_file
from fim.core.integrity import (
    IntegrityError,
    generate_key,
    load_key,
    save_key,
    sign_payload,
    verify_payload,
)


def test_hash_bytes_deterministic() -> None:
    """Ensure in-memory hashing produces valid, deterministic digests."""
    data = b"Hello, File Integrity Monitoring!"
    digests = hash_bytes(data)

    assert "sha256" in digests
    assert "blake2b" in digests
    assert len(digests["sha256"]) == 64
    assert len(digests["blake2b"]) == 128

    # Determinism check
    assert hash_bytes(data) == digests


def test_hash_file_empty_and_content(tmp_path: Path) -> None:
    """Ensure file hashing correctly digests empty files and populated files."""
    empty_file = tmp_path / "empty.txt"
    empty_file.write_bytes(b"")

    empty_digests = hash_file(empty_file)
    # Known SHA-256 for empty byte buffer
    assert (
        empty_digests["sha256"]
        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )

    populated = tmp_path / "sample.txt"
    content = b"Critical security system configuration payload"
    populated.write_bytes(content)

    digests = hash_file(populated)
    expected_memory = hash_bytes(content)
    assert digests["sha256"] == expected_memory["sha256"]
    assert digests["blake2b"] == expected_memory["blake2b"]


def test_hash_file_streaming_chunked(tmp_path: Path) -> None:
    """Verify chunked streaming hashing on data exceeding standard buffer size."""
    large_file = tmp_path / "large.bin"
    # Create 128 KB buffer (exceeding default 64 KB chunk size)
    data = os.urandom(131072)
    large_file.write_bytes(data)

    # Hash with smaller 16 KB chunks
    chunked_digests = hash_file(large_file, chunk_size=16384)
    direct_digests = hash_bytes(data)

    assert chunked_digests["sha256"] == direct_digests["sha256"]
    assert chunked_digests["blake2b"] == direct_digests["blake2b"]


def test_hash_file_error_handling(tmp_path: Path) -> None:
    """Verify FileHashingError is raised on missing file or directory target."""
    missing = tmp_path / "ghost.txt"
    with pytest.raises(FileHashingError, match="Failed to hash"):
        hash_file(missing)

    directory = tmp_path / "sub_dir"
    directory.mkdir()
    with pytest.raises(FileHashingError):
        hash_file(directory)


def test_hmac_key_lifecycle(tmp_path: Path) -> None:
    """Test generating, storing with POSIX 0600 permissions, and loading HMAC key."""
    key_file = tmp_path / "fim.key"
    key = generate_key(32)

    assert len(key) == 32

    save_key(key, key_file)
    assert key_file.exists()

    # Verify POSIX file permissions are restricted to owner rw (0o600)
    file_mode = stat.S_IMODE(key_file.stat().st_mode)
    assert file_mode == 0o600

    loaded = load_key(key_file)
    assert loaded == key

    # Test short key rejection
    with pytest.raises(IntegrityError, match="at least 32 bytes"):
        save_key(b"too_short_key", tmp_path / "bad.key")

    # Test load missing key
    with pytest.raises(IntegrityError, match="does not exist"):
        load_key(tmp_path / "missing.key")

    # Test load short key
    short_file = tmp_path / "short.key"
    short_file.write_bytes(b"short")
    with pytest.raises(IntegrityError, match="insufficiently secure"):
        load_key(short_file)


def test_hmac_sign_and_verify() -> None:
    """Verify HMAC-SHA256 signature generation and constant-time tampering detection."""
    key = generate_key(32)
    payload = b'{"files": {"/etc/passwd": "dummy_hash"}}'

    sig = sign_payload(payload, key)
    assert len(sig) == 64  # SHA-256 hex length

    # Valid payload & signature passes
    assert verify_payload(payload, sig, key) is True

    # Tampered payload fails
    tampered_payload = b'{"files": {"/etc/passwd": "MALICIOUS_HASH"}}'
    assert verify_payload(tampered_payload, sig, key) is False

    # Tampered signature fails
    corrupted_sig = sig[:-4] + "0000"
    assert verify_payload(payload, corrupted_sig, key) is False

    # Different key fails
    other_key = generate_key(32)
    assert verify_payload(payload, sig, other_key) is False
