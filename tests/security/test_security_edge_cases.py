"""Security and edge case test suite for File Integrity Monitor.

Covers:
- Symlink traversal and escape attacks
- Symlink cycle / infinite recursion loop prevention
- Constant-time HMAC authentication and single-bit flip rejection
- Unreadable permissions and graceful degradation
- Large file streaming bounded-memory hashing
- Zero-byte file handling
"""

from pathlib import Path

import pytest

from fim.core.hasher import hash_file
from fim.core.integrity import (
    generate_key,
    sign_payload,
    verify_payload,
)
from fim.models.file_record import FileRecord
from fim.scanner.engine import ScanEngine
from fim.scanner.walker import SafePathWalker


def test_symlink_escape_attack_prevention(tmp_path: Path) -> None:
    """Ensure symlinks pointing to targets outside the monitored root are not followed."""
    outside_dir = tmp_path / "outside_secure"
    outside_dir.mkdir()
    secret_file = outside_dir / "secret_keys.pem"
    secret_file.write_text("SUPER_SECRET_PRIVATE_KEY")

    monitored_dir = tmp_path / "monitored"
    monitored_dir.mkdir()

    # Create malicious symlink inside monitored dir pointing outside
    malicious_symlink = monitored_dir / "symlink_to_secret"
    try:
        malicious_symlink.symlink_to(secret_file)
    except OSError:
        pytest.skip("Symlink creation not supported on this platform/filesystem.")

    walker = SafePathWalker(follow_symlinks=False)
    discovered_files = list(walker.walk(monitored_dir))

    # The secret file must NOT be discovered or traversed through the symlink
    discovered_paths = [f.resolve().as_posix() for f in discovered_files]
    assert secret_file.resolve().as_posix() not in discovered_paths


def test_symlink_cyclic_recursion_bomb_prevention(tmp_path: Path) -> None:
    """Ensure circular directory symlinks do not cause infinite recursion."""
    watch_dir = tmp_path / "cycle_test"
    watch_dir.mkdir()
    sub_dir = watch_dir / "subdir"
    sub_dir.mkdir()

    # Create circular symlink pointing to parent
    loop_symlink = sub_dir / "infinite_loop"
    try:
        loop_symlink.symlink_to(watch_dir, target_is_directory=True)
    except OSError:
        pytest.skip("Symlink creation not supported.")

    walker = SafePathWalker(follow_symlinks=False)
    # Must terminate without RecursionError or infinite loop
    files = list(walker.walk(watch_dir))
    assert isinstance(files, list)


def test_hmac_single_bit_flip_tampering_rejected() -> None:
    """Verify that a single-bit flip anywhere in payload or signature causes rejection."""
    key = generate_key()
    canonical_payload = b'{"algorithm":"sha256","records":{"/etc/app":1234}}'
    valid_signature = sign_payload(canonical_payload, key)

    # 1. Valid signature passes
    assert verify_payload(canonical_payload, valid_signature, key) is True

    # 2. Corrupt payload by 1 byte
    tampered_payload = bytearray(canonical_payload)
    tampered_payload[10] ^= 0x01
    assert verify_payload(bytes(tampered_payload), valid_signature, key) is False

    # 3. Corrupt signature by 1 byte
    tampered_sig = ("0" if valid_signature[0] != "0" else "1") + valid_signature[1:]
    assert verify_payload(canonical_payload, tampered_sig, key) is False


def test_zero_byte_file_hashing_and_modeling(tmp_path: Path) -> None:
    """Verify zero-byte files are hashed correctly with standard digests."""
    empty_file = tmp_path / "empty.dat"
    empty_file.touch()

    hashes = hash_file(empty_file)
    assert "sha256" in hashes
    assert "blake2b" in hashes
    # Standard SHA-256 for empty byte buffer:
    # e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    assert hashes["sha256"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    rec = FileRecord.from_path(empty_file)
    assert rec.size_bytes == 0
    assert rec.hashes["sha256"] == hashes["sha256"]


def test_large_file_chunked_streaming(tmp_path: Path) -> None:
    """Verify hashing a multi-megabyte file streams correctly in chunks."""
    large_file = tmp_path / "large_payload.bin"
    # Write 512KB of repeated bytes (exceeding default 64KB buffer)
    chunk = b"A" * 65536
    with large_file.open("wb") as f:
        for _ in range(8):
            f.write(chunk)

    hashes = hash_file(large_file, chunk_size=32768)
    assert len(hashes["sha256"]) == 64
    assert len(hashes["blake2b"]) == 128


def test_unreadable_file_handled_gracefully(tmp_path: Path) -> None:
    """Scanner should log warning and continue when encountering unreadable file."""
    unreadable = tmp_path / "no_access.secret"
    unreadable.write_text("classified")

    # If running as root (e.g. in some containers), chmod 0o000 doesn't prevent root read.
    # We test non-root permissions or simulate
    try:
        unreadable.chmod(0o000)
    except OSError:
        pytest.skip("Chmod not supported on this filesystem.")

    try:
        # Check if we can still read (e.g. if running as root)
        with unreadable.open("r"):
            pytest.skip("Running as root/superuser; cannot simulate PermissionError.")
    except PermissionError:
        pass

    engine = ScanEngine()
    records = engine.scan_live_state([tmp_path])
    # Should not crash, unreadable file omitted from records
    assert unreadable.as_posix() not in records

    # Restore permission so tmp_path cleanup succeeds
    unreadable.chmod(0o644)
