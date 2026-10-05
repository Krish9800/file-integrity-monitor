"""Streaming, memory-bounded multi-algorithm cryptographic file hashing."""

import hashlib
from pathlib import Path

from fim.config.settings import settings


class FileHashingError(Exception):
    """Raised when file hashing cannot proceed due to I/O or permissions issues."""


def hash_bytes(data: bytes) -> dict[str, str]:
    """Compute dual SHA-256 and BLAKE2b digests for in-memory byte buffers.

    Args:
        data: Raw byte string to hash.

    Returns:
        Dictionary mapping algorithm name to hex-encoded digest string.
    """
    sha256_hash = hashlib.sha256(data).hexdigest()
    blake2b_hash = hashlib.blake2b(data).hexdigest()
    return {
        "sha256": sha256_hash,
        "blake2b": blake2b_hash,
    }


def hash_file(
    file_path: Path,
    chunk_size: int | None = None,
) -> dict[str, str]:
    """Compute dual SHA-256 and BLAKE2b digests in a single streaming I/O pass.

    Guarantees O(1) constant memory consumption by reading files in chunk buffers,
    safely handling small scripts or multi-gigabyte ISOs without memory exhaustion.

    Args:
        file_path: Path to target file.
        chunk_size: Optional byte read size. Defaults to settings.HASH_CHUNK_SIZE_BYTES.

    Returns:
        Dictionary mapping algorithm names to hex digests.

    Raises:
        FileHashingError: If file is missing, inaccessible, or an unreadable device/pipe.
    """
    buffer_size = chunk_size or settings.HASH_CHUNK_SIZE_BYTES
    sha256 = hashlib.sha256()
    blake2b = hashlib.blake2b()

    try:
        with file_path.open("rb") as f:
            while chunk := f.read(buffer_size):
                sha256.update(chunk)
                blake2b.update(chunk)
    except (FileNotFoundError, PermissionError, IsADirectoryError, OSError) as exc:
        raise FileHashingError(f"Failed to hash '{file_path}': {exc}") from exc

    return {
        "sha256": sha256.hexdigest(),
        "blake2b": blake2b.hexdigest(),
    }
