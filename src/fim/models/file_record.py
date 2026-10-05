"""File state record representing cryptographic and POSIX metadata attributes."""

import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from fim.core.hasher import hash_file


class FileRecord(BaseModel):
    """Immutable snapshot of a file's physical, cryptographic, and POSIX state."""

    path: str = Field(description="Canonical normalized absolute file path")
    size_bytes: int = Field(ge=0, description="Size of file content in bytes")
    mode: int = Field(description="Raw POSIX mode bitmask")
    permissions: str = Field(description="Octal permissions string (e.g. 0644)")
    uid: int = Field(ge=0, description="POSIX owner user ID")
    gid: int = Field(ge=0, description="POSIX group ID")
    mtime: float = Field(description="Last modification timestamp in epoch seconds")
    inode: int = Field(ge=0, description="Filesystem inode number")
    is_suid: bool = Field(default=False, description="SetUID permission bit active")
    is_sgid: bool = Field(default=False, description="SetGID permission bit active")
    hashes: dict[str, str] = Field(
        default_factory=dict,
        description="Cryptographic digests (sha256, blake2b)",
    )

    @classmethod
    def from_path(cls, file_path: Path, compute_hashes: bool = True) -> "FileRecord":
        """Construct a FileRecord from an existing filesystem path.

        Args:
            file_path: Path to target file.
            compute_hashes: Whether to execute streaming cryptographic hashing.

        Returns:
            Populated FileRecord instance.

        Raises:
            FileNotFoundError: If path does not exist.
            OSError: On stat or read failure.
        """
        resolved = file_path.resolve(strict=False)
        st = resolved.stat()

        mode_val = st.st_mode
        perms_octal = oct(stat.S_IMODE(mode_val))
        suid = bool(mode_val & stat.S_ISUID)
        sgid = bool(mode_val & stat.S_ISGID)

        file_hashes: dict[str, str] = {}
        if compute_hashes and stat.S_ISREG(mode_val):
            file_hashes = hash_file(resolved)

        return cls(
            path=str(resolved),
            size_bytes=st.st_size,
            mode=mode_val,
            permissions=perms_octal,
            uid=st.st_uid,
            gid=st.st_gid,
            mtime=st.st_mtime,
            inode=st.st_ino,
            is_suid=suid,
            is_sgid=sgid,
            hashes=file_hashes,
        )

    def to_readable_mtime(self) -> str:
        """Format modification timestamp as human-readable UTC ISO-8601 string."""
        return datetime.fromtimestamp(self.mtime, tz=UTC).isoformat()

    def compare_attributes(self, other: "FileRecord") -> dict[str, tuple[Any, Any]]:
        """Compare attributes against another FileRecord snapshot.

        Returns:
            Dictionary of differences: {attribute: (self_val, other_val)}.
        """
        diffs: dict[str, tuple[Any, Any]] = {}

        if self.size_bytes != other.size_bytes:
            diffs["size_bytes"] = (self.size_bytes, other.size_bytes)
        if self.permissions != other.permissions:
            diffs["permissions"] = (self.permissions, other.permissions)
        if self.uid != other.uid:
            diffs["uid"] = (self.uid, other.uid)
        if self.gid != other.gid:
            diffs["gid"] = (self.gid, other.gid)
        if self.is_suid != other.is_suid:
            diffs["is_suid"] = (self.is_suid, other.is_suid)
        if self.is_sgid != other.is_sgid:
            diffs["is_sgid"] = (self.is_sgid, other.is_sgid)

        # Check hashes
        all_algos = set(self.hashes.keys()) | set(other.hashes.keys())
        for algo in all_algos:
            h1 = self.hashes.get(algo)
            h2 = other.hashes.get(algo)
            if h1 != h2:
                diffs[f"hash_{algo}"] = (h1, h2)

        return diffs
