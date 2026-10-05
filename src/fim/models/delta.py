"""Differential state and change comparison models."""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from fim.models.file_record import FileRecord


class ChangeType(StrEnum):
    """Classification of detected filesystem alterations."""

    ADDED = "ADDED"
    DELETED = "DELETED"
    MODIFIED = "MODIFIED"
    ATTRIBUTES_CHANGED = "ATTRIBUTES_CHANGED"


class AttributeDiff(BaseModel):
    """Record of a specific attribute difference between two file snapshots."""

    attribute: str = Field(description="Name of changed attribute (e.g. 'permissions', 'sha256')")
    old_value: Any = Field(description="Value in baseline reference")
    new_value: Any = Field(description="Value in live observed state")


class FileDelta(BaseModel):
    """Structured representation of a single file modification event."""

    path: str = Field(description="Canonical path to modified target")
    change_type: ChangeType = Field(description="High-level change category")
    old_record: FileRecord | None = Field(
        default=None,
        description="Reference baseline record if available",
    )
    new_record: FileRecord | None = Field(
        default=None,
        description="Newly observed record if available",
    )
    diffs: list[AttributeDiff] = Field(
        default_factory=list,
        description="Detailed list of altered attributes",
    )

    @property
    def is_hash_changed(self) -> bool:
        """True if any cryptographic content hash altered."""
        return any(d.attribute.startswith("hash_") for d in self.diffs)

    @property
    def is_permission_changed(self) -> bool:
        """True if POSIX permissions or ownership altered."""
        return any(d.attribute in ("permissions", "uid", "gid") for d in self.diffs)

    @property
    def is_suid_changed(self) -> bool:
        """True if SetUID or SetGID security flags altered."""
        return any(d.attribute in ("is_suid", "is_sgid") for d in self.diffs)


class ScanReport(BaseModel):
    """Aggregate summary of an integrity verification scan."""

    total_scanned: int = Field(default=0, ge=0)
    added_count: int = Field(default=0, ge=0)
    deleted_count: int = Field(default=0, ge=0)
    modified_count: int = Field(default=0, ge=0)
    unaltered_count: int = Field(default=0, ge=0)
    scan_duration_seconds: float = Field(default=0.0, ge=0.0)
    deltas: list[FileDelta] = Field(default_factory=list)

    @property
    def has_anomalies(self) -> bool:
        """True if any additions, deletions, or modifications were detected."""
        return len(self.deltas) > 0
