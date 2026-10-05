"""Filesystem scanning engine for baseline creation and live state capture."""

import logging
from pathlib import Path

from fim.core.hasher import FileHashingError
from fim.models.baseline import BaselineCatalog
from fim.models.file_record import FileRecord
from fim.scanner.walker import SafePathWalker

logger = logging.getLogger("fim.scanner")


class ScanEngine:
    """Orchestrates path walking and cryptographic snapshot generation."""

    def __init__(self, walker: SafePathWalker | None = None) -> None:
        self.walker = walker or SafePathWalker()

    def scan_live_state(self, roots: list[Path]) -> dict[str, FileRecord]:
        """Traverse target root paths and return mapping of canonical path to FileRecord.

        Args:
            roots: Target file or directory paths to inspect.

        Returns:
            Dictionary mapping canonical absolute path strings to FileRecord instances.
        """
        records: dict[str, FileRecord] = {}

        for root in roots:
            for file_path in self.walker.walk(root):
                try:
                    record = FileRecord.from_path(file_path, compute_hashes=True)
                    records[record.path] = record
                except (PermissionError, OSError, FileHashingError) as exc:
                    logger.warning("Could not process file '%s': %s", file_path, exc)

        return records

    def build_baseline(
        self,
        roots: list[Path],
        key: bytes | None = None,
    ) -> BaselineCatalog:
        """Construct a fresh cryptographically sealed baseline catalog across roots.

        Args:
            roots: Target filesystem directories or files.
            key: Optional HMAC key to seal the catalog immediately.

        Returns:
            Populated (and optionally sealed) BaselineCatalog instance.
        """
        records = self.scan_live_state(roots)
        canonical_roots = [str(r.resolve(strict=False)) for r in roots]

        catalog = BaselineCatalog(
            root_paths=canonical_roots,
            total_files=len(records),
            records=records,
        )

        if key is not None:
            catalog.seal(key)

        return catalog
