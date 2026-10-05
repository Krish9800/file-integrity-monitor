"""Real-time filesystem event handler translating kernel filesystem events into security deltas."""

import logging
import threading
import time
from collections.abc import Callable
from pathlib import Path

from watchdog.events import (
    DirCreatedEvent,
    DirDeletedEvent,
    DirModifiedEvent,
    DirMovedEvent,
    FileSystemEvent,
    FileSystemEventHandler,
)

from fim.models.alert import SecurityAlert
from fim.models.baseline import BaselineCatalog
from fim.models.delta import AttributeDiff, ChangeType, FileDelta
from fim.models.file_record import FileRecord
from fim.rules.policy import PolicyEngine
from fim.scanner.walker import SafePathWalker

logger = logging.getLogger("fim.monitor")


class FIMEventHandler(FileSystemEventHandler):
    """Processes filesystem change notifications and triggers security threat analysis."""

    def __init__(
        self,
        baseline: BaselineCatalog,
        policy_engine: PolicyEngine,
        alert_callback: Callable[[SecurityAlert], None],
        exclude_patterns: list[str] | None = None,
        settle_delay: float = 0.1,
    ) -> None:
        """Initialize real-time event handler.

        Args:
            baseline: Initial baseline reference catalog.
            policy_engine: Threat evaluation engine for alerts.
            alert_callback: Invoked when a security alert is produced.
            exclude_patterns: Glob patterns to ignore (e.g. temp files, caches).
            settle_delay: Small window (seconds) allowing file write flush before hashing.
        """
        super().__init__()
        self.baseline = baseline
        self.policy_engine = policy_engine
        self.alert_callback = alert_callback
        self.exclude_patterns = exclude_patterns or []
        self.settle_delay = settle_delay

        # Active state tracked in memory, initialized from baseline records
        self._lock = threading.Lock()
        self._current_records: dict[str, FileRecord] = dict(baseline.records)

    def _should_ignore(self, path: Path) -> bool:
        """Check if file path matches exclusions or is hidden/temporary."""
        return SafePathWalker.is_path_excluded(path, self.exclude_patterns)

    @staticmethod
    def _to_path(raw_path: bytes | str) -> Path:
        """Convert watchdog event path (str or bytes) to a Path object."""
        if isinstance(raw_path, bytes):
            return Path(raw_path.decode("utf-8", errors="replace"))
        return Path(raw_path)

    def on_created(self, event: FileSystemEvent) -> None:
        """Handle file creation events."""
        if isinstance(event, DirCreatedEvent):
            return
        self._process_path_change(self._to_path(event.src_path))

    def on_modified(self, event: FileSystemEvent) -> None:
        """Handle file modification events."""
        if isinstance(event, DirModifiedEvent):
            return
        self._process_path_change(self._to_path(event.src_path))

    def on_deleted(self, event: FileSystemEvent) -> None:
        """Handle file deletion events."""
        if isinstance(event, DirDeletedEvent):
            return
        self._process_path_deletion(self._to_path(event.src_path))

    def on_moved(self, event: FileSystemEvent) -> None:
        """Handle file relocation/rename events."""
        if isinstance(event, DirMovedEvent):
            return
        # A file move constitutes deletion of the source and creation of the destination
        if hasattr(event, "src_path"):
            self._process_path_deletion(self._to_path(event.src_path))
        if hasattr(event, "dest_path"):
            self._process_path_change(self._to_path(event.dest_path))

    def _process_path_change(self, file_path: Path) -> None:
        """Process created or modified file with debouncing settle delay."""
        if self._should_ignore(file_path):
            return

        if self.settle_delay > 0:
            time.sleep(self.settle_delay)

        canonical_path = file_path.as_posix()
        try:
            if not file_path.is_file():
                return
            new_record = FileRecord.from_path(file_path, compute_hashes=True)
            canonical_path = new_record.path
        except (FileNotFoundError, PermissionError, OSError) as e:
            logger.debug("Failed reading live record for %s: %s", file_path, e)
            return

        with self._lock:
            old_record = self._current_records.get(canonical_path)

            if old_record is None:
                # Newly added file
                diffs = [
                    AttributeDiff(
                        attribute="state",
                        old_value="ABSENT",
                        new_value="CREATED",
                    )
                ]
                delta = FileDelta(
                    path=canonical_path,
                    change_type=ChangeType.ADDED,
                    old_record=None,
                    new_record=new_record,
                    diffs=diffs,
                )
                self._current_records[canonical_path] = new_record
            else:
                raw_diffs = old_record.compare_attributes(new_record)
                if not raw_diffs:
                    return  # No discernible changes

                attr_diffs = [
                    AttributeDiff(
                        attribute=k,
                        old_value=v[0],
                        new_value=v[1],
                    )
                    for k, v in raw_diffs.items()
                ]
                has_hash_change = any(k.startswith("hash_") for k in raw_diffs)
                change_type = (
                    ChangeType.MODIFIED if has_hash_change else ChangeType.ATTRIBUTES_CHANGED
                )

                delta = FileDelta(
                    path=canonical_path,
                    change_type=change_type,
                    old_record=old_record,
                    new_record=new_record,
                    diffs=attr_diffs,
                )
                self._current_records[canonical_path] = new_record

        # Generate threat alert and dispatch
        alert = self.policy_engine.evaluate_delta(delta)
        self.alert_callback(alert)

    def _process_path_deletion(self, file_path: Path) -> None:
        """Process deletion of a file."""
        if self._should_ignore(file_path):
            return

        canonical_path = file_path.as_posix()
        with self._lock:
            old_record = self._current_records.pop(canonical_path, None)
            if old_record is None:
                # Try matching by resolving path string if needed
                for tracked_path in list(self._current_records.keys()):
                    if tracked_path == canonical_path or tracked_path.endswith(
                        f"/{file_path.name}"
                    ):
                        old_record = self._current_records.pop(tracked_path, None)
                        canonical_path = tracked_path
                        break

            if old_record is None:
                return  # Deletion of unmonitored untracked file

            diffs = [
                AttributeDiff(
                    attribute="state",
                    old_value="PRESENT",
                    new_value="DELETED",
                )
            ]
            delta = FileDelta(
                path=canonical_path,
                change_type=ChangeType.DELETED,
                old_record=old_record,
                new_record=None,
                diffs=diffs,
            )

        alert = self.policy_engine.evaluate_delta(delta)
        self.alert_callback(alert)
