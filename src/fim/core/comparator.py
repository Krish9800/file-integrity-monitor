"""Differential state comparator identifying filesystem modifications against a baseline."""

from fim.models.baseline import BaselineCatalog
from fim.models.delta import AttributeDiff, ChangeType, FileDelta, ScanReport
from fim.models.file_record import FileRecord


class StateComparator:
    """Computes exact attribute and content deltas between baseline and live state."""

    @staticmethod
    def compare(
        baseline: BaselineCatalog,
        current_records: dict[str, FileRecord],
        scan_duration: float = 0.0,
    ) -> ScanReport:
        """Compare live filesystem snapshot against a reference baseline catalog.

        Args:
            baseline: Authenticated baseline catalog.
            current_records: Live file records mapped by canonical path.
            scan_duration: Elapsed duration of scan in seconds.

        Returns:
            Populated ScanReport with granular deltas.
        """
        baseline_keys = set(baseline.records.keys())
        current_keys = set(current_records.keys())

        added_paths = current_keys - baseline_keys
        deleted_paths = baseline_keys - current_keys
        common_paths = baseline_keys & current_keys

        deltas: list[FileDelta] = []
        unaltered_count = 0

        # 1. Process added files
        for path in sorted(added_paths):
            rec = current_records[path]
            diffs = [
                AttributeDiff(
                    attribute="state",
                    old_value="ABSENT",
                    new_value="CREATED",
                )
            ]
            deltas.append(
                FileDelta(
                    path=path,
                    change_type=ChangeType.ADDED,
                    old_record=None,
                    new_record=rec,
                    diffs=diffs,
                )
            )

        # 2. Process deleted files
        for path in sorted(deleted_paths):
            old_rec = baseline.records[path]
            diffs = [
                AttributeDiff(
                    attribute="state",
                    old_value="PRESENT",
                    new_value="DELETED",
                )
            ]
            deltas.append(
                FileDelta(
                    path=path,
                    change_type=ChangeType.DELETED,
                    old_record=old_rec,
                    new_record=None,
                    diffs=diffs,
                )
            )

        # 3. Process existing files for attribute or content modifications
        for path in sorted(common_paths):
            old_rec = baseline.records[path]
            new_rec = current_records[path]

            raw_diffs = old_rec.compare_attributes(new_rec)
            if not raw_diffs:
                unaltered_count += 1
                continue

            attr_diffs = [
                AttributeDiff(
                    attribute=attr_name,
                    old_value=vals[0],
                    new_value=vals[1],
                )
                for attr_name, vals in raw_diffs.items()
            ]

            # Differentiate content modifications from metadata-only changes
            has_hash_change = any(k.startswith("hash_") for k in raw_diffs)
            change_type = ChangeType.MODIFIED if has_hash_change else ChangeType.ATTRIBUTES_CHANGED

            deltas.append(
                FileDelta(
                    path=path,
                    change_type=change_type,
                    old_record=old_rec,
                    new_record=new_rec,
                    diffs=attr_diffs,
                )
            )

        added_cnt = len(added_paths)
        deleted_cnt = len(deleted_paths)
        modified_cnt = len(deltas) - added_cnt - deleted_cnt

        return ScanReport(
            total_scanned=len(current_records),
            added_count=added_cnt,
            deleted_count=deleted_cnt,
            modified_count=modified_cnt,
            unaltered_count=unaltered_count,
            scan_duration_seconds=scan_duration,
            deltas=deltas,
        )
