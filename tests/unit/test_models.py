"""Unit tests for Phase 3 models: FileRecord, BaselineCatalog, FileDelta, SecurityAlert."""

from pathlib import Path

import pytest

from fim.core.integrity import IntegrityError, generate_key
from fim.models.alert import SecurityAlert, Severity
from fim.models.baseline import BaselineCatalog
from fim.models.delta import AttributeDiff, ChangeType, FileDelta, ScanReport
from fim.models.file_record import FileRecord


def test_file_record_from_path(tmp_path: Path) -> None:
    """Test constructing FileRecord from a target file on disk."""
    sample = tmp_path / "test.conf"
    sample.write_text("config_param=1", encoding="utf-8")

    record = FileRecord.from_path(sample)

    assert record.path == str(sample.resolve())
    assert record.size_bytes == 14
    assert "sha256" in record.hashes
    assert "blake2b" in record.hashes
    assert record.is_suid is False
    assert record.is_sgid is False
    assert len(record.to_readable_mtime()) > 10


def test_file_record_attribute_comparison(tmp_path: Path) -> None:
    """Test comparing two FileRecord instances for differences."""
    sample1 = tmp_path / "f1.txt"
    sample1.write_text("version 1", encoding="utf-8")
    rec1 = FileRecord.from_path(sample1)

    # Modify content
    sample1.write_text("version 2 modified", encoding="utf-8")
    rec2 = FileRecord.from_path(sample1)

    diffs = rec1.compare_attributes(rec2)
    assert "size_bytes" in diffs
    assert "hash_sha256" in diffs
    assert "hash_blake2b" in diffs


def test_baseline_catalog_sealing_and_tampering(tmp_path: Path) -> None:
    """Test HMAC catalog sealing and detecting tampered records."""
    key = generate_key()
    catalog_file = tmp_path / "baseline.json"

    file1 = tmp_path / "file1.txt"
    file1.write_text("content1", encoding="utf-8")
    rec1 = FileRecord.from_path(file1)

    catalog = BaselineCatalog(
        root_paths=[str(tmp_path)],
        total_files=1,
        records={rec1.path: rec1},
    )

    # Seal and save
    catalog.save(catalog_file, key=key)
    assert catalog_file.exists()

    # Load and verify
    loaded = BaselineCatalog.load(catalog_file, key=key)
    assert loaded.total_files == 1
    assert loaded.verify_integrity(key) is True

    # Tamper with file content directly on disk
    raw_json = catalog_file.read_text(encoding="utf-8")
    tampered_json = raw_json.replace('"total_files": 1', '"total_files": 99')
    assert tampered_json != raw_json
    catalog_file.write_text(tampered_json, encoding="utf-8")

    # Loading with key should raise IntegrityError
    with pytest.raises(IntegrityError, match="failed HMAC signature check"):
        BaselineCatalog.load(catalog_file, key=key)


def test_file_delta_and_scan_report() -> None:
    """Test FileDelta change classifications and ScanReport aggregation."""
    delta = FileDelta(
        path="/etc/shadow",
        change_type=ChangeType.MODIFIED,
        diffs=[
            AttributeDiff(
                attribute="hash_sha256",
                old_value="hash_a",
                new_value="hash_b",
            ),
            AttributeDiff(
                attribute="permissions",
                old_value="0600",
                new_value="0644",
            ),
        ],
    )

    assert delta.is_hash_changed is True
    assert delta.is_permission_changed is True
    assert delta.is_suid_changed is False

    report = ScanReport(
        total_scanned=10,
        modified_count=1,
        deltas=[delta],
    )
    assert report.has_anomalies is True


def test_security_alert_and_cef_export() -> None:
    """Test alert creation and ArcSight Common Event Format (CEF) string generation."""
    alert = SecurityAlert(
        severity=Severity.CRITICAL,
        category="PRIVILEGE_ESCALATION",
        target_path="/usr/bin/python3",
        change_type=ChangeType.ATTRIBUTES_CHANGED,
        description="SetUID bit added to executable binary",
    )

    cef = alert.to_cef()
    assert "CEF:0|CyberSecurityPortfolio|FileIntegrityMonitor|0.1.0|" in cef
    assert "|PRIVILEGE_ESCALATION|" in cef
    assert "|10|" in cef  # CRITICAL mapped to CEF severity 10
    assert "filePath=/usr/bin/python3" in cef
