"""Unit tests for differential StateComparator and threat PolicyEngine."""

from pathlib import Path

from fim.core.comparator import StateComparator
from fim.core.hasher import hash_file
from fim.models.alert import Severity
from fim.models.baseline import BaselineCatalog
from fim.models.delta import ChangeType
from fim.models.file_record import FileRecord
from fim.rules.policy import PolicyEngine


def test_comparator_detects_no_changes(tmp_path: Path) -> None:
    f1 = tmp_path / "app.conf"
    f1.write_text("setting=active\n")

    stat = f1.stat()
    shas = hash_file(f1)
    record = FileRecord(
        path=f1.as_posix(),
        size_bytes=stat.st_size,
        mode=stat.st_mode,
        permissions=oct(stat.st_mode)[-3:],
        uid=stat.st_uid,
        gid=stat.st_gid,
        mtime=stat.st_mtime,
        inode=stat.st_ino,
        is_suid=bool(stat.st_mode & 0o4000),
        is_sgid=bool(stat.st_mode & 0o2000),
        hashes=shas,
    )

    baseline = BaselineCatalog(
        root_paths=[tmp_path.as_posix()],
        records={record.path: record},
    )

    live_records = {record.path: record}
    report = StateComparator.compare(baseline, live_records)

    assert report.total_scanned == 1
    assert report.added_count == 0
    assert report.deleted_count == 0
    assert report.modified_count == 0
    assert report.unaltered_count == 1
    assert len(report.deltas) == 0


def test_comparator_detects_added_and_deleted_files(tmp_path: Path) -> None:
    f_old = tmp_path / "old.txt"
    f_old.write_text("old content")
    stat_old = f_old.stat()
    rec_old = FileRecord(
        path=f_old.as_posix(),
        size_bytes=stat_old.st_size,
        mode=stat_old.st_mode,
        permissions="644",
        uid=stat_old.st_uid,
        gid=stat_old.st_gid,
        mtime=stat_old.st_mtime,
        inode=stat_old.st_ino,
        is_suid=False,
        is_sgid=False,
        hashes=hash_file(f_old),
    )

    f_new = tmp_path / "new.txt"
    f_new.write_text("new content")
    stat_new = f_new.stat()
    rec_new = FileRecord(
        path=f_new.as_posix(),
        size_bytes=stat_new.st_size,
        mode=stat_new.st_mode,
        permissions="644",
        uid=stat_new.st_uid,
        gid=stat_new.st_gid,
        mtime=stat_new.st_mtime,
        inode=stat_new.st_ino,
        is_suid=False,
        is_sgid=False,
        hashes=hash_file(f_new),
    )

    # Baseline only knows f_old
    baseline = BaselineCatalog(
        root_paths=[tmp_path.as_posix()],
        records={rec_old.path: rec_old},
    )

    # Live only knows f_new
    live_records = {rec_new.path: rec_new}
    report = StateComparator.compare(baseline, live_records)

    assert report.added_count == 1
    assert report.deleted_count == 1
    assert report.modified_count == 0

    added_delta = next(d for d in report.deltas if d.change_type == ChangeType.ADDED)
    assert added_delta.path == rec_new.path
    assert added_delta.old_record is None
    assert added_delta.new_record is not None

    del_delta = next(d for d in report.deltas if d.change_type == ChangeType.DELETED)
    assert del_delta.path == rec_old.path
    assert del_delta.new_record is None
    assert del_delta.old_record is not None


def test_comparator_distinguishes_content_modification_vs_attributes(tmp_path: Path) -> None:
    f = tmp_path / "service.conf"
    f.write_text("v1")
    rec1 = FileRecord(
        path=f.as_posix(),
        size_bytes=2,
        mode=0o100644,
        permissions="644",
        uid=1000,
        gid=1000,
        mtime=1000.0,
        inode=12345,
        is_suid=False,
        is_sgid=False,
        hashes=hash_file(f),
    )

    baseline = BaselineCatalog(root_paths=[tmp_path.as_posix()], records={rec1.path: rec1})

    # Case A: Content changed
    f.write_text("v2 modified")
    rec2 = FileRecord(
        path=f.as_posix(),
        size_bytes=11,
        mode=0o100644,
        permissions="644",
        uid=1000,
        gid=1000,
        mtime=1005.0,
        inode=12345,
        is_suid=False,
        is_sgid=False,
        hashes=hash_file(f),
    )
    report_modified = StateComparator.compare(baseline, {rec2.path: rec2})
    assert report_modified.modified_count == 1
    assert report_modified.deltas[0].change_type == ChangeType.MODIFIED
    assert report_modified.deltas[0].is_hash_changed

    # Case B: Only permissions changed, hash identical
    f.write_text("v1")
    rec3 = FileRecord(
        path=f.as_posix(),
        size_bytes=2,
        mode=0o100755,
        permissions="755",
        uid=1000,
        gid=1000,
        mtime=1000.0,
        inode=12345,
        is_suid=False,
        is_sgid=False,
        hashes=rec1.hashes,
    )
    report_attrs = StateComparator.compare(baseline, {rec3.path: rec3})
    assert report_attrs.modified_count == 1
    assert report_attrs.deltas[0].change_type == ChangeType.ATTRIBUTES_CHANGED
    assert not report_attrs.deltas[0].is_hash_changed


def test_threat_policy_suid_privilege_escalation() -> None:
    engine = PolicyEngine()

    rec_old = FileRecord(
        path="/usr/local/bin/custom_tool",
        size_bytes=100,
        mode=0o100755,
        permissions="755",
        uid=0,
        gid=0,
        mtime=100.0,
        inode=1,
        is_suid=False,
        is_sgid=False,
    )
    rec_new = FileRecord(
        path="/usr/local/bin/custom_tool",
        size_bytes=100,
        mode=0o104755,
        permissions="4755",
        uid=0,
        gid=0,
        mtime=105.0,
        inode=1,
        is_suid=True,
        is_sgid=False,
    )

    baseline = BaselineCatalog(root_paths=["/usr/local/bin"], records={rec_old.path: rec_old})
    report = StateComparator.compare(baseline, {rec_new.path: rec_new})
    alert = engine.evaluate_delta(report.deltas[0])

    assert alert.severity == Severity.CRITICAL
    assert alert.category == "SUID_PRIVILEGE_ESCALATION"
    assert "Privilege escalation indicator" in alert.description
    assert alert.to_cef().startswith("CEF:0|CyberSecurityPortfolio|FileIntegrityMonitor")


def test_threat_policy_critical_system_file_tampering() -> None:
    engine = PolicyEngine(critical_patterns=["*/etc/shadow*", "*/etc/sudoers*"])

    rec_old = FileRecord(
        path="/etc/shadow",
        size_bytes=200,
        mode=0o100640,
        permissions="640",
        uid=0,
        gid=42,
        mtime=100.0,
        inode=10,
        is_suid=False,
        is_sgid=False,
        hashes={"sha256": "aaa", "blake2b": "bbb"},
    )
    rec_new = FileRecord(
        path="/etc/shadow",
        size_bytes=250,
        mode=0o100640,
        permissions="640",
        uid=0,
        gid=42,
        mtime=200.0,
        inode=10,
        is_suid=False,
        is_sgid=False,
        hashes={"sha256": "zzz", "blake2b": "yyy"},
    )

    baseline = BaselineCatalog(root_paths=["/etc"], records={rec_old.path: rec_old})
    report = StateComparator.compare(baseline, {rec_new.path: rec_new})
    alert = engine.evaluate_delta(report.deltas[0])

    assert alert.severity == Severity.CRITICAL
    assert alert.category == "CRITICAL_FILE_TAMPERED"


def test_threat_policy_world_writable_exposure() -> None:
    engine = PolicyEngine()

    rec_old = FileRecord(
        path="/var/log/app.log",
        size_bytes=50,
        mode=0o100644,
        permissions="644",
        uid=1000,
        gid=1000,
        mtime=10.0,
        inode=99,
        is_suid=False,
        is_sgid=False,
    )
    rec_new = FileRecord(
        path="/var/log/app.log",
        size_bytes=50,
        mode=0o100666,  # S_IWOTH set
        permissions="666",
        uid=1000,
        gid=1000,
        mtime=10.0,
        inode=99,
        is_suid=False,
        is_sgid=False,
    )

    baseline = BaselineCatalog(root_paths=["/var/log"], records={rec_old.path: rec_old})
    report = StateComparator.compare(baseline, {rec_new.path: rec_new})
    alert = engine.evaluate_delta(report.deltas[0])

    assert alert.severity == Severity.HIGH
    assert alert.category == "PERMISSIVE_ACCESS_EXPOSURE"


def test_threat_policy_eval_report_sorting_and_filtering() -> None:
    engine = PolicyEngine(critical_patterns=["*/etc/shadow*"])

    rec_crit = FileRecord(
        path="/etc/shadow",
        size_bytes=10,
        mode=0o100600,
        permissions="600",
        uid=0,
        gid=0,
        mtime=1.0,
        inode=1,
        is_suid=False,
        is_sgid=False,
        hashes={"sha256": "1"},
    )
    rec_crit_mod = rec_crit.model_copy(update={"hashes": {"sha256": "2"}})

    rec_low = FileRecord(
        path="/var/data/touch.txt",
        size_bytes=10,
        mode=0o100644,
        permissions="644",
        uid=1000,
        gid=1000,
        mtime=1.0,
        inode=2,
        is_suid=False,
        is_sgid=False,
        hashes={"sha256": "x"},
    )
    rec_low_touch = rec_low.model_copy(update={"mtime": 2.0})

    baseline = BaselineCatalog(
        root_paths=["/"],
        records={rec_crit.path: rec_crit, rec_low.path: rec_low},
    )
    report = StateComparator.compare(
        baseline,
        {rec_crit_mod.path: rec_crit_mod, rec_low_touch.path: rec_low_touch},
    )

    alerts = engine.evaluate_report(report)
    assert len(alerts) == 2
    # Verify sorting: CRITICAL should be first, LOW second
    assert alerts[0].severity == Severity.CRITICAL
    assert alerts[1].severity == Severity.LOW

    # Verify filter
    high_and_above = PolicyEngine.filter_alerts(alerts, min_severity=Severity.HIGH)
    assert len(high_and_above) == 1
    assert high_and_above[0].target_path == "/etc/shadow"


def test_threat_policy_critical_file_added_and_metadata() -> None:
    engine = PolicyEngine(critical_patterns=["*/bin/*"])

    # 1. Critical file added
    rec_injected = FileRecord(
        path="/usr/bin/backdoor",
        size_bytes=100,
        mode=0o100755,
        permissions="755",
        uid=0,
        gid=0,
        mtime=1.0,
        inode=999,
        is_suid=False,
        is_sgid=False,
    )
    baseline = BaselineCatalog(root_paths=["/usr/bin"], records={})
    report = StateComparator.compare(baseline, {rec_injected.path: rec_injected})
    alert = engine.evaluate_delta(report.deltas[0])
    assert alert.severity == Severity.CRITICAL
    assert alert.category == "CRITICAL_FILE_INJECTION"

    # 2. Critical file metadata altered
    rec_crit_old = FileRecord(
        path="/usr/bin/sudo",
        size_bytes=500,
        mode=0o104755,
        permissions="4755",
        uid=0,
        gid=0,
        mtime=1.0,
        inode=100,
        is_suid=True,
        is_sgid=False,
        hashes={"sha256": "same"},
    )
    rec_crit_new = rec_crit_old.model_copy(
        update={"permissions": "0755", "mode": 0o100755, "is_suid": False}
    )
    base_crit = BaselineCatalog(root_paths=["/usr/bin"], records={rec_crit_old.path: rec_crit_old})
    rep_crit = StateComparator.compare(base_crit, {rec_crit_new.path: rec_crit_new})
    alert_meta = engine.evaluate_delta(rep_crit.deltas[0])
    assert alert_meta.severity == Severity.HIGH
    assert alert_meta.category == "CRITICAL_METADATA_ALTERED"


def test_threat_policy_ownership_and_permission_changes() -> None:
    engine = PolicyEngine()

    rec_base = FileRecord(
        path="/var/www/index.html",
        size_bytes=50,
        mode=0o100644,
        permissions="644",
        uid=1000,
        gid=1000,
        mtime=1.0,
        inode=1,
        is_suid=False,
        is_sgid=False,
        hashes={"sha256": "abc"},
    )

    # UID/GID change
    rec_chown = rec_base.model_copy(update={"uid": 0})
    base = BaselineCatalog(root_paths=["/var/www"], records={rec_base.path: rec_base})
    rep_chown = StateComparator.compare(base, {rec_chown.path: rec_chown})
    alert_chown = engine.evaluate_delta(rep_chown.deltas[0])
    assert alert_chown.severity == Severity.MEDIUM
    assert alert_chown.category == "OWNERSHIP_CHANGED"

    # Non-world-writable permission change
    rec_chmod = rec_base.model_copy(update={"permissions": "664", "mode": 0o100664})
    rep_chmod = StateComparator.compare(base, {rec_chmod.path: rec_chmod})
    alert_chmod = engine.evaluate_delta(rep_chmod.deltas[0])
    assert alert_chmod.severity == Severity.MEDIUM
    assert alert_chmod.category == "PERMISSIONS_ALTERED"
