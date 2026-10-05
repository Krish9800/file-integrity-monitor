"""Unit tests for FIMEventHandler and RealtimeMonitor."""

import time
from pathlib import Path

import pytest
from watchdog.events import (
    DirCreatedEvent,
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    FileMovedEvent,
)

from fim.models.alert import SecurityAlert, Severity
from fim.models.baseline import BaselineCatalog
from fim.models.delta import ChangeType
from fim.models.file_record import FileRecord
from fim.monitor.handler import FIMEventHandler
from fim.monitor.watcher import RealtimeMonitor
from fim.rules.policy import PolicyEngine


def test_handler_ignores_directory_and_excluded_events(tmp_path: Path) -> None:
    alerts: list[SecurityAlert] = []
    baseline = BaselineCatalog(root_paths=[tmp_path.as_posix()])
    policy = PolicyEngine()

    handler = FIMEventHandler(
        baseline=baseline,
        policy_engine=policy,
        alert_callback=alerts.append,
        exclude_patterns=["*.tmp", "*cache*"],
        settle_delay=0.0,
    )

    # 1. Directory event
    dir_event = DirCreatedEvent((tmp_path / "subdir").as_posix())
    handler.on_created(dir_event)
    assert len(alerts) == 0

    # 2. Excluded pattern
    tmp_file = tmp_path / "temp.tmp"
    tmp_file.write_text("test")
    file_event = FileCreatedEvent(tmp_file.as_posix())
    handler.on_created(file_event)
    assert len(alerts) == 0


def test_handler_processes_file_created_and_modified(tmp_path: Path) -> None:
    alerts: list[SecurityAlert] = []
    baseline = BaselineCatalog(root_paths=[tmp_path.as_posix()])
    policy = PolicyEngine()

    handler = FIMEventHandler(
        baseline=baseline,
        policy_engine=policy,
        alert_callback=alerts.append,
        settle_delay=0.0,
    )

    test_file = tmp_path / "config.ini"
    test_file.write_text("[section]\nkey=val1\n")

    # Created event
    handler.on_created(FileCreatedEvent(test_file.as_posix()))
    assert len(alerts) == 1
    assert alerts[0].change_type == ChangeType.ADDED
    assert alerts[0].target_path == test_file.resolve().as_posix()

    # Modified event (content change)
    test_file.write_text("[section]\nkey=val2_altered\n")
    handler.on_modified(FileModifiedEvent(test_file.as_posix()))
    assert len(alerts) == 2
    assert alerts[1].change_type == ChangeType.MODIFIED
    assert alerts[1].severity == Severity.HIGH


def test_handler_processes_file_deleted(tmp_path: Path) -> None:
    test_file = tmp_path / "app.log"
    test_file.write_text("log data")

    rec = FileRecord.from_path(test_file)
    baseline = BaselineCatalog(
        root_paths=[tmp_path.as_posix()],
        records={rec.path: rec},
    )
    alerts: list[SecurityAlert] = []
    policy = PolicyEngine()

    handler = FIMEventHandler(
        baseline=baseline,
        policy_engine=policy,
        alert_callback=alerts.append,
        settle_delay=0.0,
    )

    # Delete file and trigger handler
    test_file.unlink()
    handler.on_deleted(FileDeletedEvent(test_file.as_posix()))

    assert len(alerts) == 1
    assert alerts[0].change_type == ChangeType.DELETED
    assert alerts[0].category == "FILE_DELETED"


def test_handler_processes_file_moved(tmp_path: Path) -> None:
    src_file = tmp_path / "source.txt"
    src_file.write_text("payload")
    rec = FileRecord.from_path(src_file)

    dest_file = tmp_path / "destination.txt"

    baseline = BaselineCatalog(
        root_paths=[tmp_path.as_posix()],
        records={rec.path: rec},
    )
    alerts: list[SecurityAlert] = []
    policy = PolicyEngine()

    handler = FIMEventHandler(
        baseline=baseline,
        policy_engine=policy,
        alert_callback=alerts.append,
        settle_delay=0.0,
    )

    # Emulate move: rename on disk then trigger event
    src_file.rename(dest_file)
    move_event = FileMovedEvent(src_file.as_posix(), dest_file.as_posix())
    handler.on_moved(move_event)

    # Should have a DELETED alert for src and an ADDED alert for dest
    assert len(alerts) == 2
    types = {a.change_type for a in alerts}
    assert ChangeType.DELETED in types
    assert ChangeType.ADDED in types


def test_realtime_monitor_lifecycle_and_live_events(tmp_path: Path) -> None:
    target_dir = tmp_path / "watched"
    target_dir.mkdir()

    initial_file = target_dir / "base.txt"
    initial_file.write_text("initial")
    rec = FileRecord.from_path(initial_file)

    baseline = BaselineCatalog(
        root_paths=[target_dir.as_posix()],
        records={rec.path: rec},
    )
    alerts: list[SecurityAlert] = []
    policy = PolicyEngine()

    monitor = RealtimeMonitor(
        baseline=baseline,
        policy_engine=policy,
        alert_callback=alerts.append,
        settle_delay=0.05,
    )

    with monitor:
        assert monitor.is_alive

        # Create a new file in watched directory
        new_file = target_dir / "attack_tool.py"
        new_file.write_text("# new code injected")

        # Wait up to 1.5 seconds for kernel filesystem event to bubble up
        deadline = time.time() + 1.5
        while time.time() < deadline and not alerts:
            time.sleep(0.05)

        assert len(alerts) >= 1
        assert any(a.change_type == ChangeType.ADDED for a in alerts)

    assert not monitor.is_alive


def test_realtime_monitor_invalid_paths_raises() -> None:
    baseline = BaselineCatalog(root_paths=["/nonexistent/path/for/sure/12345"])
    policy = PolicyEngine()
    monitor = RealtimeMonitor(
        baseline=baseline,
        policy_engine=policy,
        alert_callback=lambda _alert: None,
    )

    with pytest.raises(ValueError, match="No valid directories or files"):
        monitor.start()
