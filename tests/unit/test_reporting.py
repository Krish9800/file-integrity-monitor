"""Unit tests for TelemetryEmitter."""

import io
from pathlib import Path

from rich.console import Console

from fim.models.alert import SecurityAlert, Severity
from fim.models.delta import ChangeType, ScanReport
from fim.reporting.emitter import TelemetryEmitter


def test_emitter_print_scan_report() -> None:
    output = io.StringIO()
    console = Console(file=output, color_system=None)
    emitter = TelemetryEmitter(console=console)

    report = ScanReport(
        total_scanned=10,
        added_count=2,
        deleted_count=1,
        modified_count=3,
        unaltered_count=4,
        scan_duration_seconds=0.123,
    )
    emitter.print_scan_report(report)
    rendered = output.getvalue()

    assert "Filesystem Integrity Scan Summary" in rendered
    assert "10" in rendered
    assert "2" in rendered
    assert "1" in rendered


def test_emitter_print_alert_and_table() -> None:
    output = io.StringIO()
    console = Console(file=output, color_system=None)
    emitter = TelemetryEmitter(console=console)

    alert = SecurityAlert(
        severity=Severity.CRITICAL,
        category="SUID_PRIVILEGE_ESCALATION",
        target_path="/usr/bin/tampered_tool",
        change_type=ChangeType.MODIFIED,
        description="SetUID bit added to tool",
        recommendation="Revoke SUID bit",
        details={"permissions": ("0755", "4755")},
    )

    emitter.print_alert(alert)
    rendered = output.getvalue()
    assert "SECURITY ALERT: CRITICAL" in rendered
    assert "SUID_PRIVILEGE_ESCALATION" in rendered
    assert "/usr/bin/tampered_tool" in rendered
    assert "permissions" in rendered

    # Print table with alerts
    output_table = io.StringIO()
    console_table = Console(file=output_table, width=140, color_system=None)
    emitter_table = TelemetryEmitter(console=console_table)

    emitter_table.print_alerts_table([alert])
    rendered_table = output_table.getvalue()
    assert "Security Alerts (1 detected)" in rendered_table
    assert "CRITICAL" in rendered_table

    # Print table with empty alerts
    output_empty = io.StringIO()
    console_empty = Console(file=output_empty, color_system=None)
    emitter_empty = TelemetryEmitter(console=console_empty)
    emitter_empty.print_alerts_table([])
    assert "No security anomalies" in output_empty.getvalue()


def test_emitter_emit_json_and_cef(tmp_path: Path) -> None:
    alert = SecurityAlert(
        severity=Severity.HIGH,
        category="CONTENT_TAMPERED",
        target_path="/etc/hosts",
        change_type=ChangeType.MODIFIED,
        description="Hash changed",
    )

    # JSON streaming
    json_stream = io.StringIO()
    TelemetryEmitter.emit_json_lines([alert], json_stream)
    json_line = json_stream.getvalue().strip()
    assert '"category":"CONTENT_TAMPERED"' in json_line
    assert '"target_path":"/etc/hosts"' in json_line

    # CEF streaming
    cef_stream = io.StringIO()
    TelemetryEmitter.emit_cef([alert], cef_stream)
    cef_line = cef_stream.getvalue().strip()
    assert cef_line.startswith("CEF:0|CyberSecurityPortfolio|FileIntegrityMonitor")
    assert "filePath=/etc/hosts" in cef_line

    # File logging
    log_file = tmp_path / "alerts.log"
    TelemetryEmitter.log_alert_to_file(alert, log_file, as_cef=False)
    assert log_file.exists()
    assert "/etc/hosts" in log_file.read_text(encoding="utf-8")
