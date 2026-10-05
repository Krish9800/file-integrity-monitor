"""Integration tests for FIM Typer CLI commands."""

import json
from pathlib import Path

from typer.testing import CliRunner

from fim.cli.main import app

runner = CliRunner()


def test_cli_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "File Integrity Monitoring (FIM) Engine" in result.stdout
    assert "SHA-256, BLAKE2b" in result.stdout


def test_cli_init_key(tmp_path: Path) -> None:
    key_file = tmp_path / "secret.key"

    # 1. Create key
    result = runner.invoke(app, ["init-key", "--output", str(key_file)])
    assert result.exit_code == 0
    assert key_file.exists()
    assert len(key_file.read_bytes()) == 32

    # Check 0600 POSIX permissions
    file_stat = key_file.stat()
    assert (file_stat.st_mode & 0o777) == 0o600

    # 2. Overwrite protection
    result_dup = runner.invoke(app, ["init-key", "--output", str(key_file)])
    assert result_dup.exit_code == 1
    assert "already exists" in result_dup.stdout

    # 3. Force overwrite
    result_force = runner.invoke(app, ["init-key", "--output", str(key_file), "--force"])
    assert result_force.exit_code == 0


def test_cli_baseline_create_and_verify_clean(tmp_path: Path) -> None:
    monitored_dir = tmp_path / "monitored"
    monitored_dir.mkdir()
    f1 = monitored_dir / "app.py"
    f1.write_text("print('hello world')")

    key_file = tmp_path / "fim.key"
    runner.invoke(app, ["init-key", "--output", str(key_file)])

    baseline_file = tmp_path / "baseline.json"

    # Create sealed baseline
    res_base = runner.invoke(
        app,
        [
            "baseline",
            "create",
            str(monitored_dir),
            "--output",
            str(baseline_file),
            "--key",
            str(key_file),
        ],
    )
    assert res_base.exit_code == 0
    assert baseline_file.exists()
    assert "AUTHENTICATED & SEALED" in res_base.stdout

    # Verify without alterations -> exit code 0
    res_verify = runner.invoke(
        app,
        [
            "verify",
            "--baseline",
            str(baseline_file),
            "--key",
            str(key_file),
        ],
    )
    assert res_verify.exit_code == 0
    assert "No security anomalies" in res_verify.stdout


def test_cli_verify_detects_tampering(tmp_path: Path) -> None:
    monitored_dir = tmp_path / "monitored"
    monitored_dir.mkdir()
    f1 = monitored_dir / "secure_config.conf"
    f1.write_text("admin_enabled=false")

    key_file = tmp_path / "fim.key"
    runner.invoke(app, ["init-key", "--output", str(key_file)])

    baseline_file = tmp_path / "baseline.json"
    runner.invoke(
        app,
        [
            "baseline",
            "create",
            str(monitored_dir),
            "--output",
            str(baseline_file),
            "--key",
            str(key_file),
        ],
    )

    # Tamper with the monitored file
    f1.write_text("admin_enabled=true; BACKDOOR_INJECTED=1")

    # Verify should detect changes and exit with code 1
    res_verify = runner.invoke(
        app,
        [
            "verify",
            "--baseline",
            str(baseline_file),
            "--key",
            str(key_file),
        ],
    )
    assert res_verify.exit_code == 1
    assert "CONTENT_TAMPERED" in res_verify.stdout or "Security Alerts" in res_verify.stdout


def test_cli_verify_output_formats_json_and_cef(tmp_path: Path) -> None:
    monitored_dir = tmp_path / "monitored"
    monitored_dir.mkdir()
    f1 = monitored_dir / "data.txt"
    f1.write_text("original")

    baseline_file = tmp_path / "baseline.json"
    runner.invoke(
        app,
        ["baseline", "create", str(monitored_dir), "--output", str(baseline_file)],
    )

    # Add a new file
    f2 = monitored_dir / "new_payload.sh"
    f2.write_text("#!/bin/bash\nrm -rf /")

    # Test JSON output
    res_json = runner.invoke(
        app,
        ["verify", "--baseline", str(baseline_file), "--format", "json"],
    )
    assert res_json.exit_code == 1
    assert '"target_path":' in res_json.stdout

    # Test CEF output
    res_cef = runner.invoke(
        app,
        ["verify", "--baseline", str(baseline_file), "--format", "cef"],
    )
    assert res_cef.exit_code == 1
    assert "CEF:0|CyberSecurityPortfolio|FileIntegrityMonitor" in res_cef.stdout


def test_cli_verify_rejects_tampered_baseline_signature(tmp_path: Path) -> None:
    monitored_dir = tmp_path / "monitored"
    monitored_dir.mkdir()
    f = monitored_dir / "target.txt"
    f.write_text("normal")

    key_file = tmp_path / "fim.key"
    runner.invoke(app, ["init-key", "--output", str(key_file)])

    baseline_file = tmp_path / "baseline.json"
    runner.invoke(
        app,
        [
            "baseline",
            "create",
            str(monitored_dir),
            "--output",
            str(baseline_file),
            "--key",
            str(key_file),
        ],
    )

    # Tamper with the baseline file itself (adversary attempts to alter records)
    data = json.loads(baseline_file.read_text(encoding="utf-8"))
    # Invalidate signature
    data["signature"] = "deadbeef" * 8
    baseline_file.write_text(json.dumps(data), encoding="utf-8")

    # Verification must fail with exit code 2
    res_verify = runner.invoke(
        app,
        [
            "verify",
            "--baseline",
            str(baseline_file),
            "--key",
            str(key_file),
        ],
    )
    assert res_verify.exit_code == 2
    assert "CRITICAL INTEGRITY FAILURE" in res_verify.stdout


def test_cli_baseline_create_errors(tmp_path: Path) -> None:
    # 1. Non-existent path
    res = runner.invoke(app, ["baseline", "create", "/nonexistent/xyz/123"])
    assert res.exit_code == 1
    assert "does not exist" in res.stdout

    # 2. Non-existent key file
    valid_dir = tmp_path / "valid"
    valid_dir.mkdir()
    res_key = runner.invoke(
        app,
        ["baseline", "create", str(valid_dir), "--key", "/nonexistent/key.secret"],
    )
    assert res_key.exit_code == 1
    assert "not found" in res_key.stdout


def test_cli_verify_errors_and_fallbacks(tmp_path: Path) -> None:
    # 1. Non-existent baseline
    res_no_base = runner.invoke(app, ["verify", "--baseline", "/nonexistent/base.json"])
    assert res_no_base.exit_code == 2
    assert "not found" in res_no_base.stdout

    # 2. Corrupt baseline file
    corrupt = tmp_path / "corrupt.json"
    corrupt.write_text("NOT_JSON")
    res_corrupt = runner.invoke(app, ["verify", "--baseline", str(corrupt)])
    assert res_corrupt.exit_code == 2
    assert "Error loading baseline" in res_corrupt.stdout

    # 3. Sealed baseline without key
    monitored = tmp_path / "mon"
    monitored.mkdir()
    (monitored / "a.txt").write_text("content")

    key_file = tmp_path / "test.key"
    runner.invoke(app, ["init-key", "--output", str(key_file)])

    sealed_base = tmp_path / "sealed.json"
    runner.invoke(
        app,
        ["baseline", "create", str(monitored), "-o", str(sealed_base), "-k", str(key_file)],
    )

    res_no_key = runner.invoke(app, ["verify", "--baseline", str(sealed_base)])
    assert res_no_key.exit_code == 2
    assert "Baseline is sealed with HMAC signature" in res_no_key.stdout

    # 4. Sealed baseline with missing key file
    res_bad_key_path = runner.invoke(
        app,
        ["verify", "--baseline", str(sealed_base), "--key", "/missing/key.secret"],
    )
    assert res_bad_key_path.exit_code == 2
    assert "not found" in res_bad_key_path.stdout

    # 5. Invalid min_severity fallback to LOW
    res_invalid_sev = runner.invoke(
        app,
        [
            "verify",
            "--baseline",
            str(sealed_base),
            "--key",
            str(key_file),
            "--min-severity",
            "NON_EXISTENT_SEVERITY",
        ],
    )
    assert res_invalid_sev.exit_code == 0


def test_cli_watch_errors() -> None:
    # Non-existent baseline file
    res = runner.invoke(app, ["watch", "--baseline", "/nonexistent/base.json"])
    assert res.exit_code == 1
    assert "not found" in res.stdout
