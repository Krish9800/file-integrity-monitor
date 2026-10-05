"""Command-line interface for File Integrity Monitor (FIM)."""

import sys
import time
from pathlib import Path

import typer
from rich.console import Console

from fim.core.comparator import StateComparator
from fim.core.integrity import (
    IntegrityError,
    generate_key,
    load_key,
    save_key,
)
from fim.models.alert import SecurityAlert, Severity
from fim.models.baseline import BaselineCatalog
from fim.monitor.watcher import RealtimeMonitor
from fim.reporting.emitter import TelemetryEmitter
from fim.rules.policy import PolicyEngine
from fim.scanner.engine import ScanEngine

app = typer.Typer(
    name="fim",
    help="Production-Grade File Integrity Monitoring (FIM) & Anti-Tampering Engine.",
    no_args_is_help=True,
)
baseline_app = typer.Typer(
    name="baseline",
    help="Manage cryptographic filesystem baseline catalogs.",
    no_args_is_help=True,
)
app.add_typer(baseline_app, name="baseline")

console = Console()
emitter = TelemetryEmitter(console=console)


@app.command("init-key")
def init_key(
    output: Path = typer.Option(
        Path("fim.key"),
        "--output",
        "-o",
        help="Destination path for generated 256-bit HMAC key.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Overwrite existing key file if present.",
    ),
) -> None:
    """Generate a cryptographically secure 256-bit HMAC key with POSIX 0600 permissions."""
    if output.exists() and not force:
        console.print(
            f"[bold red]Error:[/bold red] Key file '{output}' already exists. Use -f to overwrite."
        )
        raise typer.Exit(code=1)

    key_bytes = generate_key()
    save_key(key_bytes, output)

    console.print(f"[bold green]✔ Generated 256-bit HMAC key at:[/bold green] {output.resolve()}")
    console.print("[yellow]Notice:[/yellow] Permissions restricted to 0600. Keep this key safe!")


@baseline_app.command("create")
def baseline_create(
    paths: list[str] = typer.Argument(
        ...,
        help="Directory or file paths to catalog in baseline.",
    ),
    output: Path = typer.Option(
        Path("baseline.json"),
        "--output",
        "-o",
        help="Destination path for sealed baseline catalog.",
    ),
    key: Path | None = typer.Option(
        None,
        "--key",
        "-k",
        help="Path to HMAC key file to cryptographically seal the baseline.",
    ),
    exclude: list[str] | None = typer.Option(
        None,
        "--exclude",
        "-e",
        help="Glob exclusion pattern (repeatable).",
    ),
) -> None:
    """Scan target filesystem trees, compute streaming dual-hashes, and generate sealed baseline."""
    resolved_paths: list[Path] = []
    for p in paths:
        path_obj = Path(p).resolve()
        if not path_obj.exists():
            console.print(f"[bold red]Error:[/bold red] Path '{p}' does not exist.")
            raise typer.Exit(code=1)
        resolved_paths.append(path_obj)

    console.print(
        f"[cyan]Scanning {len(resolved_paths)} path(s); computing SHA-256 + BLAKE2b...[/cyan]"
    )
    start_time = time.time()

    from fim.scanner.walker import SafePathWalker

    walker = SafePathWalker(exclude_patterns=exclude)
    scanner = ScanEngine(walker=walker)
    catalog = scanner.build_baseline(resolved_paths)
    elapsed = time.time() - start_time

    # Cryptographically seal if HMAC key provided
    sealed = False
    if key is not None:
        if not key.exists():
            console.print(f"[bold red]Error:[/bold red] HMAC key file '{key}' not found.")
            raise typer.Exit(code=1)
        key_bytes = load_key(key)
        catalog.seal(key_bytes)
        sealed = True

    catalog.save(output)

    console.print(
        f"[bold green]✔ Baseline catalog successfully generated:[/bold green] {output.resolve()}"
    )
    console.print(f"  • Files cataloged: [bold]{len(catalog.records)}[/bold]")
    console.print(f"  • Scan duration:   [bold]{elapsed:.3f}s[/bold]")
    if sealed:
        console.print(
            "  • HMAC Signature:  [bold green]AUTHENTICATED & SEALED (HMAC-SHA256)[/bold green]"
        )
    else:
        console.print("  • HMAC Signature:  [yellow]UNSEALED (No HMAC key provided)[/yellow]")


@app.command("verify")
def verify(
    baseline_path: Path = typer.Option(
        Path("baseline.json"),
        "--baseline",
        "-b",
        help="Path to reference baseline catalog.",
    ),
    key: Path | None = typer.Option(
        None,
        "--key",
        "-k",
        help="HMAC key file to authenticate baseline catalog.",
    ),
    output_format: str = typer.Option(
        "table",
        "--format",
        "-f",
        help="Output format: table, json, cef.",
    ),
    min_severity: str = typer.Option(
        "LOW",
        "--min-severity",
        "-s",
        help="Minimum severity threshold: CRITICAL, HIGH, MEDIUM, LOW, INFO.",
    ),
) -> None:
    """Verify live filesystem state against cryptographic baseline catalog."""
    if not baseline_path.exists():
        console.print(f"[bold red]Error:[/bold red] Baseline file '{baseline_path}' not found.")
        raise typer.Exit(code=2)

    try:
        baseline = BaselineCatalog.load(baseline_path)
    except Exception as e:
        console.print(f"[bold red]Error loading baseline:[/bold red] {e}")
        raise typer.Exit(code=2) from e

    # 1. Cryptographic Baseline Authenticity Verification
    if baseline.signature is not None:
        if key is None:
            console.print(
                "[bold red]Integrity Error:[/bold red] Baseline is sealed with HMAC signature, "
                "but no HMAC key was provided via --key to verify authenticity."
            )
            raise typer.Exit(code=2)
        if not key.exists():
            console.print(f"[bold red]Integrity Error:[/bold red] HMAC key file '{key}' not found.")
            raise typer.Exit(code=2)

        key_bytes = load_key(key)
        try:
            if not baseline.verify_integrity(key_bytes):
                console.print(
                    "[bold red]CRITICAL INTEGRITY FAILURE:[/bold red] "
                    "Baseline HMAC signature does not match! "
                    "The baseline database has been tampered with or corrupted."
                )
                raise typer.Exit(code=2)
        except IntegrityError as err:
            console.print(f"[bold red]Integrity Error:[/bold red] {err}")
            raise typer.Exit(code=2) from err

    # 2. Rescan live targets
    root_paths = [Path(p) for p in baseline.root_paths]
    scanner = ScanEngine()
    start_time = time.time()
    live_records = scanner.scan_live_state(root_paths)
    scan_duration = time.time() - start_time

    # 3. Compare differential state
    report = StateComparator.compare(baseline, live_records, scan_duration)

    # 4. Evaluate threats
    policy_engine = PolicyEngine()
    alerts = policy_engine.evaluate_report(report)

    # 5. Filter by severity
    try:
        sev_threshold = Severity(min_severity.upper())
    except ValueError:
        sev_threshold = Severity.LOW

    filtered_alerts = PolicyEngine.filter_alerts(alerts, min_severity=sev_threshold)

    # 6. Emit output
    if output_format == "json":
        emitter.emit_json_lines(filtered_alerts, sys.stdout)
    elif output_format == "cef":
        emitter.emit_cef(filtered_alerts, sys.stdout)
    else:
        emitter.print_scan_report(report)
        emitter.print_alerts_table(filtered_alerts)

    # Exit code: 0 if clean, 1 if modifications/alerts present
    has_changes = (
        bool(filtered_alerts)
        or report.modified_count > 0
        or report.deleted_count > 0
        or report.added_count > 0
    )
    if has_changes:
        raise typer.Exit(code=1)


@app.command("watch")
def watch(
    paths: list[str] | None = typer.Argument(
        None,
        help="Directories or files to watch (defaults to baseline roots).",
    ),
    baseline_path: Path = typer.Option(
        Path("baseline.json"),
        "--baseline",
        "-b",
        help="Reference baseline catalog file.",
    ),
    key: Path | None = typer.Option(
        None,
        "--key",
        "-k",
        help="HMAC key file to verify baseline authenticity.",
    ),
    output_format: str = typer.Option(
        "console",
        "--format",
        "-f",
        help="Output format: console, json, cef.",
    ),
    log_file: Path | None = typer.Option(
        None,
        "--log-file",
        "-l",
        help="Persistent file to append security alerts in real-time.",
    ),
) -> None:
    """Continuously monitor filesystem in real-time and stream security alerts."""
    if not baseline_path.exists():
        console.print(f"[bold red]Error:[/bold red] Baseline file '{baseline_path}' not found.")
        raise typer.Exit(code=1)

    baseline = BaselineCatalog.load(baseline_path)
    if baseline.signature is not None and key is not None:
        key_bytes = load_key(key)
        if not baseline.verify_integrity(key_bytes):
            console.print("[bold red]CRITICAL:[/bold red] Baseline HMAC verification failed.")
            raise typer.Exit(code=2)

    # If user provided explicit paths to watch, override root_paths in baseline
    if paths:
        baseline.root_paths = [Path(p).resolve().as_posix() for p in paths]

    policy_engine = PolicyEngine()

    def handle_alert(alert: SecurityAlert) -> None:
        if output_format == "json":
            print(alert.model_dump_json())
        elif output_format == "cef":
            print(alert.to_cef())
        else:
            emitter.print_alert(alert)

        if log_file is not None:
            emitter.log_alert_to_file(alert, log_file, as_cef=(output_format == "cef"))

    monitor = RealtimeMonitor(
        baseline=baseline,
        policy_engine=policy_engine,
        alert_callback=handle_alert,
    )

    console.print("[bold green]Starting real-time FIM kernel observer daemon...[/bold green]")
    for r in baseline.root_paths:
        console.print(f"  • Watching target: [cyan]{r}[/cyan]")
    console.print("[yellow]Press Ctrl+C to terminate.[/yellow]\n")

    try:
        monitor.start()
        while monitor.is_alive:
            time.sleep(0.5)
    except KeyboardInterrupt:
        console.print("\n[yellow]Shutdown signal received. Stopping observer...[/yellow]")
    finally:
        monitor.stop()
        console.print("[bold green]Observer stopped cleanly.[/bold green]")


@app.command("version")
def version() -> None:
    """Print FIM version and cryptographic capabilities."""
    console.print("[bold cyan]File Integrity Monitoring (FIM) Engine[/bold cyan]")
    console.print("  • Version:          0.1.0")
    console.print("  • Hashing Algos:    SHA-256, BLAKE2b (64KB streaming)")
    console.print("  • Baseline Auth:    HMAC-SHA256 (Constant-time verification)")
    console.print("  • Kernel Observer:  Inotify / FileSystemEventHandler")
    console.print("  • SIEM Telemetry:   JSON Lines, ArcSight CEF")
