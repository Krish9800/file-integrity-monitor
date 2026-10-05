"""Telemetry emitter supporting console rendering, JSON streaming, and ArcSight CEF logging."""

from pathlib import Path
from typing import TextIO

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from fim.models.alert import SecurityAlert, Severity
from fim.models.delta import ScanReport


class TelemetryEmitter:
    """Dispatches security events to local terminals, files, and SIEM pipelines."""

    def __init__(self, console: Console | None = None) -> None:
        """Initialize emitter with optional Rich console."""
        self.console = console or Console()

    def print_scan_report(self, report: ScanReport) -> None:
        """Render a high-level summary of filesystem scan results."""
        table = Table(
            title="Filesystem Integrity Scan Summary",
            show_header=True,
            header_style="bold cyan",
        )
        table.add_column("Metric", style="bold")
        table.add_column("Count", justify="right")

        table.add_row("Total Scanned Files", str(report.total_scanned))
        table.add_row("Unaltered Files", f"[green]{report.unaltered_count}[/green]")
        table.add_row(
            "Added Files",
            f"[yellow]{report.added_count}[/yellow]" if report.added_count else "0",
        )
        table.add_row(
            "Deleted Files",
            f"[red]{report.deleted_count}[/red]" if report.deleted_count else "0",
        )
        table.add_row(
            "Modified Files",
            f"[bold red]{report.modified_count}[/bold red]" if report.modified_count else "0",
        )
        table.add_row("Scan Duration", f"{report.scan_duration_seconds:.3f} seconds")

        self.console.print(table)

    def print_alert(self, alert: SecurityAlert) -> None:
        """Render a single security alert as an eye-catching Rich panel."""
        color_map = {
            Severity.CRITICAL: "bold white on red",
            Severity.HIGH: "bold red",
            Severity.MEDIUM: "bold yellow",
            Severity.LOW: "bold cyan",
            Severity.INFO: "bold green",
        }
        style = color_map.get(alert.severity, "bold white")

        diff_summary = ""
        if alert.details:
            diff_lines = [
                f"  • [bold]{k}[/bold]: {v[0]} -> [bold]{v[1]}[/bold]"
                for k, v in alert.details.items()
            ]
            diff_summary = "\n[bold]Differences:[/bold]\n" + "\n".join(diff_lines)

        content = (
            f"[bold]Target File:[/bold] {alert.target_path}\n"
            f"[bold]Category:[/bold]    {alert.category}\n"
            f"[bold]Change Type:[/bold] {alert.change_type.value}\n"
            f"[bold]Description:[/bold] {alert.description}\n"
            f"[bold]Action:[/bold]      {alert.recommendation}"
            f"{diff_summary}"
        )

        self.console.print(
            Panel(
                content,
                title=f"[{style}] SECURITY ALERT: {alert.severity.value} [/{style}]",
                border_style=("red" if alert.severity == Severity.CRITICAL else "yellow"),
            )
        )

    def print_alerts_table(self, alerts: list[SecurityAlert]) -> None:
        """Render a consolidated table of security alerts."""
        if not alerts:
            self.console.print(
                "[bold green]✔ No security anomalies or baseline deviations detected.[/bold green]"
            )
            return

        table = Table(
            title=f"Security Alerts ({len(alerts)} detected)",
            show_header=True,
            header_style="bold magenta",
        )
        table.add_column("Severity", style="bold", width=10)
        table.add_column("Category", width=25)
        table.add_column("Target Path", width=35)
        table.add_column("Description", width=40)

        for alert in alerts:
            sev_color = {
                Severity.CRITICAL: "[bold red]CRITICAL[/bold red]",
                Severity.HIGH: "[red]HIGH[/red]",
                Severity.MEDIUM: "[yellow]MEDIUM[/yellow]",
                Severity.LOW: "[cyan]LOW[/cyan]",
                Severity.INFO: "[green]INFO[/green]",
            }.get(alert.severity, alert.severity.value)

            table.add_row(
                sev_color,
                alert.category,
                alert.target_path,
                alert.description,
            )

        self.console.print(table)

    @staticmethod
    def emit_json_lines(alerts: list[SecurityAlert], stream: TextIO) -> None:
        """Stream alerts as JSON Lines format."""
        for alert in alerts:
            stream.write(alert.model_dump_json() + "\n")
            stream.flush()

    @staticmethod
    def emit_cef(alerts: list[SecurityAlert], stream: TextIO) -> None:
        """Stream alerts formatted as ArcSight Common Event Format (CEF)."""
        for alert in alerts:
            stream.write(alert.to_cef() + "\n")
            stream.flush()

    @staticmethod
    def log_alert_to_file(alert: SecurityAlert, file_path: Path, as_cef: bool = False) -> None:
        """Append an individual alert to a persistent log file."""
        file_path.parent.mkdir(parents=True, exist_ok=True)
        line = alert.to_cef() if as_cef else alert.model_dump_json()
        with file_path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
