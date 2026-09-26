from __future__ import annotations

from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from pipeshield.models import ScanResult, Severity


BANNER = r"""
[bold cyan]  _____  _             _____ _     _      _     _ 
 |  __ \(_)           / ____| |   (_)    | |   | |
 | |__) |_ _ __   ___| (___ | |__  _  ___| | __| |
 |  ___/| | '_ \ / _ \\___ \| '_ \| |/ _ \ |/ _` |
 | |    | | |_) |  __/____) | | | | |  __/ | (_| |
 |_|    |_| .__/ \___|_____/|_| |_|_|\___|_|\__,_|
          | |   [bold white]Next-Gen DevSecOps Pipeline Security Scanner[/]
          |_|[/]
"""


def render_console(result: ScanResult, console: Console | None = None) -> None:
    """Render findings and scan summary in a clean, professional terminal UI using Rich."""
    c = console or Console()

    # Print logo banner
    c.print(BANNER)

    if not result.findings:
        c.print(
            Panel(
                "[bold green][+] No security vulnerabilities or policy violations detected![/]\n"
                f"Scanned [bold]{result.summary.scanned_files}[/] files in [bold]{result.summary.scan_duration_ms:.2f} ms[/].",
                title="[bold green]Scan Result: CLEAN[/]",
                border_style="green",
            )
        )
        return

    # Table of findings
    table = Table(
        title=f"Security Audit Findings ({len(result.findings)} detected)",
        show_header=True,
        header_style="bold magenta",
        expand=True,
        border_style="dim",
    )

    table.add_column("Severity", justify="center", width=12)
    table.add_column("Rule ID", style="cyan", width=13)
    table.add_column("Location", style="white", width=32)
    table.add_column("Title & Snippet", ratio=1)

    for f in result.findings:
        sev_badge = Text(f.severity.value, style=f.severity.color)

        try:
            rel_path = Path(f.file_path).name
        except Exception:
            rel_path = f.file_path

        loc = f"{rel_path}:{f.line_number}"

        desc_text = Text()
        desc_text.append(f"{f.title}\n", style="bold white")
        desc_text.append(f"Snippet: {f.snippet}\n", style="dim italic")
        desc_text.append(f"Fix: {f.remediation}", style="green")

        table.add_row(sev_badge, f.rule_id, loc, desc_text)

    c.print(table)
    c.print()

    # Summary Panel
    crit = f"[bold red]{result.summary.critical_count} CRITICAL[/]"
    high = f"[bright_red]{result.summary.high_count} HIGH[/]"
    med = f"[yellow]{result.summary.medium_count} MEDIUM[/]"
    low = f"[cyan]{result.summary.low_count} LOW[/]"

    status_str = (
        "[bold red][FAIL] SCAN FAILED[/] (Threshold exceeded)"
        if result.summary.failed
        else "[bold green][OK] SCAN PASSED[/] (Below failure threshold)"
    )

    summary_text = (
        f"Files Scanned: [bold]{result.summary.scanned_files}[/]  |  "
        f"Total Findings: [bold]{result.summary.total_findings}[/]  |  "
        f"Duration: [bold]{result.summary.scan_duration_ms:.2f} ms[/]\n"
        f"Breakdown: {crit}  |  {high}  |  {med}  |  {low}\n\n"
        f"Status: {status_str}"
    )

    panel_border = "red" if result.summary.failed else "green"
    c.print(
        Panel(
            summary_text,
            title="[bold]PipeShield Executive Summary[/]",
            border_style=panel_border,
        )
    )
