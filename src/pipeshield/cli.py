from __future__ import annotations

import stat
import sys
from pathlib import Path
import click
from rich.console import Console
from rich.table import Table

from pipeshield.config import Config
from pipeshield.core.scanner import Scanner
from pipeshield.formatters.console import render_console
from pipeshield.formatters.html_out import export_html
from pipeshield.formatters.json_out import export_json
from pipeshield.formatters.sarif import export_sarif
from pipeshield.models import Severity
from pipeshield.rules.cicd_rules import CICD_RULES
from pipeshield.rules.docker_rules import DOCKER_RULES
from pipeshield.rules.secret_rules import SECRET_RULES


console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="pipeshield")
def cli() -> None:
    """PipeShield: Next-Gen DevSecOps Pipeline Security Scanner."""
    pass


@cli.command(name="scan")
@click.argument("target", default=".", type=click.Path(exists=True, file_okay=True, dir_okay=True))
@click.option(
    "--fail-on",
    type=click.Choice(["critical", "high", "medium", "low", "info"], case_sensitive=False),
    default="high",
    help="Exit with non-zero status code if findings meet or exceed this severity (default: high).",
)
@click.option(
    "--sarif",
    type=click.Path(dir_okay=False, writable=True),
    default=None,
    help="Export findings to an OASIS SARIF v2.1.0 file (for GitHub Code Scanning).",
)
@click.option(
    "--json",
    "json_out",
    type=click.Path(dir_okay=False, writable=True),
    default=None,
    help="Export findings to a JSON report file.",
)
@click.option(
    "--html",
    "html_out",
    type=click.Path(dir_okay=False, writable=True),
    default=None,
    help="Export findings to an interactive HTML Dashboard report.",
)
@click.option(
    "--ignore-rule",
    "-i",
    multiple=True,
    help="Rule ID(s) to suppress (e.g., -i PS-SEC-009). Can be repeated.",
)
@click.option(
    "--entropy-threshold",
    type=float,
    default=3.8,
    help="Minimum Shannon entropy threshold for secret detection (default: 3.8).",
)
def scan_command(
    target: str,
    fail_on: str,
    sarif: str | None,
    json_out: str | None,
    html_out: str | None,
    ignore_rule: tuple[str, ...],
    entropy_threshold: float,
) -> None:
    """Audit a repository or file for secrets, Dockerfile flaws, and CI/CD supply chain risks."""
    target_path = Path(target).resolve()
    base_dir = target_path if target_path.is_dir() else target_path.parent

    # Load configuration
    config = Config.load_from_directory(base_dir)
    config.fail_on = Severity(fail_on.upper())
    config.entropy_threshold = entropy_threshold
    for rule_id in ignore_rule:
        config.ignore_rules.add(rule_id.strip().upper())

    scanner = Scanner(config=config)

    with console.status("[bold cyan]Scanning repository for security risks...[/]", spinner="dots"):
        result = scanner.scan_path(target_path)

    # Render console view
    render_console(result, console=console)

    # Export SARIF if requested
    if sarif:
        sarif_path = Path(sarif)
        export_sarif(result, sarif_path)
        console.print(f"[bold green][+] SARIF report exported to:[/] [cyan]{sarif_path}[/]")

    # Export JSON if requested
    if json_out:
        json_path = Path(json_out)
        export_json(result, json_path)
        console.print(f"[bold green][+] JSON report exported to:[/] [cyan]{json_path}[/]")

    # Export HTML Dashboard if requested
    if html_out:
        html_path = Path(html_out)
        export_html(result, html_path)
        console.print(f"[bold green][+] Interactive HTML Dashboard exported to:[/] [cyan]{html_path}[/]")

    # Exit code based on policy
    if result.summary.failed:
        sys.exit(1)
    sys.exit(0)


@cli.command(name="rules")
def list_rules_command() -> None:
    """Display all built-in detection rules and policy definitions."""
    table = Table(
        title="PipeShield Built-in Security Rules Catalog",
        show_header=True,
        header_style="bold magenta",
        expand=True,
        border_style="dim",
    )
    table.add_column("Rule ID", style="cyan", width=14)
    table.add_column("Category", style="yellow", width=16)
    table.add_column("Severity", justify="center", width=12)
    table.add_column("CWE", style="blue", width=10)
    table.add_column("Rule Title & Description", ratio=1)

    all_rules = list(SECRET_RULES) + list(DOCKER_RULES) + list(CICD_RULES)

    for r in all_rules:
        sev_badge = f"[{r.severity.color}]{r.severity.value}[/]"
        desc = f"[bold]{r.title}[/]\n[dim]{r.description}[/]"
        table.add_row(r.id, r.category.value, sev_badge, r.cwe_id, desc)

    console.print(table)


@cli.command(name="install-hook")
@click.option("--force", "-f", is_flag=True, help="Overwrite existing pre-commit hook if present.")
def install_hook_command(force: bool) -> None:
    """Install PipeShield as a local Git pre-commit hook to block secret leaks before commit."""
    git_dir = Path(".git")
    if not git_dir.exists():
        console.print("[bold red]Error:[/] Not a git repository (missing .git directory).")
        sys.exit(1)

    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_file = hooks_dir / "pre-commit"

    if hook_file.exists() and not force:
        console.print(
            "[bold yellow]Warning:[/] .git/hooks/pre-commit already exists. Use --force to overwrite."
        )
        sys.exit(1)

    hook_content = (
        "#!/bin/sh\n"
        "# PipeShield automated pre-commit security guard\n"
        "echo 'Running PipeShield security audit...'\n"
        "pipeshield scan --fail-on high\n"
    )

    with open(hook_file, "w", encoding="utf-8", newline="\n") as f:
        f.write(hook_content)

    # Make executable on Unix-like systems
    try:
        hook_file.chmod(hook_file.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except Exception:
        pass

    console.print("[bold green][+] Pre-commit hook installed successfully at .git/hooks/pre-commit![/]")


@cli.command(name="init")
def init_config_command() -> None:
    """Generate a starter .pipeshield-ignore configuration file."""
    ignore_file = Path(".pipeshield-ignore")
    if ignore_file.exists():
        console.print("[bold yellow].pipeshield-ignore already exists in the current directory.[/]")
        return

    content = (
        "# PipeShield Ignore / Suppression Configuration\n"
        "# --------------------------------------------------\n"
        "# 1. Ignore file paths or glob patterns:\n"
        "# tests/fixtures/*\n"
        "# docs/sample_config.py\n\n"
        "# 2. Suppress a rule globally across all files:\n"
        "# PS-SEC-009\n\n"
        "# 3. Suppress a specific rule only for a particular file:\n"
        "# PS-DOCK-001:Dockerfile.local\n"
        "# PS-CICD-002:.github/workflows/experimental.yml\n"
    )

    with open(ignore_file, "w", encoding="utf-8") as f:
        f.write(content)

    console.print("[bold green][+] Generated starter .pipeshield-ignore file.[/]")


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
