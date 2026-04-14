"""CLI entry point for depenemy."""

from __future__ import annotations

import json
import sys
from enum import Enum
from pathlib import Path
from typing import Optional

import anyio
import typer
from rich.console import Console

from depenemy import __version__
from depenemy.config import load_config
from depenemy.rules import ALL_RULES
from depenemy.scanner import scan
from depenemy.types import Severity

app = typer.Typer(
    name="depenemy",
    help="Dependency scanner that finds your enemies in the supply chain.",
    add_completion=False,
    rich_markup_mode="rich",
)

console = Console()


class OutputFormat(str, Enum):
    table = "table"
    sarif = "sarif"
    json = "json"


class FailOn(str, Enum):
    error = "error"
    warning = "warning"
    info = "info"
    never = "never"


@app.command(name="scan")
def cmd_scan(
    paths: Optional[list[Path]] = typer.Argument(
        default=None,
        help="Paths to scan. Defaults to current directory.",
    ),
    output: OutputFormat = typer.Option(
        OutputFormat.table, "--output", "-o", help="Output format."
    ),
    output_file: Optional[Path] = typer.Option(
        None, "--output-file", "-f", help="Write output to file."
    ),
    fail_on: FailOn = typer.Option(
        FailOn.error,
        "--fail-on",
        help="Exit non-zero if findings at this severity or above exist.",
    ),
    config_path: Optional[Path] = typer.Option(
        None, "--config", "-c", help="Path to .depenemy.yml."
    ),
    no_cache: bool = typer.Option(False, "--no-cache", help="Disable disk cache."),
    github_token: Optional[str] = typer.Option(
        None, "--github-token", envvar="GITHUB_TOKEN", help="GitHub token for API calls."
    ),
) -> None:
    """Scan dependencies for supply chain risks, reputation issues, and behavioral problems."""
    if not paths:
        paths = [Path(".")]
    config = load_config(config_path)
    config.no_cache = no_cache
    if github_token:
        config.github_token = github_token

    console.print(f"\n[bold]depenemy[/bold] v{__version__} - scanning {len(paths)} path(s)...\n")

    result = anyio.run(scan, paths, config)

    # Always write full results to JSON (table view only shows first 5 per rule)
    if output == OutputFormat.table and not output_file:
        from depenemy.reporters.json_reporter import write_json
        json_path = Path("depenemy-results.json")
        write_json(result, json_path)

    if output == OutputFormat.table:
        from depenemy.reporters.table import print_table

        if output_file:
            out_console = Console(file=output_file.open("w"), highlight=False)
            print_table(result, console=out_console)
        else:
            print_table(result, console=console)
            console.print(f"[bright_black]Full results → [bold]depenemy-results.json[/bold][/bright_black]\n")

    elif output == OutputFormat.sarif:
        from depenemy.reporters.sarif import generate_sarif, write_sarif
        if output_file:
            write_sarif(result, output_file)
            console.print(f"SARIF written to [bold]{output_file}[/bold]")
        else:
            sys.stdout.write(json.dumps(generate_sarif(result), indent=2) + "\n")

    elif output == OutputFormat.json:
        from depenemy.reporters.json_reporter import generate_json, write_json
        if output_file:
            write_json(result, output_file)
            console.print(f"JSON written to [bold]{output_file}[/bold]")
        else:
            sys.stdout.write(json.dumps(generate_json(result), indent=2) + "\n")

    # Set GitHub Actions outputs if running in CI
    _set_github_outputs(result)

    # Exit code
    if fail_on == FailOn.never:
        raise typer.Exit(0)

    severity_threshold = {
        FailOn.error: Severity.ERROR,
        FailOn.warning: Severity.WARNING,
        FailOn.info: Severity.INFO,
    }[fail_on]

    has_failure = any(f.severity >= severity_threshold for f in result.findings)
    raise typer.Exit(1 if has_failure else 0)


@app.command(name="rules")
def cmd_rules() -> None:
    """List all available rules and their descriptions."""
    from rich import box
    from rich.table import Table

    table = Table(title="depenemy Rules", box=box.ROUNDED, expand=True)
    table.add_column("ID", style="bold cyan", width=6)
    table.add_column("Name", min_width=25)
    table.add_column("Description", overflow="fold")

    for rule in ALL_RULES:
        table.add_row(rule.id, rule.name, rule.description)

    console.print(table)


@app.command(name="version")
def cmd_version() -> None:
    """Print version and exit."""
    console.print(f"depenemy v{__version__}")


def _set_github_outputs(result: object) -> None:
    """Write GitHub Actions output variables if GITHUB_OUTPUT is set."""
    import os
    output_file = os.environ.get("GITHUB_OUTPUT")
    if not output_file:
        return
    try:
        from depenemy.types import ScanResult
        if not isinstance(result, ScanResult):
            return
        with open(output_file, "a") as f:
            f.write(f"findings-count={len(result.findings)}\n")
            f.write(f"errors-count={len(result.errors)}\n")
    except OSError:
        pass


if __name__ == "__main__":
    app()
