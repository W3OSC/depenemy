"""Rich terminal table reporter."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich import box
from rich.text import Text

from depenemy.types import Finding, ScanResult, Severity

_SEVERITY_COLORS = {
    Severity.ERROR: "red",
    Severity.WARNING: "yellow",
    Severity.INFO: "cyan",
}

_SEVERITY_ICONS = {
    Severity.ERROR: "✗",
    Severity.WARNING: "⚠",
    Severity.INFO: "i",
}


def print_table(result: ScanResult, console: Console | None = None) -> None:
    console = console or Console()

    if not result.findings:
        console.print("\n[green]✓ No issues found.[/green]\n")
        return

    # Group findings by dependency
    findings_by_dep: dict[str, list[Finding]] = {}
    for f in result.findings:
        key = f"{f.dependency.ecosystem.value}:{f.dependency.name}"
        findings_by_dep.setdefault(key, []).append(f)

    table = Table(
        title="Depenemy Scan Results",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold white",
        border_style="bright_black",
        expand=True,
    )

    table.add_column("Package", style="bold", min_width=20)
    table.add_column("Ecosystem", min_width=6)
    table.add_column("Version", min_width=12)
    table.add_column("File", min_width=20, overflow="fold")
    table.add_column("Issues", min_width=40, overflow="fold")

    for key, findings in sorted(findings_by_dep.items()):
        dep = findings[0].dependency
        issues = _format_issues(findings)

        # Worst severity determines row styling
        worst = max(findings, key=lambda f: list(Severity).index(f.severity))
        row_style = ""
        if worst.severity == Severity.ERROR:
            row_style = "on dark_red" if False else ""  # keep it clean

        table.add_row(
            dep.name,
            dep.ecosystem.value,
            dep.resolved_version or dep.version_spec,
            f"{dep.location.file}:{dep.location.line}",
            issues,
            style=row_style,
        )

    console.print()
    console.print(table)
    _print_summary(result, console)


def _format_issues(findings: list[Finding]) -> Text:
    text = Text()
    for i, f in enumerate(findings):
        color = _SEVERITY_COLORS[f.severity]
        icon = _SEVERITY_ICONS[f.severity]
        if i > 0:
            text.append("\n")
        text.append(f"[{f.rule_id}] ", style="bold bright_black")
        text.append(f"{icon} ", style=f"bold {color}")
        text.append(f.message, style=color)
    return text


def _print_summary(result: ScanResult, console: Console) -> None:
    errors = len(result.errors)
    warnings = len(result.warnings)
    infos = len(result.infos)

    parts = []
    if errors:
        parts.append(f"[red]{errors} error(s)[/red]")
    if warnings:
        parts.append(f"[yellow]{warnings} warning(s)[/yellow]")
    if infos:
        parts.append(f"[cyan]{infos} info(s)[/cyan]")

    summary = ", ".join(parts) if parts else "[green]no issues[/green]"
    console.print(
        f"\n[bold]Summary:[/bold] {len(result.dependencies)} packages scanned — {summary}\n"
    )
