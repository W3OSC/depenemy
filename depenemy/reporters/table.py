"""Rich terminal table reporter."""

from __future__ import annotations

from rich.console import Console
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

_SEVERITY_LEVEL = {
    Severity.ERROR: 2,
    Severity.WARNING: 1,
    Severity.INFO: 0,
}


def print_table(result: ScanResult, console: Console | None = None) -> None:
    console = console or Console()

    if not result.findings:
        console.print("\n[green]✓ No issues found.[/green]\n")
        return

    # Group findings by rule
    findings_by_rule: dict[str, list[Finding]] = {}
    for f in result.findings:
        findings_by_rule.setdefault(f.rule_id, []).append(f)

    # Sort: errors first, then warnings, then by rule ID
    def _sort_key(item: tuple[str, list[Finding]]) -> tuple[int, str]:
        _, findings = item
        worst = max(findings, key=lambda f: _SEVERITY_LEVEL[f.severity])
        return (-_SEVERITY_LEVEL[worst.severity], item[0])

    sorted_rules = sorted(findings_by_rule.items(), key=_sort_key)

    console.print()
    console.print("[bold]Depenemy Scan Results[/bold]")
    console.print()

    for rule_id, findings in sorted_rules:
        worst = max(findings, key=lambda f: _SEVERITY_LEVEL[f.severity])
        color = _SEVERITY_COLORS[worst.severity]
        icon = _SEVERITY_ICONS[worst.severity]
        rule_name = findings[0].rule_name
        count = len(findings)
        label = f"package{'s' if count != 1 else ''}"

        # Rule header
        console.print(
            Text.assemble(
                (f"{icon} {rule_id}", f"bold {color}"),
                (" · ", "bold bright_black"),
                (rule_name, "bold"),
                ("  ", ""),
                (f"[{count} {label}]", "bright_black"),
            )
        )

        # Package list under the rule
        for f in findings:
            dep = f.dependency
            line = Text("  • ", style="bright_black")
            line.append(dep.name, style="bold")
            line.append(f"  ({dep.ecosystem.value})", style="bright_black")
            if f.actual:
                line.append(f"  {f.actual}", style=color)
            if f.expected:
                line.append(f"  →  {f.expected}", style="green")
            console.print(line)

        console.print()

    _print_summary(result, console)


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
        f"[bold]Summary:[/bold] {len(result.dependencies)} packages scanned - {summary}\n"
    )
