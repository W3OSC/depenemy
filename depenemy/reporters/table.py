"""Rich terminal table reporter."""

from __future__ import annotations

from rich.console import Console
from rich.text import Text

from depenemy.rules import ALL_RULES
from depenemy.types import Finding, ScanResult, Severity

_RULE_DESCRIPTIONS: dict[str, str] = {r.id: r.description for r in ALL_RULES}

_SEVERITY_COLORS = {
    Severity.ERROR: "red",
    Severity.WARNING: "yellow",
    Severity.INFO: "cyan",
}

_SEVERITY_ICONS = {
    Severity.ERROR: "ERROR",
    Severity.WARNING: "WARNING",
    Severity.INFO: "INFO",
}

_SEVERITY_LEVEL = {
    Severity.ERROR: 2,
    Severity.WARNING: 1,
    Severity.INFO: 0,
}

_PREVIEW_LIMIT = 5


def _first_sentence(text: str) -> str:
    """Return only the first sentence of a description."""
    end = text.find(". ")
    return text[: end + 1] if end != -1 else text


def print_table(result: ScanResult, console: Console | None = None) -> None:
    console = console or Console()

    if not result.findings:
        console.print()
        console.print("[green]  ✓  No issues found.[/green]")
        console.print()
        return

    # Group findings by rule
    findings_by_rule: dict[str, list[Finding]] = {}
    for f in result.findings:
        findings_by_rule.setdefault(f.rule_id, []).append(f)

    # Sort: errors first, then warnings, then by rule ID
    def _sort_key(item: tuple[str, list[Finding]]) -> tuple[int, str]:
        rule_id, findings = item
        worst = max(findings, key=lambda f: _SEVERITY_LEVEL[f.severity])
        return (-_SEVERITY_LEVEL[worst.severity], rule_id)

    sorted_rules = sorted(findings_by_rule.items(), key=_sort_key)

    console.rule("[bold]depenemy[/bold]", style="bright_black")
    console.print()

    for rule_id, findings in sorted_rules:
        worst = max(findings, key=lambda f: _SEVERITY_LEVEL[f.severity])
        color = _SEVERITY_COLORS[worst.severity]
        icon = _SEVERITY_ICONS[worst.severity]
        rule_name = findings[0].rule_name
        count = len(findings)
        label = f"package{'s' if count != 1 else ''}"

        # Rule header: colored badge + ID + name + count
        header = Text()
        header.append(f" {icon} ", style=f"bold white on {color}")
        header.append(f"  {rule_id}", style=f"bold {color}")
        header.append("  ", style="")
        header.append(rule_name, style="bold")
        header.append(f"  ·  {count} {label}", style="bright_black")
        console.print(header)

        # Description - first sentence only, dimmed
        description = _RULE_DESCRIPTIONS.get(rule_id, "")
        if description:
            console.print(f"     [italic bright_black]{_first_sentence(description)}[/italic bright_black]")

        console.print()

        # Package rows - manually aligned
        visible = findings[:_PREVIEW_LIMIT]
        max_name = max(len(f.dependency.name) for f in visible)
        max_eco = max(len(f.dependency.ecosystem.value) for f in visible)

        for f in visible:
            dep = f.dependency
            line = Text("     ")
            line.append(dep.name.ljust(max_name), style="bold")
            line.append(f"  {dep.ecosystem.value.ljust(max_eco)}", style="bright_black")
            if f.actual:
                line.append(f"  {f.actual}", style=color)
            if f.expected:
                line.append(f"  →  {f.expected}", style="green")
            console.print(line)

        overflow = count - _PREVIEW_LIMIT
        if overflow > 0:
            console.print(
                f"     [bright_black]+ {overflow} more  ·  see depenemy-results.json[/bright_black]"
            )

        console.print()

    _print_summary(result, console)


def _print_summary(result: ScanResult, console: Console) -> None:
    errors = len(result.errors)
    warnings = len(result.warnings)
    infos = len(result.infos)

    console.rule(style="bright_black")
    console.print()

    summary = Text("  ")
    pkg_label = f"package{'s' if len(result.dependencies) != 1 else ''}"
    summary.append(f"{len(result.dependencies)} {pkg_label} scanned", style="bold")
    summary.append("   ", style="")

    if errors:
        summary.append(f"{errors} error{'s' if errors != 1 else ''}", style="bold red")
    else:
        summary.append("0 errors", style="bright_black")

    summary.append("   ", style="")

    if warnings:
        summary.append(f"{warnings} warning{'s' if warnings != 1 else ''}", style="bold yellow")
    else:
        summary.append("0 warnings", style="bright_black")

    if infos:
        summary.append("   ", style="")
        summary.append(f"{infos} info", style="bold cyan")

    console.print(summary)
    console.print()
