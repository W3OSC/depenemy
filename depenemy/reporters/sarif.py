"""SARIF 2.1.0 reporter - compatible with GitHub Code Scanning."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from depenemy import __version__
from depenemy.rules import ALL_RULES
from depenemy.types import Finding, ScanResult, Severity

_LEVEL_MAP = {
    Severity.ERROR: "error",
    Severity.WARNING: "warning",
    Severity.INFO: "note",
}


def generate_sarif(result: ScanResult) -> dict[str, Any]:
    rules = [
        {
            "id": rule.id,
            "name": rule.name,
            "shortDescription": {"text": rule.name},
            "fullDescription": {"text": rule.description},
            "helpUri": f"https://github.com/W3OSC/depenemy/blob/main/docs/rules/{rule.id.lower()}.md",
            "properties": {"tags": ["supply-chain", "security"]},
        }
        for rule in ALL_RULES
    ]

    results = [_finding_to_sarif(f) for f in result.findings]

    return {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "depenemy",
                        "version": __version__,
                        "informationUri": "https://github.com/W3OSC/depenemy",
                        "rules": rules,
                    }
                },
                "results": results,
                "artifacts": [
                    {"location": {"uri": f}, "description": {"text": "Scanned manifest"}}
                    for f in result.scanned_files
                ],
            }
        ],
    }


def write_sarif(result: ScanResult, output: Path) -> None:
    data = generate_sarif(result)
    output.write_text(json.dumps(data, indent=2))


def _finding_to_sarif(finding: Finding) -> dict[str, Any]:
    message = finding.message
    if finding.actual and finding.expected:
        message += f" (actual: {finding.actual}, expected: {finding.expected})"

    loc = finding.dependency.location
    return {
        "ruleId": finding.rule_id,
        "level": _LEVEL_MAP[finding.severity],
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": loc.file,
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {
                        "startLine": loc.line,
                        "startColumn": loc.column,
                    },
                }
            }
        ],
        "properties": {
            "actual": finding.actual,
            "expected": finding.expected,
        },
    }
