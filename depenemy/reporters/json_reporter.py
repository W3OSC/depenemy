"""JSON reporter — raw structured output."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from depenemy.types import ScanResult


def generate_json(result: ScanResult) -> dict[str, Any]:
    return {
        "summary": {
            "packages": len(result.dependencies),
            "findings": len(result.findings),
            "errors": len(result.errors),
            "warnings": len(result.warnings),
            "infos": len(result.infos),
            "scanned_files": result.scanned_files,
        },
        "findings": [
            {
                "rule_id": f.rule_id,
                "rule_name": f.rule_name,
                "severity": f.severity.value,
                "package": f.dependency.name,
                "ecosystem": f.dependency.ecosystem.value,
                "version_spec": f.dependency.version_spec,
                "resolved_version": f.dependency.resolved_version,
                "file": f.dependency.location.file,
                "line": f.dependency.location.line,
                "message": f.message,
                "actual": f.actual,
                "expected": f.expected,
            }
            for f in result.findings
        ],
    }


def write_json(result: ScanResult, output: Path) -> None:
    output.write_text(json.dumps(generate_json(result), indent=2))
