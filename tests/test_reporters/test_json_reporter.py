"""Tests for the JSON reporter."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from depenemy.reporters.json_reporter import generate_json, write_json
from depenemy.types import Dependency, Ecosystem, Finding, Location, ScanResult, Severity


def _make_dep(name: str = "lodash") -> Dependency:
    return Dependency(
        name=name,
        version_spec="^4.0.0",
        ecosystem=Ecosystem.NPM,
        location=Location(file="package.json", line=5),
    )


def _make_finding(dep: Dependency | None = None) -> Finding:
    d = dep or _make_dep()
    return Finding(
        rule_id="B001",
        rule_name="Range specifier",
        severity=Severity.WARNING,
        dependency=d,
        message="`lodash` uses range `^4.0.0`",
        actual="^4.0.0",
        expected=None,
    )


def _make_result(findings: list[Finding] | None = None) -> ScanResult:
    dep = _make_dep()
    return ScanResult(
        dependencies=[dep],
        findings=findings or [],
        scanned_files=["package.json"],
    )


class TestGenerateJson(unittest.TestCase):
    def test_has_summary_key(self) -> None:
        data = generate_json(_make_result())
        self.assertIn("summary", data)

    def test_has_findings_key(self) -> None:
        data = generate_json(_make_result())
        self.assertIn("findings", data)

    def test_summary_package_count(self) -> None:
        data = generate_json(_make_result())
        self.assertEqual(data["summary"]["packages"], 1)

    def test_summary_findings_count(self) -> None:
        data = generate_json(_make_result(findings=[_make_finding()]))
        self.assertEqual(data["summary"]["findings"], 1)

    def test_summary_errors_count(self) -> None:
        finding = _make_finding()
        finding.severity = Severity.ERROR
        data = generate_json(_make_result(findings=[finding]))
        self.assertEqual(data["summary"]["errors"], 1)
        self.assertEqual(data["summary"]["warnings"], 0)

    def test_finding_fields(self) -> None:
        dep = _make_dep("axios")
        finding = _make_finding(dep)
        data = generate_json(_make_result(findings=[finding]))
        f = data["findings"][0]
        self.assertEqual(f["rule_id"], "B001")
        self.assertEqual(f["package"], "axios")
        self.assertEqual(f["ecosystem"], "npm")
        self.assertEqual(f["severity"], "warning")
        self.assertEqual(f["version_spec"], "^4.0.0")
        self.assertEqual(f["file"], "package.json")
        self.assertEqual(f["line"], 5)

    def test_empty_findings_list(self) -> None:
        data = generate_json(_make_result(findings=[]))
        self.assertEqual(data["findings"], [])
        self.assertEqual(data["summary"]["findings"], 0)

    def test_scanned_files_in_summary(self) -> None:
        data = generate_json(_make_result())
        self.assertIn("package.json", data["summary"]["scanned_files"])

    def test_all_findings_included(self) -> None:
        deps = [_make_dep(f"pkg-{i}") for i in range(10)]
        findings = [_make_finding(d) for d in deps]
        result = ScanResult(dependencies=deps, findings=findings, scanned_files=["package.json"])
        data = generate_json(result)
        self.assertEqual(len(data["findings"]), 10)


class TestWriteJson(unittest.TestCase):
    def test_creates_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "results.json"
            write_json(_make_result(), path)
            self.assertTrue(path.exists())

    def test_file_is_valid_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "results.json"
            write_json(_make_result(findings=[_make_finding()]), path)
            data = json.loads(path.read_text())
            self.assertIn("summary", data)
            self.assertIn("findings", data)

    def test_file_contains_all_findings(self) -> None:
        deps = [_make_dep(f"pkg-{i}") for i in range(7)]
        findings = [_make_finding(d) for d in deps]
        result = ScanResult(dependencies=deps, findings=findings, scanned_files=["package.json"])
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "results.json"
            write_json(result, path)
            data = json.loads(path.read_text())
            self.assertEqual(len(data["findings"]), 7)


if __name__ == "__main__":
    unittest.main()
