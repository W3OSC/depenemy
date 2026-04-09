"""Tests for the SARIF reporter."""

from __future__ import annotations

import unittest

from depenemy.reporters.sarif import generate_sarif
from depenemy.types import Dependency, Ecosystem, Finding, Location, ScanResult, Severity


def _make_result(findings: list[Finding] | None = None) -> ScanResult:
    dep = Dependency(
        name="lodash",
        version_spec="^4.0.0",
        ecosystem=Ecosystem.NPM,
        location=Location(file="package.json", line=5, column=3),
    )
    return ScanResult(dependencies=[dep], findings=findings or [], scanned_files=["package.json"])


class TestSarifReporter(unittest.TestCase):
    def test_sarif_version(self) -> None:
        sarif = generate_sarif(_make_result())
        self.assertEqual(sarif["version"], "2.1.0")

    def test_sarif_has_runs(self) -> None:
        sarif = generate_sarif(_make_result())
        self.assertEqual(len(sarif["runs"]), 1)

    def test_sarif_tool_name(self) -> None:
        sarif = generate_sarif(_make_result())
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["name"], "depenemy")

    def test_finding_maps_to_result(self) -> None:
        dep = Dependency(
            name="test-pkg", version_spec="^1.0.0", ecosystem=Ecosystem.NPM,
            location=Location(file="package.json", line=10, column=5),
        )
        finding = Finding(
            rule_id="B001", rule_name="Range specifier", severity=Severity.WARNING,
            dependency=dep, message="Uses range", actual="^1.0.0", expected="1.0.0",
        )
        result = ScanResult(dependencies=[dep], findings=[finding], scanned_files=["package.json"])
        sarif = generate_sarif(result)
        results = sarif["runs"][0]["results"]
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["ruleId"], "B001")
        self.assertEqual(results[0]["level"], "warning")
        self.assertEqual(results[0]["locations"][0]["physicalLocation"]["region"]["startLine"], 10)

    def test_empty_findings(self) -> None:
        sarif = generate_sarif(_make_result())
        self.assertEqual(sarif["runs"][0]["results"], [])

    def test_error_maps_to_error_level(self) -> None:
        dep = Dependency(
            name="evil-pkg", version_spec="1.0.0", ecosystem=Ecosystem.NPM,
            location=Location(file="package.json", line=1),
        )
        finding = Finding(
            rule_id="R001", rule_name="Young author", severity=Severity.ERROR,
            dependency=dep, message="Author is 30 days old",
        )
        result = ScanResult(dependencies=[dep], findings=[finding], scanned_files=["package.json"])
        sarif = generate_sarif(result)
        self.assertEqual(sarif["runs"][0]["results"][0]["level"], "error")


if __name__ == "__main__":
    unittest.main()
