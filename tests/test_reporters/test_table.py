"""Tests for the terminal table reporter."""
from __future__ import annotations

import io
import unittest

from rich.console import Console

from depenemy.reporters.table import _first_sentence, print_table
from depenemy.types import Dependency, Ecosystem, Finding, Location, ScanResult, Severity


def _dep(name: str = "test-pkg") -> Dependency:
    return Dependency(
        name=name,
        version_spec="^1.0.0",
        ecosystem=Ecosystem.NPM,
        location=Location(file="package.json", line=1),
    )


def _finding(
    rule_id: str = "B001",
    severity: Severity = Severity.ERROR,
    name: str = "test-pkg",
    actual: str = "^1.0.0",
) -> Finding:
    dep = _dep(name)
    return Finding(
        rule_id=rule_id,
        rule_name="Range specifier",
        severity=severity,
        dependency=dep,
        message=f"`{name}` uses range `{actual}`",
        actual=actual,
    )


def _result(findings: list[Finding] | None = None, n_deps: int = 1) -> ScanResult:
    deps = [_dep(f"pkg-{i}") for i in range(n_deps)]
    return ScanResult(
        dependencies=deps,
        findings=findings or [],
        scanned_files=["package.json"],
    )


def _capture(result: ScanResult) -> str:
    buf = io.StringIO()
    console = Console(file=buf, no_color=True, highlight=False, width=120)
    print_table(result, console=console)
    return buf.getvalue()


class TestFirstSentence(unittest.TestCase):
    def test_splits_on_period_space(self) -> None:
        text = "First sentence. Second sentence."
        self.assertEqual(_first_sentence(text), "First sentence.")

    def test_returns_full_text_when_no_period_space(self) -> None:
        text = "Only one sentence"
        self.assertEqual(_first_sentence(text), "Only one sentence")

    def test_single_sentence_with_period(self) -> None:
        text = "Short sentence."
        self.assertEqual(_first_sentence(text), "Short sentence.")


class TestNoFindings(unittest.TestCase):
    def test_shows_clean_message(self) -> None:
        output = _capture(_result(findings=[]))
        self.assertIn("No issues found", output)

    def test_does_not_show_summary_line(self) -> None:
        output = _capture(_result(findings=[]))
        self.assertNotIn("packages scanned", output)


class TestRuleHeader(unittest.TestCase):
    def test_rule_id_in_output(self) -> None:
        output = _capture(_result(findings=[_finding("B001")]))
        self.assertIn("B001", output)

    def test_rule_name_in_output(self) -> None:
        output = _capture(_result(findings=[_finding("B001")]))
        self.assertIn("Range specifier", output)

    def test_package_count_in_header(self) -> None:
        findings = [_finding("B001", name=f"pkg-{i}") for i in range(3)]
        output = _capture(_result(findings=findings))
        self.assertIn("3 packages", output)

    def test_singular_package_label(self) -> None:
        output = _capture(_result(findings=[_finding("B001")]))
        self.assertIn("1 package", output)
        self.assertNotIn("1 packages", output)

    def test_severity_badge_error(self) -> None:
        output = _capture(_result(findings=[_finding(severity=Severity.ERROR)]))
        self.assertIn("ERROR", output)

    def test_severity_badge_warning(self) -> None:
        output = _capture(_result(findings=[_finding(severity=Severity.WARNING)]))
        self.assertIn("WARNING", output)


class TestPackageRows(unittest.TestCase):
    def test_package_name_shown(self) -> None:
        output = _capture(_result(findings=[_finding(name="my-special-pkg")]))
        self.assertIn("my-special-pkg", output)

    def test_ecosystem_shown(self) -> None:
        output = _capture(_result(findings=[_finding()]))
        self.assertIn("npm", output)

    def test_actual_value_shown(self) -> None:
        output = _capture(_result(findings=[_finding(actual="^2.3.4")]))
        self.assertIn("^2.3.4", output)

    def test_expected_shown_with_arrow(self) -> None:
        dep = _dep()
        finding = Finding(
            rule_id="B003", rule_name="Lagging version", severity=Severity.WARNING,
            dependency=dep, message="test", actual="1.0.0", expected="2.0.0",
        )
        output = _capture(_result(findings=[finding]))
        self.assertIn("2.0.0", output)
        self.assertIn("->", output.replace("→", "->"))


class TestOverflow(unittest.TestCase):
    def test_overflow_note_shown_when_more_than_5(self) -> None:
        findings = [_finding("B001", name=f"pkg-{i}") for i in range(8)]
        output = _capture(_result(findings=findings))
        self.assertIn("+ 3 more", output)
        self.assertIn("depenemy-results.json", output)

    def test_no_overflow_note_when_5_or_fewer(self) -> None:
        findings = [_finding("B001", name=f"pkg-{i}") for i in range(5)]
        output = _capture(_result(findings=findings))
        self.assertNotIn("more", output)

    def test_all_5_packages_shown(self) -> None:
        findings = [_finding("B001", name=f"pkg-{i}") for i in range(8)]
        output = _capture(_result(findings=findings))
        for i in range(5):
            self.assertIn(f"pkg-{i}", output)

    def test_6th_package_not_shown(self) -> None:
        findings = [_finding("B001", name=f"pkg-{i}") for i in range(8)]
        output = _capture(_result(findings=findings))
        self.assertNotIn("pkg-5", output)
        self.assertNotIn("pkg-6", output)
        self.assertNotIn("pkg-7", output)


class TestSummary(unittest.TestCase):
    def test_packages_scanned_count(self) -> None:
        output = _capture(_result(findings=[_finding()], n_deps=5))
        self.assertIn("5 packages scanned", output)

    def test_error_count_shown(self) -> None:
        findings = [_finding(severity=Severity.ERROR, name=f"pkg-{i}") for i in range(2)]
        output = _capture(_result(findings=findings))
        self.assertIn("2 errors", output)

    def test_warning_count_shown(self) -> None:
        findings = [_finding("R001", severity=Severity.WARNING, name=f"pkg-{i}") for i in range(3)]
        output = _capture(_result(findings=findings))
        self.assertIn("3 warnings", output)

    def test_zero_errors_shown_dimmed(self) -> None:
        findings = [_finding("R001", severity=Severity.WARNING)]
        output = _capture(_result(findings=findings))
        self.assertIn("0 errors", output)


class TestSorting(unittest.TestCase):
    def test_errors_shown_before_warnings(self) -> None:
        findings = [
            _finding("R001", severity=Severity.WARNING, name="warn-pkg"),
            _finding("B001", severity=Severity.ERROR, name="error-pkg"),
        ]
        output = _capture(_result(findings=findings))
        self.assertLess(output.index("B001"), output.index("R001"))


if __name__ == "__main__":
    unittest.main()
