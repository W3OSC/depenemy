"""
Detection coverage test and pattern classification for npm/package.json.

This file serves two purposes:
  1. Classification: KNOWN_PATTERNS is the canonical list of all npm insecurity
     patterns depenemy should detect, organised by category.
  2. Coverage test: parametrized tests verify that implemented rules fire on
     their expected fixture files, and report the overall detection rate.

Run with -v -s to see the full coverage report printed to stdout.

Detection rate formula:
    implemented patterns caught / total known patterns
"""
from __future__ import annotations

import unittest
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

try:
    import pytest
    _HAS_PYTEST = True
except ImportError:
    _HAS_PYTEST = False


def load_tests(loader, tests, pattern):  # noqa: ARG001
    if not _HAS_PYTEST:
        return unittest.TestSuite()
    return tests


from depenemy.config import Config
from depenemy.rules.behavioral.b001_range_specifier import B001RangeSpecifier
from depenemy.rules.behavioral.b002_unpinned import B002Unpinned
from depenemy.rules.base import BaseRule
from tests.conftest import FIXTURES_NPM, make_meta

# ---------------------------------------------------------------------------
# Pattern classification
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PatternEntry:
    pattern_id: str
    category: str
    description: str
    example_spec: str          # Representative version string
    fixture_file: Optional[str]  # Fixture that contains this pattern
    target_dep: Optional[str]    # Package name to look for in fixture
    rule_id: Optional[str]       # Rule that should catch it; None = no rule yet
    detected: bool               # Whether current depenemy catches it


KNOWN_PATTERNS: list[PatternEntry] = [
    # -----------------------------------------------------------------------
    # BEHAVIORAL - Version pinning (B001/B002)
    # -----------------------------------------------------------------------
    PatternEntry("CARET",        "behavioral/pinning", "^ caret range - allows any minor+patch update",
                 "^1.2.3",         "b001_caret_ranges.json",    "express",      "B001", True),
    PatternEntry("TILDE",        "behavioral/pinning", "~ tilde range - allows patch updates",
                 "~1.2.3",         "b001_tilde_ranges.json",    "express",      "B001", True),
    PatternEntry("STAR",         "behavioral/pinning", "* wildcard - installs any version (also B002)",
                 "*",              "b001_star_wildcard.json",   "axios",        "B001", True),
    PatternEntry("LATEST",       "behavioral/pinning", "'latest' dist-tag - always newest (also B002)",
                 "latest",         "b001_latest_tag.json",      "react",        "B001", True),
    PatternEntry("GTE",          "behavioral/pinning", ">= lower-bound range - no upper cap",
                 ">=4.0.0",        "b001_gte_range.json",       "express",      "B001", True),
    PatternEntry("GT",           "behavioral/pinning", "> exclusive lower bound",
                 ">3.0.0",         "b001_gte_range.json",       "body-parser",  "B001", True),
    PatternEntry("NEQ",          "behavioral/pinning", "!= exclusion - installs anything except one version",
                 "!=1.7.3",        "b001_gte_range.json",       "compression",  "B001", True),
    PatternEntry("SPACE_RANGE",  "behavioral/pinning", "space-separated compound range (e.g. >=1 <2)",
                 ">=2.0.0 <3.0.0", "b001_gte_range.json",       "cors",         "B001", True),
    PatternEntry("OR_RANGE",     "behavioral/pinning", "|| union range spanning major versions",
                 "^4.0.0 || ^5.0.0","b001_or_range.json",       "webpack",      "B001", True),
    PatternEntry("EMPTY",        "behavioral/pinning", "Empty string - npm treats as '*' (also B002)",
                 "",               "b002_empty_version.json",   "debug",        "B001", True),
    PatternEntry("STAR_B002",    "behavioral/pinning", "* unpinned - B002 perspective",
                 "*",              "b001_star_wildcard.json",   "axios",        "B002", True),
    PatternEntry("LATEST_B002",  "behavioral/pinning", "'latest' unpinned - B002 perspective",
                 "latest",         "b001_latest_tag.json",      "react",        "B002", True),
    PatternEntry("EMPTY_B002",   "behavioral/pinning", "Empty string unpinned - B002 perspective",
                 "",               "b002_empty_version.json",   "debug",        "B002", True),
    PatternEntry("X_LITERAL",    "behavioral/pinning", "Literal 'x' version - only B002 catches it",
                 "x",              "b002_x_version.json",       "chalk",        "B002", True),

    # -----------------------------------------------------------------------
    # BEHAVIORAL - Detection gaps in current implementation
    # -----------------------------------------------------------------------
    PatternEntry("X_RANGE",      "behavioral/pinning", "[GAP] x-range notation (1.x, 4.x.x) - no rule catches this",
                 "10.x",           "b001_x_range.json",         "mocha",        None,   False),

    # -----------------------------------------------------------------------
    # SUPPLY CHAIN - Non-registry dependency sources (no rules yet)
    # -----------------------------------------------------------------------
    PatternEntry("GIT_GITHUB",   "supply_chain/source", "[GAP] github: shorthand bypasses registry vetting",
                 "github:owner/repo",           "future_git_dep.json",  "mylib",    None, False),
    PatternEntry("GIT_HTTPS",    "supply_chain/source", "[GAP] git+https:// URL dep - no audit, no integrity",
                 "git+https://github.com/x.git","future_git_dep.json",  "helper",   None, False),
    PatternEntry("GIT_BITBUCKET","supply_chain/source", "[GAP] bitbucket: shorthand",
                 "bitbucket:owner/pkg",          "future_git_dep.json",  "util",     None, False),
    PatternEntry("HTTP_URL",     "supply_chain/source", "[GAP] https:// URL dep - MITM risk, no integrity check",
                 "https://example.com/p.tar.gz", "future_http_dep.json", "utils",    None, False),
    PatternEntry("FILE_PATH",    "supply_chain/source", "[GAP] file: local path - unversioned, no lockfile integrity",
                 "file:../shared",               "future_file_dep.json", "shared",   None, False),
    PatternEntry("WORKSPACE",    "supply_chain/source", "[GAP] workspace:* protocol - monorepo-specific, can be *",
                 "workspace:*",                  "future_file_dep.json", "monorepo-pkg", None, False),

    # -----------------------------------------------------------------------
    # SUPPLY CHAIN - Metadata-based risks (require fetcher data, no rule yet)
    # -----------------------------------------------------------------------
    PatternEntry("INSTALL_SCRIPTS","supply_chain/execution",
                 "[GAP] preinstall/postinstall executes arbitrary code on npm install",
                 "N/A (scripts field)", "future_install_scripts.json", None, None, False),
    PatternEntry("TYPOSQUAT",    "supply_chain/confusion",
                 "[GAP] Name close to popular package (edit distance ≤ threshold)",
                 "N/A (metadata)",      None,                           None, None, False),
    PatternEntry("SINGLE_MAINT", "supply_chain/busfactor",
                 "[GAP] Single maintainer - high bus-factor risk",
                 "N/A (metadata)",      None,                           None, None, False),

    # -----------------------------------------------------------------------
    # REPUTATION (metadata-based, no rules yet)
    # -----------------------------------------------------------------------
    PatternEntry("DEPRECATED",   "reputation/lifecycle",  "[GAP] Package is marked deprecated",
                 "N/A (metadata)", None, None, None, False),
    PatternEntry("ARCHIVED",     "reputation/lifecycle",  "[GAP] Source repo is archived",
                 "N/A (metadata)", None, None, None, False),
    PatternEntry("LOW_DOWNLOADS","reputation/popularity", "[GAP] Weekly downloads below threshold",
                 "N/A (metadata)", None, None, None, False),
    PatternEntry("NEW_PACKAGE",  "reputation/age",        "[GAP] Package age < min_package_age_days",
                 "N/A (metadata)", None, None, None, False),
    PatternEntry("NEW_AUTHOR",   "reputation/age",        "[GAP] Author account age < threshold",
                 "N/A (metadata)", None, None, None, False),
    PatternEntry("FEW_CONTRIBS", "reputation/community",  "[GAP] Contributor count < min_contributors",
                 "N/A (metadata)", None, None, None, False),
    PatternEntry("KNOWN_CVE",    "reputation/advisory",   "[GAP] Package version has known advisory/CVE",
                 "N/A (metadata)", None, None, None, False),
    PatternEntry("STALE",        "reputation/maintenance","[GAP] No update in > max_stale_days",
                 "N/A (metadata)", None, None, None, False),

]

# ---------------------------------------------------------------------------
# Rule registry - maps rule_id → instantiated rule object
# ---------------------------------------------------------------------------

RULE_REGISTRY: dict[str, BaseRule] = {
    "B001": B001RangeSpecifier(),
    "B002": B002Unpinned(),
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_fixture_deps(fixture_file: str) -> list:
    from depenemy.parsers.npm import NpmParser
    return NpmParser().parse(FIXTURES_NPM / fixture_file)


def _run_rule(rule_id: str, fixture_file: str, dep_name: str) -> bool:
    """Return True if rule fires for any dep matching dep_name in fixture."""
    config = Config()
    rule = RULE_REGISTRY[rule_id]
    deps = _load_fixture_deps(fixture_file)
    targets = [d for d in deps if d.name == dep_name]
    assert targets, f"Dep '{dep_name}' not found in {fixture_file}"
    meta = make_meta(dep_name)
    return any(rule.check(dep, meta, config) is not None for dep in targets)


# ---------------------------------------------------------------------------
# Coverage report utility
# ---------------------------------------------------------------------------

def _coverage_report(patterns: list[PatternEntry]) -> str:
    total = len(patterns)
    detected = sum(1 for p in patterns if p.detected)
    rate = detected / total * 100 if total else 0

    lines = [
        "",
        "=" * 70,
        f"  DEPENEMY DETECTION COVERAGE REPORT",
        f"  Detected: {detected}/{total} patterns  ({rate:.1f}%)",
        "=" * 70,
    ]

    # Group by category
    categories: dict[str, list[PatternEntry]] = {}
    for p in patterns:
        categories.setdefault(p.category, []).append(p)

    for cat, entries in sorted(categories.items()):
        lines.append(f"\n  [{cat}]")
        for e in entries:
            mark = "✓" if e.detected else "✗"
            rule_label = f"  rule={e.rule_id}" if e.rule_id else "  no rule"
            lines.append(f"    {mark} {e.pattern_id:<20} {e.description[:52]}{rule_label}")

    lines.append("")
    lines.append("  Legend: ✓ = currently detected   ✗ = coverage gap")
    lines.append("=" * 70)
    return "\n".join(lines)


if _HAS_PYTEST:
    # ---------------------------------------------------------------------------
    # Parametrized detection tests (implemented rules only)
    # ---------------------------------------------------------------------------

    _IMPLEMENTED = [p for p in KNOWN_PATTERNS if p.detected and p.rule_id and p.fixture_file and p.target_dep]

    @pytest.mark.parametrize(
        "pattern",
        _IMPLEMENTED,
        ids=[p.pattern_id for p in _IMPLEMENTED],
    )
    def test_rule_fires_on_fixture(pattern: PatternEntry) -> None:
        """Each implemented pattern must be detected by its designated rule on the fixture file."""
        fired = _run_rule(pattern.rule_id, pattern.fixture_file, pattern.target_dep)
        assert fired, (
            f"[{pattern.pattern_id}] rule {pattern.rule_id} did NOT fire for "
            f"'{pattern.target_dep}' in {pattern.fixture_file}\n"
            f"  spec example: {pattern.example_spec!r}"
        )

    # ---------------------------------------------------------------------------
    # Gap confirmation tests (unimplemented rules should NOT accidentally fire)
    # ---------------------------------------------------------------------------

    _GAPS_WITH_FIXTURES = [
        p for p in KNOWN_PATTERNS
        if not p.detected and p.fixture_file and p.target_dep
    ]

    @pytest.mark.parametrize(
        "pattern",
        _GAPS_WITH_FIXTURES,
        ids=[p.pattern_id for p in _GAPS_WITH_FIXTURES],
    )
    def test_gap_confirms_not_detected(pattern: PatternEntry) -> None:
        """Gaps must currently produce no finding from any implemented rule."""
        config = Config()
        deps = _load_fixture_deps(pattern.fixture_file)
        targets = [d for d in deps if d.name == pattern.target_dep]
        assert targets, f"Dep '{pattern.target_dep}' not found in {pattern.fixture_file}"
        meta = make_meta(pattern.target_dep)
        findings = []
        for dep in targets:
            for rule in RULE_REGISTRY.values():
                f = rule.check(dep, meta, config)
                if f is not None:
                    findings.append(f)
        assert not findings, (
            f"[{pattern.pattern_id}] Expected no findings for gap pattern "
            f"'{pattern.target_dep}' ({pattern.example_spec!r}), "
            f"but got: {[f.rule_id for f in findings]}"
        )

    # ---------------------------------------------------------------------------
    # Coverage rate assertion + report
    # ---------------------------------------------------------------------------

    def test_detection_rate_report(capsys) -> None:
        """Print the full coverage report and assert the current known rate."""
        report = _coverage_report(KNOWN_PATTERNS)
        with capsys.disabled():
            print(report)

        total = len(KNOWN_PATTERNS)
        detected = sum(1 for p in KNOWN_PATTERNS if p.detected)
        rate = detected / total * 100

        # Update this threshold as new rules are added
        EXPECTED_MIN_RATE = 35.0  # current baseline with only B001/B002 implemented
        assert rate >= EXPECTED_MIN_RATE, (
            f"Detection rate {rate:.1f}% is below expected minimum {EXPECTED_MIN_RATE}%. "
            f"Detected {detected}/{total} patterns."
        )
