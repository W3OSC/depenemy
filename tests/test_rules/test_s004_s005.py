"""Tests for S004 (dependency confusion) and S005 (malicious package)."""
from __future__ import annotations

import unittest

from depenemy.config import Config
from depenemy.rules.supply_chain.s004_dependency_confusion import S004DependencyConfusion
from depenemy.rules.supply_chain.s005_malicious_package import S005MaliciousPackage
from depenemy.types import Advisory, Ecosystem
from tests.conftest import make_dep, make_meta


class TestS004DependencyConfusion(unittest.TestCase):
    rule = S004DependencyConfusion()

    # --- Scoped internal packages ---

    def test_scoped_internal_name_flagged(self) -> None:
        dep = make_dep("@acme/internal-api", "1.0.0", ecosystem=Ecosystem.NPM)
        meta = make_meta("@acme/internal-api", weekly_downloads=50)
        result = self.rule.check(dep, meta, Config())  # type: ignore[arg-type]
        self.assertIsNotNone(result)
        self.assertEqual(result.rule_id, "S004")  # type: ignore[union-attr]

    def test_scoped_private_name_flagged(self) -> None:
        dep = make_dep("@corp/private-utils", "1.0.0", ecosystem=Ecosystem.NPM)
        meta = make_meta("@corp/private-utils")
        result = self.rule.check(dep, meta, Config())  # type: ignore[arg-type]
        self.assertIsNotNone(result)

    def test_known_public_scope_not_flagged(self) -> None:
        dep = make_dep("@babel/core", "7.0.0", ecosystem=Ecosystem.NPM)
        meta = make_meta("@babel/core")
        result = self.rule.check(dep, meta, Config())  # type: ignore[arg-type]
        self.assertIsNone(result)

    def test_babel_internal_not_flagged(self) -> None:
        # @babel scope is a known public org - even internal-sounding names should pass
        dep = make_dep("@babel/internal-helpers", "7.0.0", ecosystem=Ecosystem.NPM)
        meta = make_meta("@babel/internal-helpers")
        result = self.rule.check(dep, meta, Config())  # type: ignore[arg-type]
        self.assertIsNone(result)

    def test_types_scope_not_flagged(self) -> None:
        dep = make_dep("@types/node", "18.0.0", ecosystem=Ecosystem.NPM)
        meta = make_meta("@types/node")
        result = self.rule.check(dep, meta, Config())  # type: ignore[arg-type]
        self.assertIsNone(result)

    # --- Unscoped internal-sounding packages ---

    def test_unscoped_internal_low_downloads_flagged(self) -> None:
        dep = make_dep("internal-auth-utils", "1.0.0", ecosystem=Ecosystem.NPM)
        meta = make_meta("internal-auth-utils", weekly_downloads=10)
        result = self.rule.check(dep, meta, Config())  # type: ignore[arg-type]
        self.assertIsNotNone(result)
        self.assertEqual(result.rule_id, "S004")  # type: ignore[union-attr]

    def test_unscoped_corp_low_downloads_flagged(self) -> None:
        dep = make_dep("corp-design-system", "1.0.0", ecosystem=Ecosystem.NPM)
        meta = make_meta("corp-design-system", weekly_downloads=5)
        result = self.rule.check(dep, meta, Config())  # type: ignore[arg-type]
        self.assertIsNotNone(result)

    def test_unscoped_internal_high_downloads_not_flagged(self) -> None:
        # If it has high downloads it's probably a legitimate public package
        dep = make_dep("internal-ip", "1.0.0", ecosystem=Ecosystem.NPM)
        meta = make_meta("internal-ip", weekly_downloads=500_000)
        result = self.rule.check(dep, meta, Config())  # type: ignore[arg-type]
        self.assertIsNone(result)

    def test_normal_package_not_flagged(self) -> None:
        dep = make_dep("express", "4.18.0", ecosystem=Ecosystem.NPM)
        meta = make_meta("express", weekly_downloads=25_000_000)
        result = self.rule.check(dep, meta, Config())  # type: ignore[arg-type]
        self.assertIsNone(result)

    def test_scoped_non_internal_name_not_flagged(self) -> None:
        # Scope "myteam" doesn't match internal patterns, name has no internal keywords
        dep = make_dep("@myteam/ui-components", "1.0.0", ecosystem=Ecosystem.NPM)
        meta = make_meta("@myteam/ui-components")
        result = self.rule.check(dep, meta, Config())  # type: ignore[arg-type]
        self.assertIsNone(result)


class TestS005MaliciousPackage(unittest.TestCase):
    rule = S005MaliciousPackage()

    def test_malicious_advisory_flagged(self) -> None:
        dep = make_dep("evil-logger", "1.0.0")
        meta = make_meta("evil-logger")
        meta.malicious_advisories = [
            Advisory(
                id="MAL-2024-001",
                severity="critical",
                affected_range="*",
                patched_version="",
                description="Package contains malicious code that exfiltrates env vars.",
            )
        ]
        result = self.rule.check(dep, meta, Config())  # type: ignore[arg-type]
        self.assertIsNotNone(result)
        self.assertEqual(result.rule_id, "S005")  # type: ignore[union-attr]

    def test_finding_contains_advisory_id(self) -> None:
        dep = make_dep("evil-pkg", "1.0.0")
        meta = make_meta("evil-pkg")
        meta.malicious_advisories = [
            Advisory(
                id="MAL-2024-999",
                severity="critical",
                affected_range="*",
                patched_version="",
                description="Backdoor detected.",
            )
        ]
        result = self.rule.check(dep, meta, Config())  # type: ignore[arg-type]
        self.assertIsNotNone(result)
        self.assertIn("MAL-2024-999", result.message)  # type: ignore[union-attr]

    def test_no_malicious_advisories_passes(self) -> None:
        dep = make_dep("safe-pkg", "1.0.0")
        meta = make_meta("safe-pkg")
        meta.malicious_advisories = []
        result = self.rule.check(dep, meta, Config())  # type: ignore[arg-type]
        self.assertIsNone(result)

    def test_uses_first_advisory(self) -> None:
        dep = make_dep("multi-evil", "1.0.0")
        meta = make_meta("multi-evil")
        meta.malicious_advisories = [
            Advisory(id="MAL-001", severity="critical", affected_range="*",
                     patched_version="", description="First issue."),
            Advisory(id="MAL-002", severity="high", affected_range="*",
                     patched_version="", description="Second issue."),
        ]
        result = self.rule.check(dep, meta, Config())  # type: ignore[arg-type]
        self.assertIsNotNone(result)
        self.assertIn("MAL-001", result.message)  # type: ignore[union-attr]

    def test_actual_field_set(self) -> None:
        dep = make_dep("evil-pkg", "1.0.0")
        meta = make_meta("evil-pkg")
        meta.malicious_advisories = [
            Advisory(id="MAL-001", severity="critical", affected_range="*",
                     patched_version="", description="Bad."),
        ]
        result = self.rule.check(dep, meta, Config())  # type: ignore[arg-type]
        self.assertEqual(result.actual, "malicious activity recorded")  # type: ignore[union-attr]

    def test_rule_disabled_returns_none(self) -> None:
        from depenemy.config import DEFAULT_RULES
        rules = {k: v for k, v in DEFAULT_RULES.items() if k != "S005"}
        config = Config(rules=rules)
        dep = make_dep("evil-pkg", "1.0.0")
        meta = make_meta("evil-pkg")
        meta.malicious_advisories = [
            Advisory(id="MAL-001", severity="critical", affected_range="*",
                     patched_version="", description="Bad."),
        ]
        self.assertIsNone(self.rule.check(dep, meta, config))  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
