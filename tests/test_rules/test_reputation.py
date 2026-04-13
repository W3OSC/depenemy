"""Tests for reputation rules."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone

from depenemy.config import Config
from depenemy.rules.reputation import (
    R001YoungAuthor,
    R002YoungPackage,
    R003LowWeeklyDownloads,
    R004LowTotalDownloads,
    R005StalePackage,
    R006FewContributors,
    R007BelowSecurityPatch,
    R008Deprecated,
)
from depenemy.types import Advisory
from tests.conftest import make_dep, make_meta


def _dep() -> object:
    return make_dep("test-pkg", "1.0.0")


def _ago(days: int) -> datetime:
    return datetime.fromtimestamp(
        datetime.now(timezone.utc).timestamp() - days * 86400, tz=timezone.utc
    )


class TestR001YoungAuthor(unittest.TestCase):
    rule = R001YoungAuthor()

    def test_flags_young_author(self) -> None:
        meta = make_meta("test-pkg")
        meta.author_account_created_at = _ago(100)
        result = self.rule.check(_dep(), meta, Config())  # type: ignore[arg-type]
        self.assertIsNotNone(result)
        self.assertEqual(result.rule_id, "R001")  # type: ignore[union-attr]

    def test_passes_old_author(self) -> None:
        meta = make_meta("test-pkg")
        meta.author_account_created_at = _ago(500)
        self.assertIsNone(self.rule.check(_dep(), meta, Config()))  # type: ignore[arg-type]

    def test_passes_no_author_data(self) -> None:
        meta = make_meta("test-pkg")
        meta.author_account_created_at = None
        self.assertIsNone(self.rule.check(_dep(), meta, Config()))  # type: ignore[arg-type]


class TestR002YoungPackage(unittest.TestCase):
    rule = R002YoungPackage()

    def test_flags_young_package(self) -> None:
        meta = make_meta("test-pkg")
        meta.published_at = _ago(30)
        self.assertIsNotNone(self.rule.check(_dep(), meta, Config()))  # type: ignore[arg-type]

    def test_passes_old_package(self) -> None:
        meta = make_meta("test-pkg")
        meta.published_at = _ago(400)
        self.assertIsNone(self.rule.check(_dep(), meta, Config()))  # type: ignore[arg-type]


class TestR003LowWeeklyDownloads(unittest.TestCase):
    rule = R003LowWeeklyDownloads()

    def test_flags_low(self) -> None:
        meta = make_meta("test-pkg", weekly_downloads=500)
        self.assertIsNotNone(self.rule.check(_dep(), meta, Config()))  # type: ignore[arg-type]

    def test_passes_high(self) -> None:
        meta = make_meta("test-pkg", weekly_downloads=50000)
        self.assertIsNone(self.rule.check(_dep(), meta, Config()))  # type: ignore[arg-type]

    def test_skips_zero(self) -> None:
        meta = make_meta("test-pkg", weekly_downloads=0)
        self.assertIsNone(self.rule.check(_dep(), meta, Config()))  # type: ignore[arg-type]


class TestR004LowTotalDownloads(unittest.TestCase):
    rule = R004LowTotalDownloads()

    def test_flags_low(self) -> None:
        meta = make_meta("test-pkg", total_downloads=5000)
        self.assertIsNotNone(self.rule.check(_dep(), meta, Config()))  # type: ignore[arg-type]

    def test_passes_high(self) -> None:
        meta = make_meta("test-pkg", total_downloads=500000)
        self.assertIsNone(self.rule.check(_dep(), meta, Config()))  # type: ignore[arg-type]


class TestR005StalePackage(unittest.TestCase):
    rule = R005StalePackage()

    def test_flags_stale(self) -> None:
        meta = make_meta("test-pkg")
        meta.last_published_at = _ago(800)
        self.assertIsNotNone(self.rule.check(_dep(), meta, Config()))  # type: ignore[arg-type]

    def test_passes_recent(self) -> None:
        meta = make_meta("test-pkg")
        meta.last_published_at = _ago(100)
        self.assertIsNone(self.rule.check(_dep(), meta, Config()))  # type: ignore[arg-type]


class TestR006FewContributors(unittest.TestCase):
    rule = R006FewContributors()

    def test_flags_few(self) -> None:
        meta = make_meta("test-pkg", contributor_count=2)
        self.assertIsNotNone(self.rule.check(_dep(), meta, Config()))  # type: ignore[arg-type]

    def test_passes_many(self) -> None:
        meta = make_meta("test-pkg", contributor_count=20)
        self.assertIsNone(self.rule.check(_dep(), meta, Config()))  # type: ignore[arg-type]

    def test_skips_zero(self) -> None:
        meta = make_meta("test-pkg", contributor_count=0)
        self.assertIsNone(self.rule.check(_dep(), meta, Config()))  # type: ignore[arg-type]


class TestR007BelowSecurityPatch(unittest.TestCase):
    rule = R007BelowSecurityPatch()

    def test_flags_below_patch(self) -> None:
        meta = make_meta("test-pkg", target_version="1.0.0")
        meta.advisories = [
            Advisory(id="GHSA-test", severity="high", affected_range="<1.2.0", patched_version="1.2.0")
        ]
        self.assertIsNotNone(self.rule.check(_dep(), meta, Config()))  # type: ignore[arg-type]

    def test_passes_above_patch(self) -> None:
        meta = make_meta("test-pkg", target_version="2.0.0")
        meta.advisories = [
            Advisory(id="GHSA-test", severity="high", affected_range="<1.2.0", patched_version="1.2.0")
        ]
        self.assertIsNone(self.rule.check(_dep(), meta, Config()))  # type: ignore[arg-type]


class TestR008Deprecated(unittest.TestCase):
    rule = R008Deprecated()

    def test_flags_deprecated(self) -> None:
        meta = make_meta("test-pkg", is_deprecated=True)
        meta.deprecation_message = "Use newpkg instead"
        result = self.rule.check(_dep(), meta, Config())  # type: ignore[arg-type]
        self.assertIsNotNone(result)
        self.assertIn("deprecated", result.message.lower())  # type: ignore[union-attr]

    def test_passes_not_deprecated(self) -> None:
        meta = make_meta("test-pkg", is_deprecated=False)
        self.assertIsNone(self.rule.check(_dep(), meta, Config()))  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
