"""Tests for behavioral rules."""

from __future__ import annotations

import unittest

from depenemy.config import Config
from depenemy.rules.behavioral import B001RangeSpecifier, B002Unpinned, B003LaggingVersion
from depenemy.types import Dependency
from tests.conftest import make_dep, make_meta


def _dep(spec: str, resolved: str | None = None) -> Dependency:
    d = make_dep("test-pkg", spec)
    d.resolved_version = resolved
    return d


class TestB001RangeSpecifier(unittest.TestCase):
    def setUp(self) -> None:
        self.rule = B001RangeSpecifier()
        self.meta = make_meta("test-pkg")
        self.cfg = Config()

    def test_flags_caret(self) -> None:
        result = self.rule.check(_dep("^1.2.3"), self.meta, self.cfg)
        self.assertIsNotNone(result)
        self.assertEqual(result.rule_id, "B001")  # type: ignore[union-attr]

    def test_flags_tilde(self) -> None:
        self.assertIsNotNone(self.rule.check(_dep("~1.2.3"), self.meta, self.cfg))

    def test_flags_wildcard(self) -> None:
        self.assertIsNotNone(self.rule.check(_dep("*"), self.meta, self.cfg))

    def test_flags_gte(self) -> None:
        self.assertIsNotNone(self.rule.check(_dep(">=1.0.0"), self.meta, self.cfg))

    def test_passes_exact(self) -> None:
        self.assertIsNone(self.rule.check(_dep("1.2.3"), self.meta, self.cfg))

    def test_disabled_by_config(self) -> None:
        cfg = Config()
        cfg.rules = {}
        self.assertIsNone(self.rule.check(_dep("^1.2.3"), self.meta, cfg))


class TestB002Unpinned(unittest.TestCase):
    def setUp(self) -> None:
        self.rule = B002Unpinned()
        self.meta = make_meta("test-pkg")
        self.cfg = Config()

    def test_flags_empty(self) -> None:
        self.assertIsNotNone(self.rule.check(_dep(""), self.meta, self.cfg))

    def test_flags_star(self) -> None:
        self.assertIsNotNone(self.rule.check(_dep("*"), self.meta, self.cfg))

    def test_flags_latest(self) -> None:
        self.assertIsNotNone(self.rule.check(_dep("latest"), self.meta, self.cfg))

    def test_passes_exact(self) -> None:
        self.assertIsNone(self.rule.check(_dep("1.2.3"), self.meta, self.cfg))


class TestB003LaggingVersion(unittest.TestCase):
    def setUp(self) -> None:
        self.rule = B003LaggingVersion()
        self.cfg = Config()

    def test_flags_major_lag(self) -> None:
        meta = make_meta("test-pkg", latest_version="3.0.0", target_version="1.0.0")
        result = self.rule.check(_dep("1.0.0", "1.0.0"), meta, self.cfg)
        self.assertIsNotNone(result)

    def test_flags_minor_lag_beyond_threshold(self) -> None:
        meta = make_meta("test-pkg", latest_version="1.11.0", target_version="1.0.0")
        self.assertIsNotNone(self.rule.check(_dep("1.0.0", "1.0.0"), meta, self.cfg))

    def test_passes_within_threshold(self) -> None:
        meta = make_meta("test-pkg", latest_version="1.6.0", target_version="1.0.0")
        self.assertIsNone(self.rule.check(_dep("1.0.0", "1.0.0"), meta, self.cfg))

    def test_passes_up_to_date(self) -> None:
        meta = make_meta("test-pkg", latest_version="2.0.0", target_version="2.0.0")
        self.assertIsNone(self.rule.check(_dep("2.0.0", "2.0.0"), meta, self.cfg))


if __name__ == "__main__":
    unittest.main()
