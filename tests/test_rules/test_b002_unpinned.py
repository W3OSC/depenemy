"""Tests for B002 - Unpinned dependency rule."""
from __future__ import annotations

import unittest

try:
    import pytest
    _HAS_PYTEST = True
except ImportError:
    _HAS_PYTEST = False


def load_tests(loader, tests, pattern):  # noqa: ARG001
    if not _HAS_PYTEST:
        return unittest.TestSuite()
    return tests


if _HAS_PYTEST:
    from depenemy.config import Config
    from depenemy.rules.behavioral.b002_unpinned import B002Unpinned
    from tests.conftest import make_dep, make_meta

    @pytest.fixture
    def rule() -> B002Unpinned:
        return B002Unpinned()

    class TestB002Fires:
        """Specs that should produce a B002 Finding."""

        @pytest.mark.parametrize("spec", ["", "*", "latest", "x"])
        def test_fully_unpinned_specs(self, rule, default_config, spec):
            finding = rule.check(make_dep("pkg", spec), make_meta("pkg"), default_config)
            assert finding is not None
            assert finding.rule_id == "B002"

        def test_finding_shows_latest_version(self, rule, default_config):
            meta = make_meta("express", latest_version="4.18.2")
            finding = rule.check(make_dep("express", "*"), meta, default_config)
            assert "4.18.2" in finding.message

        def test_actual_field_is_spec(self, rule, default_config):
            finding = rule.check(make_dep("pkg", "*"), make_meta("pkg"), default_config)
            assert finding.actual == "*"

        def test_empty_actual_shown_as_empty_indicator(self, rule, default_config):
            finding = rule.check(make_dep("pkg", ""), make_meta("pkg"), default_config)
            assert finding.actual == "(empty)"

        def test_finding_references_dep(self, rule, default_config):
            dep = make_dep("chalk", "x")
            finding = rule.check(dep, make_meta("chalk"), default_config)
            assert finding.dependency is dep

    class TestB002Silent:
        """Specs that should NOT produce a B002 Finding."""

        @pytest.mark.parametrize("spec", [
            "4.18.2", "1.0.0", "0.0.1",
            "^4.18.2", "~1.0.0", ">=4.0.0",
            "10.x", "file:../pkg",
        ])
        def test_pinned_or_range_no_b002(self, rule, default_config, spec):
            finding = rule.check(make_dep("pkg", spec), make_meta("pkg"), default_config)
            assert finding is None

        def test_rule_disabled_via_config(self, rule):
            config = Config(rules={})
            dep = make_dep("pkg", "*")
            assert rule.check(dep, make_meta("pkg"), config) is None

    class TestB002VsB001Overlap:
        """Documents which specs trigger both rules vs only one."""

        def test_star_triggers_both(self, default_config):
            from depenemy.rules.behavioral.b001_range_specifier import B001RangeSpecifier
            dep = make_dep("pkg", "*")
            meta = make_meta("pkg")
            assert B001RangeSpecifier().check(dep, meta, default_config) is not None
            assert B002Unpinned().check(dep, meta, default_config) is not None

        def test_caret_triggers_only_b001(self, default_config):
            from depenemy.rules.behavioral.b001_range_specifier import B001RangeSpecifier
            dep = make_dep("pkg", "^1.2.3")
            meta = make_meta("pkg")
            assert B001RangeSpecifier().check(dep, meta, default_config) is not None
            assert B002Unpinned().check(dep, meta, default_config) is None

        def test_x_literal_triggers_only_b002(self, default_config):
            from depenemy.rules.behavioral.b001_range_specifier import B001RangeSpecifier
            dep = make_dep("pkg", "x")
            meta = make_meta("pkg")
            assert B001RangeSpecifier().check(dep, meta, default_config) is None
            assert B002Unpinned().check(dep, meta, default_config) is not None
