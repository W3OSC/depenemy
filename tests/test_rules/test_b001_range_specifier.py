"""Tests for B001 - Range specifier rule."""
from __future__ import annotations

import unittest

try:
    import pytest
    _HAS_PYTEST = True
except ImportError:
    _HAS_PYTEST = False


def load_tests(loader, tests, pattern):  # noqa: ARG001
    """Return empty suite when pytest is unavailable - these tests need parametrize."""
    if not _HAS_PYTEST:
        return unittest.TestSuite()
    return tests


if _HAS_PYTEST:
    from depenemy.config import Config
    from depenemy.rules.behavioral.b001_range_specifier import B001RangeSpecifier
    from tests.conftest import make_dep, make_meta

    @pytest.fixture
    def rule() -> B001RangeSpecifier:
        return B001RangeSpecifier()

    class TestB001Fires:
        """Specs that should produce a B001 Finding."""

        @pytest.mark.parametrize("spec", ["^4.18.2", "^1.0.0", "^0.0.1"])
        def test_caret_range(self, rule, default_config, spec):
            finding = rule.check(make_dep("pkg", spec), make_meta("pkg"), default_config)
            assert finding is not None
            assert finding.rule_id == "B001"

        @pytest.mark.parametrize("spec", ["~4.17.21", "~1.0.0", "~0.1.0"])
        def test_tilde_range(self, rule, default_config, spec):
            finding = rule.check(make_dep("pkg", spec), make_meta("pkg"), default_config)
            assert finding is not None
            assert finding.rule_id == "B001"

        @pytest.mark.parametrize("spec", ["*", "latest"])
        def test_wildcard_and_latest_deferred_to_b002(self, rule, default_config, spec):
            # *, latest, and empty are fully unpinned - B002 owns them, B001 skips to avoid duplicates
            finding = rule.check(make_dep("pkg", spec), make_meta("pkg"), default_config)
            assert finding is None

        def test_empty_string_deferred_to_b002(self, rule, default_config):
            finding = rule.check(make_dep("pkg", ""), make_meta("pkg"), default_config)
            assert finding is None

        @pytest.mark.parametrize("spec", [">=4.0.0", ">3.0.0", "!=1.7.3"])
        def test_comparison_operators(self, rule, default_config, spec):
            finding = rule.check(make_dep("pkg", spec), make_meta("pkg"), default_config)
            assert finding is not None

        def test_space_separated_range(self, rule, default_config):
            finding = rule.check(make_dep("pkg", ">=2.0.0 <3.0.0"), make_meta("pkg"), default_config)
            assert finding is not None

        def test_or_range(self, rule, default_config):
            finding = rule.check(make_dep("pkg", "^4.0.0 || ^5.0.0"), make_meta("pkg"), default_config)
            assert finding is not None

        def test_finding_message_contains_spec(self, rule, default_config):
            dep = make_dep("express", "^4.18.2")
            finding = rule.check(dep, make_meta("express"), default_config)
            assert "^4.18.2" in finding.message

        def test_finding_references_dep(self, rule, default_config):
            dep = make_dep("express", "^4.18.2")
            finding = rule.check(dep, make_meta("express"), default_config)
            assert finding.dependency is dep

        def test_actual_field_is_spec(self, rule, default_config):
            dep = make_dep("express", "^4.18.2")
            finding = rule.check(dep, make_meta("express"), default_config)
            assert finding.actual == "^4.18.2"

    class TestB001Silent:
        """Specs that should NOT produce a B001 Finding."""

        @pytest.mark.parametrize("spec", [
            "4.18.2", "1.0.0", "0.0.1", "10.0.0", "1.2.3", "0.12.34",
        ])
        def test_exact_semver(self, rule, default_config, spec):
            finding = rule.check(make_dep("pkg", spec), make_meta("pkg"), default_config)
            assert finding is None

        def test_rule_disabled_via_config(self, rule):
            config = Config(rules={})
            dep = make_dep("express", "^4.18.2")
            assert rule.check(dep, make_meta("express"), config) is None

        @pytest.mark.parametrize("spec", [">=0.27.0", "^1.0.0", "~1.0.0", ">=1.0,<2.0"])
        def test_skipped_for_pyproject_toml_library_context(self, rule, default_config, spec):
            # pyproject.toml declares library compatibility ranges; pinning would
            # break downstream pip resolution. Lockfile (uv.lock/poetry.lock) owns
            # exact pins and B004 enforces lockfile presence.
            dep = make_dep("httpx", spec, file="pyproject.toml")
            assert rule.check(dep, make_meta("httpx"), default_config) is None

        @pytest.mark.parametrize("spec", [">=0.27.0", "^1.0.0", "~1.0.0"])
        def test_still_fires_for_requirements_txt(self, rule, default_config, spec):
            # requirements.txt is an application pin file - ranges remain risky.
            dep = make_dep("httpx", spec, file="requirements.txt")
            finding = rule.check(dep, make_meta("httpx"), default_config)
            assert finding is not None
            assert finding.rule_id == "B001"

        def test_still_fires_for_pipfile(self, rule, default_config):
            # Pipfile is an application manifest - Pipfile.lock holds the pins.
            dep = make_dep("httpx", ">=0.27.0", file="Pipfile")
            finding = rule.check(dep, make_meta("httpx"), default_config)
            assert finding is not None
            assert finding.rule_id == "B001"

        def test_skipped_for_nested_pyproject_toml(self, rule, default_config):
            # Walks the basename so a nested path still trips the library guard.
            dep = make_dep("httpx", ">=0.27.0", file="packages/lib/pyproject.toml")
            assert rule.check(dep, make_meta("httpx"), default_config) is None

    class TestB001CoverageGaps:
        """Documents known detection gaps - these assert CURRENT behavior."""

        @pytest.mark.parametrize("spec", ["10.x", "4.x.x", "1.2.x"])
        def test_x_range_not_caught(self, rule, default_config, spec):
            finding = rule.check(make_dep("pkg", spec), make_meta("pkg"), default_config)
            assert finding is None, f"B001 gap: '{spec}' is a range but is not caught."

        @pytest.mark.parametrize("spec", [
            "github:owner/repo",
            "git+https://github.com/owner/pkg.git",
            "bitbucket:owner/pkg",
        ])
        def test_git_shorthand_not_caught(self, rule, default_config, spec):
            finding = rule.check(make_dep("pkg", spec), make_meta("pkg"), default_config)
            assert finding is None, f"B001 gap: git dep '{spec}' has no rule."

        @pytest.mark.parametrize("spec", [
            "https://example.com/pkg.tar.gz",
            "http://example.com/pkg.tar.gz",
        ])
        def test_url_dep_not_caught(self, rule, default_config, spec):
            finding = rule.check(make_dep("pkg", spec), make_meta("pkg"), default_config)
            assert finding is None, f"B001 gap: URL dep '{spec}' has no rule."

        def test_file_path_not_caught(self, rule, default_config):
            finding = rule.check(make_dep("pkg", "file:../local"), make_meta("pkg"), default_config)
            assert finding is None, "B001 gap: file: path dep has no rule."

        def test_x_literal_not_caught(self, rule, default_config):
            finding = rule.check(make_dep("pkg", "x"), make_meta("pkg"), default_config)
            assert finding is None, "B001 gap: 'x' is only caught by B002, not B001."
