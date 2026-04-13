"""Tests for the npm package.json parser."""
from __future__ import annotations

import unittest

try:
    import pytest  # noqa: F401
    _HAS_PYTEST = True
except ImportError:
    _HAS_PYTEST = False


def load_tests(loader, tests, pattern):  # noqa: ARG001
    """Requires pytest fixtures (npm_parser) - skip under plain unittest."""
    if not _HAS_PYTEST:
        return unittest.TestSuite()
    return tests


if _HAS_PYTEST:
    from depenemy.types import Ecosystem
    from tests.conftest import FIXTURES_NPM


class TestNpmParserClean:
    def test_parses_all_sections(self, npm_parser):
        deps = npm_parser.parse(FIXTURES_NPM / "clean_exact_pins.json")
        names = {d.name for d in deps}
        assert names == {"express", "lodash", "axios", "jest", "typescript"}

    def test_dev_deps_flagged(self, npm_parser):
        deps = npm_parser.parse(FIXTURES_NPM / "clean_exact_pins.json")
        dev_names = {d.name for d in deps if d.is_dev}
        assert dev_names == {"jest", "typescript"}

    def test_prod_deps_not_dev(self, npm_parser):
        deps = npm_parser.parse(FIXTURES_NPM / "clean_exact_pins.json")
        prod = {d.name for d in deps if not d.is_dev}
        assert {"express", "lodash", "axios"} == prod

    def test_exact_version_spec_preserved(self, npm_parser):
        deps = npm_parser.parse(FIXTURES_NPM / "clean_exact_pins.json")
        by_name = {d.name: d for d in deps}
        assert by_name["express"].version_spec == "4.18.2"
        assert by_name["lodash"].version_spec == "4.17.21"

    def test_ecosystem_is_npm(self, npm_parser):
        deps = npm_parser.parse(FIXTURES_NPM / "clean_exact_pins.json")
        assert all(d.ecosystem == Ecosystem.NPM for d in deps)

    def test_line_numbers_are_positive(self, npm_parser):
        deps = npm_parser.parse(FIXTURES_NPM / "clean_exact_pins.json")
        assert all(d.location.line > 0 for d in deps)

    def test_file_path_recorded(self, npm_parser):
        path = FIXTURES_NPM / "clean_exact_pins.json"
        deps = npm_parser.parse(path)
        assert all(d.location.file == str(path) for d in deps)


class TestNpmParserRangeFixtures:
    def test_caret_spec_preserved(self, npm_parser):
        deps = npm_parser.parse(FIXTURES_NPM / "b001_caret_ranges.json")
        by_name = {d.name: d for d in deps}
        assert by_name["express"].version_spec == "^4.18.2"
        assert by_name["lodash"].version_spec == "^4.17.21"

    def test_tilde_spec_preserved(self, npm_parser):
        deps = npm_parser.parse(FIXTURES_NPM / "b001_tilde_ranges.json")
        by_name = {d.name: d for d in deps}
        assert by_name["express"].version_spec == "~4.18.2"

    def test_star_spec_preserved(self, npm_parser):
        deps = npm_parser.parse(FIXTURES_NPM / "b001_star_wildcard.json")
        assert all(d.version_spec == "*" for d in deps)

    def test_latest_spec_preserved(self, npm_parser):
        deps = npm_parser.parse(FIXTURES_NPM / "b001_latest_tag.json")
        assert all(d.version_spec == "latest" for d in deps)

    def test_empty_version_preserved(self, npm_parser):
        deps = npm_parser.parse(FIXTURES_NPM / "b002_empty_version.json")
        assert all(d.version_spec == "" for d in deps)

    def test_x_literal_version_preserved(self, npm_parser):
        deps = npm_parser.parse(FIXTURES_NPM / "b002_x_version.json")
        assert all(d.version_spec == "x" for d in deps)


class TestNpmParserMixed:
    def test_finds_all_sections_including_peer_and_optional(self, npm_parser):
        deps = npm_parser.parse(FIXTURES_NPM / "mixed_bad_patterns.json")
        names = {d.name for d in deps}
        # deps + devDeps + peerDeps + optionalDeps
        assert "express" in names      # dependencies
        assert "jest" in names         # devDependencies
        assert "react" in names        # peerDependencies (also in dependencies)
        assert "fsevents" in names     # optionalDependencies

    def test_typescript_is_dev_and_pinned(self, npm_parser):
        deps = npm_parser.parse(FIXTURES_NPM / "mixed_bad_patterns.json")
        ts = next(d for d in deps if d.name == "typescript" and d.is_dev)
        assert ts.version_spec == "5.3.3"

    def test_multiple_different_specs_in_one_file(self, npm_parser):
        deps = npm_parser.parse(FIXTURES_NPM / "mixed_bad_patterns.json")
        by_name = {d.name: d.version_spec for d in deps if not d.is_dev}
        assert "^" in by_name.get("express", "")
        assert by_name.get("lodash") == "*"
        assert by_name.get("axios") == "latest"


class TestNpmParserFutureTargets:
    """Parser should correctly read future-rule target fixtures without crashing."""

    def test_git_deps_parsed(self, npm_parser):
        deps = npm_parser.parse(FIXTURES_NPM / "future_git_dep.json")
        by_name = {d.name: d.version_spec for d in deps}
        assert by_name["mylib"] == "github:owner/mylib"
        assert by_name["helper"] == "git+https://github.com/owner/helper.git"

    def test_http_deps_parsed(self, npm_parser):
        deps = npm_parser.parse(FIXTURES_NPM / "future_http_dep.json")
        assert any(d.version_spec.startswith("https://") for d in deps)

    def test_file_deps_parsed(self, npm_parser):
        deps = npm_parser.parse(FIXTURES_NPM / "future_file_dep.json")
        by_name = {d.name: d.version_spec for d in deps}
        assert by_name["shared"] == "file:../shared"
        assert by_name["monorepo-pkg"] == "workspace:*"

    def test_install_scripts_fixture_has_exact_dep(self, npm_parser):
        deps = npm_parser.parse(FIXTURES_NPM / "future_install_scripts.json")
        assert any(d.name == "express" and d.version_spec == "4.18.2" for d in deps)
