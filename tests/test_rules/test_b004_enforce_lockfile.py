"""Tests for B004 - Enforce lockfile rule."""
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
    from depenemy.rules.behavioral.b004_enforce_lockfile import B004EnforceLockfile
    from depenemy.types import Dependency, Ecosystem, Location

    @pytest.fixture
    def rule() -> B004EnforceLockfile:
        return B004EnforceLockfile()

    def _dep(name: str, file: str, ecosystem: Ecosystem = Ecosystem.NPM) -> Dependency:
        return Dependency(
            name=name,
            version_spec="1.0.0",
            ecosystem=ecosystem,
            location=Location(file=file, line=1),
        )

    class TestB004Fires:
        """Manifest with no adjacent lockfile should fire B004."""

        def test_npm_no_lockfile(self, rule, default_config, tmp_path):
            manifest = tmp_path / "package.json"
            manifest.write_text('{"dependencies": {"lodash": "1.0.0"}}')
            findings = rule.check_project(manifest, [_dep("lodash", str(manifest))], default_config)
            assert len(findings) == 1
            assert findings[0].rule_id == "B004"

        def test_pipfile_no_lockfile(self, rule, default_config, tmp_path):
            manifest = tmp_path / "Pipfile"
            manifest.write_text("")
            findings = rule.check_project(
                manifest,
                [_dep("requests", str(manifest), Ecosystem.PYPI)],
                default_config,
            )
            assert len(findings) == 1

        def test_pyproject_no_lockfile(self, rule, default_config, tmp_path):
            manifest = tmp_path / "pyproject.toml"
            manifest.write_text("")
            findings = rule.check_project(
                manifest,
                [_dep("requests", str(manifest), Ecosystem.PYPI)],
                default_config,
            )
            assert len(findings) == 1

        def test_cargo_no_lockfile(self, rule, default_config, tmp_path):
            manifest = tmp_path / "Cargo.toml"
            manifest.write_text("")
            findings = rule.check_project(
                manifest,
                [_dep("serde", str(manifest), Ecosystem.CARGO)],
                default_config,
            )
            assert len(findings) == 1

        def test_severity_is_warning_by_default(self, rule, default_config, tmp_path):
            from depenemy.types import Severity
            manifest = tmp_path / "package.json"
            manifest.write_text("{}")
            findings = rule.check_project(manifest, [_dep("x", str(manifest))], default_config)
            assert findings[0].severity == Severity.WARNING

        def test_message_lists_acceptable_lockfiles(self, rule, default_config, tmp_path):
            manifest = tmp_path / "package.json"
            manifest.write_text("{}")
            findings = rule.check_project(manifest, [_dep("x", str(manifest))], default_config)
            assert "package-lock.json" in findings[0].message
            assert "yarn.lock" in findings[0].message
            assert "pnpm-lock.yaml" in findings[0].message

    class TestB004Silent:
        """Manifest with an acceptable lockfile should not fire."""

        @pytest.mark.parametrize("lockfile", [
            "package-lock.json",
            "npm-shrinkwrap.json",
            "yarn.lock",
            "pnpm-lock.yaml",
        ])
        def test_npm_with_any_lockfile(self, rule, default_config, tmp_path, lockfile):
            manifest = tmp_path / "package.json"
            manifest.write_text("{}")
            (tmp_path / lockfile).write_text("")
            findings = rule.check_project(manifest, [_dep("x", str(manifest))], default_config)
            assert findings == []

        def test_pipfile_with_pipfile_lock(self, rule, default_config, tmp_path):
            manifest = tmp_path / "Pipfile"
            manifest.write_text("")
            (tmp_path / "Pipfile.lock").write_text("")
            findings = rule.check_project(
                manifest,
                [_dep("x", str(manifest), Ecosystem.PYPI)],
                default_config,
            )
            assert findings == []

        @pytest.mark.parametrize("lockfile", ["poetry.lock", "uv.lock", "pdm.lock"])
        def test_pyproject_with_any_python_lockfile(self, rule, default_config, tmp_path, lockfile):
            manifest = tmp_path / "pyproject.toml"
            manifest.write_text("")
            (tmp_path / lockfile).write_text("")
            findings = rule.check_project(
                manifest,
                [_dep("x", str(manifest), Ecosystem.PYPI)],
                default_config,
            )
            assert findings == []

        def test_cargo_with_cargo_lock(self, rule, default_config, tmp_path):
            manifest = tmp_path / "Cargo.toml"
            manifest.write_text("")
            (tmp_path / "Cargo.lock").write_text("")
            findings = rule.check_project(
                manifest,
                [_dep("x", str(manifest), Ecosystem.CARGO)],
                default_config,
            )
            assert findings == []

        def test_requirements_txt_skipped(self, rule, default_config, tmp_path):
            # requirements.txt is itself a pin source; absence of separate lockfile is fine.
            manifest = tmp_path / "requirements.txt"
            manifest.write_text("requests==2.31.0\n")
            findings = rule.check_project(
                manifest,
                [_dep("requests", str(manifest), Ecosystem.PYPI)],
                default_config,
            )
            assert findings == []

        def test_unknown_manifest_skipped(self, rule, default_config, tmp_path):
            manifest = tmp_path / "weird.toml"
            manifest.write_text("")
            findings = rule.check_project(manifest, [_dep("x", str(manifest))], default_config)
            assert findings == []

        def test_empty_deps_skipped(self, rule, default_config, tmp_path):
            manifest = tmp_path / "package.json"
            manifest.write_text("{}")
            findings = rule.check_project(manifest, [], default_config)
            assert findings == []

        def test_rule_disabled_via_config(self, rule, tmp_path):
            config = Config(rules={})
            manifest = tmp_path / "package.json"
            manifest.write_text("{}")
            findings = rule.check_project(manifest, [_dep("x", str(manifest))], config)
            assert findings == []

    class TestB004PerDepIsNoop:
        """The per-dep _check should never produce a finding."""

        def test_per_dep_check_returns_none(self, rule, default_config):
            from tests.conftest import make_dep, make_meta
            assert rule.check(make_dep("x", "1.0.0"), make_meta("x"), default_config) is None
