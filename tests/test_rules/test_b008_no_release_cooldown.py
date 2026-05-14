"""Tests for B008 - No release cooldown configured."""
from __future__ import annotations

import json
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
    from depenemy.rules.behavioral.b008_no_release_cooldown import B008NoReleaseCooldown
    from depenemy.types import Dependency, Ecosystem, Location

    @pytest.fixture
    def rule() -> B008NoReleaseCooldown:
        return B008NoReleaseCooldown()

    def _dep(file: str, ecosystem: Ecosystem = Ecosystem.NPM) -> Dependency:
        return Dependency(
            name="anypkg",
            version_spec="1.0.0",
            ecosystem=ecosystem,
            location=Location(file=file, line=1),
        )

    def _write_manifest(tmp_path, name: str, ecosystem: Ecosystem):
        manifest = tmp_path / name
        manifest.write_text("{}")
        deps = [_dep(name, ecosystem)]
        return manifest, deps

    class TestB008NoConfig:
        """No cooldown config anywhere should fire B008."""

        def test_npm_no_config(self, rule, default_config, tmp_path):
            manifest, deps = _write_manifest(tmp_path, "package.json", Ecosystem.NPM)
            findings = rule.check_project(manifest, deps, default_config)
            assert len(findings) == 1
            assert findings[0].rule_id == "B008"
            assert "no cooldown config" in findings[0].actual

        def test_pypi_no_config(self, rule, default_config, tmp_path):
            manifest, deps = _write_manifest(tmp_path, "requirements.txt", Ecosystem.PYPI)
            findings = rule.check_project(manifest, deps, default_config)
            assert len(findings) == 1
            assert findings[0].rule_id == "B008"

        def test_no_deps_skips(self, rule, default_config, tmp_path):
            manifest = tmp_path / "package.json"
            manifest.write_text("{}")
            assert rule.check_project(manifest, [], default_config) == []

    class TestB008Dependabot:
        """Dependabot .github/dependabot.yml with cooldown.default-days satisfies rule."""

        def _write_dependabot(self, tmp_path, days: int):
            gh = tmp_path / ".github"
            gh.mkdir()
            (gh / "dependabot.yml").write_text(
                f"version: 2\n"
                f"updates:\n"
                f"  - package-ecosystem: pip\n"
                f"    directory: /\n"
                f"    schedule:\n"
                f"      interval: daily\n"
                f"    cooldown:\n"
                f"      default-days: {days}\n"
            )

        def test_dependabot_meets_threshold_passes(self, rule, default_config, tmp_path):
            self._write_dependabot(tmp_path, 7)
            manifest, deps = _write_manifest(tmp_path, "requirements.txt", Ecosystem.PYPI)
            assert rule.check_project(manifest, deps, default_config) == []

        def test_dependabot_above_threshold_passes(self, rule, default_config, tmp_path):
            self._write_dependabot(tmp_path, 30)
            manifest, deps = _write_manifest(tmp_path, "requirements.txt", Ecosystem.PYPI)
            assert rule.check_project(manifest, deps, default_config) == []

        def test_dependabot_below_threshold_fires(self, rule, default_config, tmp_path):
            self._write_dependabot(tmp_path, 3)
            manifest, deps = _write_manifest(tmp_path, "requirements.txt", Ecosystem.PYPI)
            findings = rule.check_project(manifest, deps, default_config)
            assert len(findings) == 1
            assert "3 days" in findings[0].actual

        def test_dependabot_walks_up_from_nested_manifest(self, rule, default_config, tmp_path):
            self._write_dependabot(tmp_path, 7)
            nested = tmp_path / "packages" / "backend"
            nested.mkdir(parents=True)
            manifest = nested / "requirements.txt"
            manifest.write_text("")
            deps = [_dep(str(manifest), Ecosystem.PYPI)]
            assert rule.check_project(manifest, deps, default_config) == []

    class TestB008Renovate:
        """Renovate top-level minimumReleaseAge satisfies rule."""

        def _write_renovate(self, tmp_path, value, filename="renovate.json"):
            (tmp_path / filename).write_text(json.dumps({"minimumReleaseAge": value}))

        def test_renovate_seven_days_string_passes(self, rule, default_config, tmp_path):
            self._write_renovate(tmp_path, "7 days")
            manifest, deps = _write_manifest(tmp_path, "requirements.txt", Ecosystem.PYPI)
            assert rule.check_project(manifest, deps, default_config) == []

        def test_renovate_one_week_passes(self, rule, default_config, tmp_path):
            self._write_renovate(tmp_path, "1 week")
            manifest, deps = _write_manifest(tmp_path, "package.json", Ecosystem.NPM)
            assert rule.check_project(manifest, deps, default_config) == []

        def test_renovate_three_days_fires(self, rule, default_config, tmp_path):
            self._write_renovate(tmp_path, "3 days")
            manifest, deps = _write_manifest(tmp_path, "requirements.txt", Ecosystem.PYPI)
            findings = rule.check_project(manifest, deps, default_config)
            assert len(findings) == 1

        def test_renovate_under_dot_github_passes(self, rule, default_config, tmp_path):
            (tmp_path / ".github").mkdir()
            self._write_renovate(tmp_path / ".github", "14 days", filename="renovate.json")
            manifest, deps = _write_manifest(tmp_path, "package.json", Ecosystem.NPM)
            assert rule.check_project(manifest, deps, default_config) == []

        def test_renovaterc_filename_recognized(self, rule, default_config, tmp_path):
            (tmp_path / ".renovaterc").write_text(json.dumps({"minimumReleaseAge": "7 days"}))
            manifest, deps = _write_manifest(tmp_path, "package.json", Ecosystem.NPM)
            assert rule.check_project(manifest, deps, default_config) == []

    class TestB008Pnpm:
        """pnpm.minimumReleaseAge in package.json (expressed in minutes) satisfies rule."""

        def _write_package_json(self, tmp_path, pnpm_value):
            manifest = tmp_path / "package.json"
            manifest.write_text(json.dumps({"pnpm": {"minimumReleaseAge": pnpm_value}}))
            return manifest

        def test_pnpm_seven_days_in_minutes_passes(self, rule, default_config, tmp_path):
            manifest = self._write_package_json(tmp_path, 10080)  # 7 days in minutes
            deps = [_dep("package.json", Ecosystem.NPM)]
            assert rule.check_project(manifest, deps, default_config) == []

        def test_pnpm_below_threshold_fires(self, rule, default_config, tmp_path):
            manifest = self._write_package_json(tmp_path, 1440)  # 1 day
            deps = [_dep("package.json", Ecosystem.NPM)]
            findings = rule.check_project(manifest, deps, default_config)
            assert len(findings) == 1

        def test_pnpm_only_applies_to_package_json(self, rule, default_config, tmp_path):
            # requirements.txt should not look at pnpm field even if a package.json sits beside it
            manifest = tmp_path / "requirements.txt"
            manifest.write_text("")
            (tmp_path / "package.json").write_text(json.dumps({"pnpm": {"minimumReleaseAge": 10080}}))
            deps = [_dep("requirements.txt", Ecosystem.PYPI)]
            findings = rule.check_project(manifest, deps, default_config)
            assert len(findings) == 1

    class TestB008Npmrc:
        """pnpm's minimum-release-age in .npmrc (expressed in minutes) satisfies rule."""

        def test_npmrc_seven_days_passes(self, rule, default_config, tmp_path):
            (tmp_path / ".npmrc").write_text("minimum-release-age=10080\n")
            manifest, deps = _write_manifest(tmp_path, "package.json", Ecosystem.NPM)
            assert rule.check_project(manifest, deps, default_config) == []

        def test_npmrc_below_threshold_fires(self, rule, default_config, tmp_path):
            (tmp_path / ".npmrc").write_text("minimum-release-age=1440\n")  # 1 day
            manifest, deps = _write_manifest(tmp_path, "package.json", Ecosystem.NPM)
            findings = rule.check_project(manifest, deps, default_config)
            assert len(findings) == 1

        def test_npmrc_mixed_with_other_keys(self, rule, default_config, tmp_path):
            (tmp_path / ".npmrc").write_text(
                "registry=https://registry.npmjs.org/\n"
                "minimum-release-age=20160\n"  # 14 days
                "save-exact=true\n"
            )
            manifest, deps = _write_manifest(tmp_path, "package.json", Ecosystem.NPM)
            assert rule.check_project(manifest, deps, default_config) == []

    class TestB008PnpmWorkspace:
        """pnpm-workspace.yaml top-level minimumReleaseAge (minutes) satisfies rule."""

        def test_pnpm_workspace_seven_days_passes(self, rule, default_config, tmp_path):
            (tmp_path / "pnpm-workspace.yaml").write_text("minimumReleaseAge: 10080\n")
            manifest, deps = _write_manifest(tmp_path, "package.json", Ecosystem.NPM)
            assert rule.check_project(manifest, deps, default_config) == []

        def test_pnpm_workspace_below_threshold_fires(self, rule, default_config, tmp_path):
            (tmp_path / "pnpm-workspace.yaml").write_text("minimumReleaseAge: 1440\n")
            manifest, deps = _write_manifest(tmp_path, "package.json", Ecosystem.NPM)
            findings = rule.check_project(manifest, deps, default_config)
            assert len(findings) == 1

    class TestB008ConfigurableThreshold:
        """Config.thresholds.min_release_cooldown_days controls the bar."""

        def test_tighter_threshold_fails_otherwise_passing_config(self, rule, tmp_path):
            (tmp_path / "renovate.json").write_text(json.dumps({"minimumReleaseAge": "7 days"}))
            manifest = tmp_path / "package.json"
            manifest.write_text("{}")
            deps = [_dep("package.json", Ecosystem.NPM)]

            config = Config()
            config.thresholds.min_release_cooldown_days = 14
            findings = rule.check_project(manifest, deps, config)
            assert len(findings) == 1
            assert "7 days" in findings[0].actual

        def test_looser_threshold_lets_short_cooldown_pass(self, rule, tmp_path):
            (tmp_path / "renovate.json").write_text(json.dumps({"minimumReleaseAge": "3 days"}))
            manifest = tmp_path / "package.json"
            manifest.write_text("{}")
            deps = [_dep("package.json", Ecosystem.NPM)]

            config = Config()
            config.thresholds.min_release_cooldown_days = 2
            assert rule.check_project(manifest, deps, config) == []
