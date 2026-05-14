"""B008 - Project lacks a release-cooldown configuration for new package versions."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

from depenemy.config import Config
from depenemy.rules.base import BaseRule
from depenemy.types import Dependency, Finding, PackageMetadata

try:
    import yaml as _yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False


_DURATION_RE = re.compile(r"(\d+)\s*(minute|hour|day|week|month|year)s?", re.IGNORECASE)
_DURATION_DAYS = {
    "minute": 1.0 / 1440,
    "hour": 1.0 / 24,
    "day": 1.0,
    "week": 7.0,
    "month": 30.0,
    "year": 365.0,
}

_RENOVATE_FILENAMES = (
    "renovate.json",
    "renovate.json5",
    ".renovaterc",
    ".renovaterc.json",
)


def _parse_duration_to_days(value: object) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        match = _DURATION_RE.search(value)
        if match:
            n = int(match.group(1))
            unit = match.group(2).lower()
            factor = _DURATION_DAYS.get(unit)
            if factor is not None:
                return n * factor
    return None


class B008NoReleaseCooldown(BaseRule):
    id = "B008"
    name = "No release cooldown configured"
    description = (
        "The project has no configuration enforcing a minimum age before adopting new "
        "package versions. The publish-then-attack window (typically <7 days) is a "
        "documented supply chain vector. Configure a cooldown in Dependabot "
        "(updates[].cooldown.default-days), Renovate (minimumReleaseAge), or pnpm "
        "(minimum-release-age in .npmrc, minimumReleaseAge in pnpm-workspace.yaml, "
        "or pnpm.minimumReleaseAge in package.json)."
    )

    def _check(
        self,
        dep: Dependency,
        meta: PackageMetadata,
        config: Config,
    ) -> Optional[Finding]:
        return None

    def _check_project(
        self,
        manifest_path: Path,
        deps: list[Dependency],
        config: Config,
    ) -> list[Finding]:
        if not deps:
            return []

        threshold = config.thresholds.min_release_cooldown_days
        detected = self._detect_max_cooldown_days(manifest_path)

        if detected is not None and detected >= threshold:
            return []

        anchor = Dependency(
            name=str(manifest_path),
            version_spec="",
            ecosystem=deps[0].ecosystem,
            location=deps[0].location,
        )
        actual = f"{detected:g} days" if detected is not None else "no cooldown config"
        return [Finding(
            rule_id=self.id,
            rule_name=self.name,
            severity=config.rule_severity(self.id),
            dependency=anchor,
            message=(
                f"`{manifest_path.name}` has no release cooldown >= {threshold} days. "
                f"Without it, a malicious version published anywhere in the dep tree "
                f"can be pulled in immediately. Configure Dependabot "
                f"`updates[].cooldown.default-days`, Renovate `minimumReleaseAge`, or "
                f"pnpm (`minimum-release-age` in `.npmrc`, `minimumReleaseAge` in "
                f"`pnpm-workspace.yaml`, or `pnpm.minimumReleaseAge` in `package.json`)."
            ),
            actual=actual,
            expected=f">= {threshold} days",
        )]

    @staticmethod
    def _detect_max_cooldown_days(manifest_path: Path) -> Optional[float]:
        best: Optional[float] = None

        def consider(value: Optional[float]) -> None:
            nonlocal best
            if value is None:
                return
            if best is None or value > best:
                best = value

        for parent in [manifest_path.parent, *manifest_path.parent.parents]:
            consider(_read_dependabot_cooldown(parent / ".github" / "dependabot.yml"))
            for name in _RENOVATE_FILENAMES:
                consider(_read_renovate_cooldown(parent / name))
                consider(_read_renovate_cooldown(parent / ".github" / name))
            consider(_read_npmrc_cooldown(parent / ".npmrc"))
            consider(_read_pnpm_workspace_cooldown(parent / "pnpm-workspace.yaml"))
            # Boundary: stop at repo root (git dir or worktree file)
            if (parent / ".git").exists():
                break

        if manifest_path.name == "package.json":
            consider(_read_pnpm_cooldown(manifest_path))

        return best


def _read_dependabot_cooldown(path: Path) -> Optional[float]:
    if not path.exists() or not _HAS_YAML:
        return None
    try:
        with open(path) as fh:
            data = _yaml.safe_load(fh) or {}
    except (OSError, _yaml.YAMLError):
        return None
    updates = data.get("updates")
    if not isinstance(updates, list):
        return None
    best: Optional[float] = None
    for entry in updates:
        if not isinstance(entry, dict):
            continue
        cooldown = entry.get("cooldown")
        if not isinstance(cooldown, dict):
            continue
        days = cooldown.get("default-days")
        if isinstance(days, (int, float)) and not isinstance(days, bool):
            value = float(days)
            if best is None or value > best:
                best = value
    return best


def _read_renovate_cooldown(path: Path) -> Optional[float]:
    if not path.exists():
        return None
    try:
        with open(path) as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    return _parse_duration_to_days(data.get("minimumReleaseAge"))


_NPMRC_RELEASE_AGE_RE = re.compile(
    r"^\s*minimum-release-age\s*=\s*(\d+)\s*$",
    re.IGNORECASE | re.MULTILINE,
)


def _read_npmrc_cooldown(path: Path) -> Optional[float]:
    if not path.exists():
        return None
    try:
        text = path.read_text()
    except OSError:
        return None
    best: Optional[float] = None
    for match in _NPMRC_RELEASE_AGE_RE.finditer(text):
        minutes = float(match.group(1))
        days = minutes / 1440.0
        if best is None or days > best:
            best = days
    return best


def _read_pnpm_workspace_cooldown(path: Path) -> Optional[float]:
    if not path.exists() or not _HAS_YAML:
        return None
    try:
        with open(path) as fh:
            data = _yaml.safe_load(fh) or {}
    except (OSError, _yaml.YAMLError):
        return None
    if not isinstance(data, dict):
        return None
    value = data.get("minimumReleaseAge")
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value) / 1440.0
    return None


def _read_pnpm_cooldown(package_json_path: Path) -> Optional[float]:
    if not package_json_path.exists():
        return None
    try:
        with open(package_json_path) as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    pnpm = data.get("pnpm")
    if not isinstance(pnpm, dict):
        return None
    value = pnpm.get("minimumReleaseAge")
    # pnpm 10's minimumReleaseAge is expressed in minutes
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value) / 1440.0
    return None
