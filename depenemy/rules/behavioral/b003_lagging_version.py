"""B003 — Target version significantly lags behind latest."""

from __future__ import annotations

from typing import Optional

from packaging.version import InvalidVersion, Version

from depenemy.config import Config
from depenemy.rules.base import BaseRule
from depenemy.types import Dependency, Finding, PackageMetadata


class B003LaggingVersion(BaseRule):
    id = "B003"
    name = "Lagging version"
    description = "The pinned version is significantly behind the latest available version."

    def _check(
        self,
        dep: Dependency,
        meta: PackageMetadata,
        config: Config,
    ) -> Optional[Finding]:
        try:
            target = Version(meta.target_version)
            latest = Version(meta.latest_version)
        except InvalidVersion:
            return None

        if latest <= target:
            return None

        # Check major version lag
        if latest.major > target.major:
            lag = latest.major - target.major
            if lag >= 1:
                return self._finding(
                    dep,
                    config,
                    f"`{dep.name}` is {lag} major version(s) behind "
                    f"(using {meta.target_version}, latest is {meta.latest_version}).",
                    actual=meta.target_version,
                    expected=meta.latest_version,
                )
        # Check minor version lag within same major
        elif latest.major == target.major:
            lag = latest.minor - target.minor
            max_lag = config.thresholds.max_version_lag
            if lag >= max_lag:
                return self._finding(
                    dep,
                    config,
                    f"`{dep.name}` is {lag} minor versions behind "
                    f"(using {meta.target_version}, latest is {meta.latest_version}).",
                    actual=meta.target_version,
                    expected=meta.latest_version,
                )
        return None
