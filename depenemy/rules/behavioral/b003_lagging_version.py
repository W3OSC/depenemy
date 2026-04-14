"""B003 - Target version significantly lags behind latest."""

from __future__ import annotations

import re
from typing import Optional

from depenemy.config import Config
from depenemy.rules.base import BaseRule, parse_semver
from depenemy.types import Dependency, Finding, PackageMetadata

_RANGE_PATTERN = re.compile(r"[\^~*]|>=|<=|>|!=|\|\|")


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
        if dep.is_dev:
            return None  # dev tool versions are not supply chain risks
        spec = dep.version_spec.strip()
        if spec in ("*", "", "latest") or _RANGE_PATTERN.search(spec):
            return None  # B001 already flags range specifiers; lag is meaningless without a pinned version
        target = parse_semver(meta.target_version)
        latest = parse_semver(meta.latest_version)

        if latest <= target:
            return None

        major_lag = latest[0] - target[0]
        if major_lag >= 1:
            return self._finding(
                dep,
                config,
                f"`{dep.name}` is {major_lag} major version(s) behind "
                f"(using {meta.target_version}, latest is {meta.latest_version}).",
                actual=meta.target_version,
                expected=meta.latest_version,
            )

        if latest[0] == target[0]:
            minor_lag = latest[1] - target[1]
            if minor_lag >= config.thresholds.max_version_lag:
                return self._finding(
                    dep,
                    config,
                    f"`{dep.name}` is {minor_lag} minor versions behind "
                    f"(using {meta.target_version}, latest is {meta.latest_version}).",
                    actual=meta.target_version,
                    expected=meta.latest_version,
                )
        return None
