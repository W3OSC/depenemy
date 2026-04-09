"""B003 - Target version significantly lags behind latest."""

from __future__ import annotations

from typing import Optional

from depenemy.config import Config
from depenemy.rules.base import BaseRule
from depenemy.types import Dependency, Finding, PackageMetadata


def _parse_ver(v: str) -> tuple[int, int, int]:
    try:
        parts = v.strip().lstrip("v").split(".")[:3]
        nums = []
        for p in parts:
            nums.append(int(p.split("-")[0].split("+")[0]))
        while len(nums) < 3:
            nums.append(0)
        return (nums[0], nums[1], nums[2])
    except (ValueError, AttributeError):
        return (0, 0, 0)


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
        target = _parse_ver(meta.target_version)
        latest = _parse_ver(meta.latest_version)

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
