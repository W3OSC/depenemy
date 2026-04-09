"""R007 - Target version is below the latest known security patch."""

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


class R007BelowSecurityPatch(BaseRule):
    id = "R007"
    name = "Below security patch"
    description = (
        "The target version is older than a version released to fix a known vulnerability."
    )

    def _check(
        self,
        dep: Dependency,
        meta: PackageMetadata,
        config: Config,
    ) -> Optional[Finding]:
        if not meta.advisories:
            return None

        target = _parse_ver(meta.target_version)

        for advisory in meta.advisories:
            if not advisory.patched_version:
                continue
            patched = _parse_ver(advisory.patched_version)
            if target < patched:
                return self._finding(
                    dep,
                    config,
                    f"`{dep.name}@{meta.target_version}` is affected by {advisory.id} "
                    f"({advisory.severity}). Patched in {advisory.patched_version}.",
                    actual=meta.target_version,
                    expected=f">= {advisory.patched_version}",
                )
        return None
