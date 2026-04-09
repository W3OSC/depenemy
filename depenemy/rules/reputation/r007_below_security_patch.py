"""R007 — Target version is below the latest known security patch."""

from __future__ import annotations

from typing import Optional

from packaging.version import InvalidVersion, Version

from depenemy.config import Config
from depenemy.rules.base import BaseRule
from depenemy.types import Dependency, Finding, PackageMetadata


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

        try:
            target = Version(meta.target_version)
        except InvalidVersion:
            return None

        for advisory in meta.advisories:
            if not advisory.patched_version:
                continue
            try:
                patched = Version(advisory.patched_version)
            except InvalidVersion:
                continue

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
