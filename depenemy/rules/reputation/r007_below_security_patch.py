"""R007 - Target version is below the latest known security patch."""

from __future__ import annotations

from typing import Optional

from depenemy.config import Config
from depenemy.rules.base import BaseRule, parse_semver
from depenemy.types import Dependency, Finding, PackageMetadata, Severity


class R007BelowSecurityPatch(BaseRule):
    id = "R007"
    name = "Known vulnerable version"
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

        target = parse_semver(meta.target_version)

        for advisory in meta.advisories:
            if not advisory.patched_version:
                continue
            patched = parse_semver(advisory.patched_version)
            if target < patched:
                severity = (
                    Severity.WARNING if advisory.severity == "low"
                    else config.rule_severity(self.id)
                )
                return self._finding(
                    dep,
                    config,
                    f"`{dep.name}@{meta.target_version}` is affected by {advisory.id} "
                    f"({advisory.severity}). Patched in {advisory.patched_version}.",
                    actual=f"{meta.target_version} [{advisory.severity} CVE]",
                    expected=f">= {advisory.patched_version}",
                    severity=severity,
                )
        return None
