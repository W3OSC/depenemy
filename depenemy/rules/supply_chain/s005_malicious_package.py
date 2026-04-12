"""S005 - Package has a known history of malicious activity."""

from __future__ import annotations

from typing import Optional

from depenemy.config import Config
from depenemy.rules.base import BaseRule
from depenemy.types import Dependency, Finding, PackageMetadata


class S005MaliciousPackage(BaseRule):
    id = "S005"
    name = "Known malicious package"
    description = (
        "This package has a recorded history of malicious activity in OSV. "
        "It may have been compromised, hijacked, or used as a supply chain attack vector."
    )

    def _check(
        self,
        dep: Dependency,
        meta: PackageMetadata,
        config: Config,
    ) -> Optional[Finding]:
        if not meta.malicious_advisories:
            return None

        advisory = meta.malicious_advisories[0]
        return self._finding(
            dep,
            config,
            f"`{dep.name}` has a known malicious activity record ({advisory.id}): "
            f"{advisory.description}",
            actual="malicious activity recorded",
            expected="no malicious history",
        )
