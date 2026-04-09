"""Q001 - Package has only one maintainer (single point of failure)."""

from __future__ import annotations

from typing import Optional

from depenemy.config import Config
from depenemy.rules.base import BaseRule
from depenemy.types import Dependency, Finding, PackageMetadata


class Q001SingleMaintainer(BaseRule):
    id = "Q001"
    name = "Single maintainer"
    description = (
        "The package has only one maintainer. A single compromised account "
        "or maintainer going rogue can compromise all dependents."
    )

    def _check(
        self,
        dep: Dependency,
        meta: PackageMetadata,
        config: Config,
    ) -> Optional[Finding]:
        if meta.maintainer_count == 0:
            return None  # Data unavailable - skip

        if meta.maintainer_count == 1:
            return self._finding(
                dep,
                config,
                f"`{dep.name}` has only 1 maintainer. "
                f"A single compromised account can poison all dependents.",
                actual="1 maintainer",
                expected=">= 2 maintainers",
            )
        return None
