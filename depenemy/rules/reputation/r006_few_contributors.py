"""R006 - Package has very few contributors on GitHub."""

from __future__ import annotations

from typing import Optional

from depenemy.config import Config
from depenemy.rules.base import BaseRule
from depenemy.types import Dependency, Finding, PackageMetadata


class R006FewContributors(BaseRule):
    id = "R006"
    name = "Few contributors"
    description = (
        "The package repository has very few contributors, "
        "indicating low community oversight."
    )

    def _check(
        self,
        dep: Dependency,
        meta: PackageMetadata,
        config: Config,
    ) -> Optional[Finding]:
        if meta.contributor_count == 0:
            return None  # GitHub data unavailable - skip

        threshold = config.thresholds.min_contributors
        if meta.contributor_count < threshold:
            return self._finding(
                dep,
                config,
                f"`{dep.name}` has only {meta.contributor_count} contributor(s) "
                f"on GitHub (threshold: {threshold}).",
                actual=str(meta.contributor_count),
                expected=f">= {threshold}",
            )
        return None
