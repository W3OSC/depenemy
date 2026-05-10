"""S008 - Package publisher released an unusually large number of packages in a short window."""

from __future__ import annotations

from typing import Optional

from depenemy.config import Config
from depenemy.rules.base import BaseRule
from depenemy.types import Dependency, Finding, PackageMetadata


class S008BulkPublish(BaseRule):
    id = "S008"
    name = "Bulk publish burst"
    description = (
        "The npm publisher released an unusually large number of packages within a short "
        "time window. Bulk-publish bursts are a known tactic in typosquatting and "
        "dependency confusion campaigns where an attacker registers hundreds of package "
        "names simultaneously to maximise the chance of a victim installing one. "
        "Legitimate maintainers rarely publish more than a handful of packages within 48 hours."
    )

    def _check(
        self,
        dep: Dependency,
        meta: PackageMetadata,
        config: Config,
    ) -> Optional[Finding]:
        if not meta.publisher_name:
            return None

        threshold = config.thresholds.bulk_publish_min_packages
        burst = meta.author_package_burst_count

        if burst < threshold:
            return None

        return self._finding(
            dep,
            config,
            f"`{dep.name}` was published by `{meta.publisher_name}` who published "
            f"{burst} packages within a {config.thresholds.bulk_publish_window_hours}-hour "
            f"window. This bulk-publish pattern is a strong indicator of a mass typosquatting "
            f"or dependency confusion campaign.",
            actual=f"burst={burst}",
        )
