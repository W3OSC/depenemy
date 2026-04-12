"""R002 - Package version is younger than threshold."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from depenemy.config import Config
from depenemy.rules.base import BaseRule
from depenemy.types import Dependency, Finding, PackageMetadata


class R002YoungPackage(BaseRule):
    id = "R002"
    name = "Young package version"
    description = (
        "The package version was published recently. "
        "New versions have less community scrutiny."
    )

    def _check(
        self,
        dep: Dependency,
        meta: PackageMetadata,
        config: Config,
    ) -> Optional[Finding]:
        if dep.is_dev:
            return None
        if not meta.published_at:
            return None

        now = datetime.now(timezone.utc)
        published = meta.published_at
        if published.tzinfo is None:
            published = published.replace(tzinfo=timezone.utc)

        age_days = (now - published).days
        threshold = config.thresholds.min_package_age_days

        if age_days < threshold:
            return self._finding(
                dep,
                config,
                f"`{dep.name}@{meta.target_version}` was published {age_days} days ago "
                f"(threshold: {threshold} days).",
                actual=f"{age_days} days",
                expected=f">= {threshold} days",
            )
        return None
