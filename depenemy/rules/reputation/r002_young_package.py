"""R002 - Package version is younger than threshold."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from depenemy.config import Config
from depenemy.rules.base import BaseRule
from depenemy.types import Dependency, Finding, PackageMetadata


class R002YoungPackage(BaseRule):
    id = "R002"
    name = "New package"
    description = (
        "The package was first published less than 6 months ago. "
        "New packages have no track record and less community scrutiny."
    )

    def _check(
        self,
        dep: Dependency,
        meta: PackageMetadata,
        config: Config,
    ) -> Optional[Finding]:
        if dep.is_dev:
            return None
        # R002 measures *package* age, not target-version age - those are R010's
        # concerns and use a separate threshold. published_at is target-scoped
        # per the type contract, so we must use first_published_at here.
        if not meta.first_published_at:
            return None

        now = datetime.now(timezone.utc)
        published = meta.first_published_at
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
