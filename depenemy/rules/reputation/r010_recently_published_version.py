"""R010 - Target version was published very recently."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from depenemy.config import Config
from depenemy.rules.base import BaseRule
from depenemy.types import Dependency, Finding, PackageMetadata


class R010RecentlyPublishedVersion(BaseRule):
    id = "R010"
    name = "Recently published version"
    description = (
        "The target version was published less than 7 days ago. "
        "Newly published versions have not been vetted by the community and are a common "
        "supply chain attack vector - the axios attack exploited this window."
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
        threshold = config.thresholds.min_version_age_days

        if age_days < threshold:
            return self._finding(
                dep,
                config,
                f"`{dep.name}@{meta.target_version}` was published only {age_days} days ago "
                f"- not yet vetted by the community (threshold: {threshold} days).",
                actual=f"{age_days} days old",
                expected=f">= {threshold} days",
            )
        return None
