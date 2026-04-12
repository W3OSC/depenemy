"""R005 - Package has not been updated for too long."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from depenemy.config import Config
from depenemy.rules.base import BaseRule
from depenemy.types import Dependency, Finding, PackageMetadata


class R005StalePackage(BaseRule):
    id = "R005"
    name = "No updates in 2+ years"
    description = (
        "The package has not been published in over 2 years, "
        "suggesting it may be abandoned."
    )

    def _check(
        self,
        dep: Dependency,
        meta: PackageMetadata,
        config: Config,
    ) -> Optional[Finding]:
        if dep.is_dev:
            return None
        if not meta.last_published_at:
            return None

        now = datetime.now(timezone.utc)
        last = meta.last_published_at
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)

        days_since = (now - last).days
        threshold = config.thresholds.max_stale_days

        if days_since > threshold:
            years = days_since // 365
            label = f"{years} year(s)" if years else f"{days_since} days"
            return self._finding(
                dep,
                config,
                f"`{dep.name}` has not been updated in {label} "
                f"(last publish: {last.date()}).",
                actual=f"{days_since} days since last publish",
                expected=f"< {threshold} days",
            )
        return None
