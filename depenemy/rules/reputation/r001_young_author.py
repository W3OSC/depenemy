"""R001 - Author account is younger than threshold."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from depenemy.config import Config
from depenemy.rules.base import BaseRule
from depenemy.types import Dependency, Finding, PackageMetadata


class R001YoungAuthor(BaseRule):
    id = "R001"
    name = "Young author account"
    description = (
        "The package author's account was created recently. "
        "New accounts are associated with higher supply chain risk."
    )

    def _check(
        self,
        dep: Dependency,
        meta: PackageMetadata,
        config: Config,
    ) -> Optional[Finding]:
        if not meta.author_account_created_at:
            return None

        now = datetime.now(timezone.utc)
        created = meta.author_account_created_at
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)

        age_days = (now - created).days
        threshold = config.thresholds.min_author_account_age_days

        if age_days < threshold:
            return self._finding(
                dep,
                config,
                f"`{dep.name}` author account is only {age_days} days old "
                f"(threshold: {threshold} days).",
                actual=f"{age_days} days",
                expected=f">= {threshold} days",
            )
        return None
