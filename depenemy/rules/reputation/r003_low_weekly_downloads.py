"""R003 - Low weekly download count."""

from __future__ import annotations

from typing import Optional

from depenemy.config import Config
from depenemy.rules.base import BaseRule
from depenemy.types import Dependency, Finding, PackageMetadata


class R003LowWeeklyDownloads(BaseRule):
    id = "R003"
    name = "Low weekly downloads"
    description = "The package has few weekly downloads, indicating low adoption."

    def _check(
        self,
        dep: Dependency,
        meta: PackageMetadata,
        config: Config,
    ) -> Optional[Finding]:
        if dep.is_dev:
            return None
        if meta.weekly_downloads == 0:
            return None  # API unavailable - skip

        threshold = config.thresholds.min_weekly_downloads
        if meta.weekly_downloads < threshold:
            return self._finding(
                dep,
                config,
                f"`{dep.name}` has only {meta.weekly_downloads:,} weekly downloads "
                f"(threshold: {threshold:,}).",
                actual=f"{meta.weekly_downloads:,}",
                expected=f">= {threshold:,}",
            )
        return None
