"""R004 - Low total download count."""

from __future__ import annotations

from typing import Optional

from depenemy.config import Config
from depenemy.rules.base import BaseRule
from depenemy.types import Dependency, Finding, PackageMetadata


class R004LowTotalDownloads(BaseRule):
    id = "R004"
    name = "Low total downloads"
    description = "The package has few total downloads across its lifetime."

    def _check(
        self,
        dep: Dependency,
        meta: PackageMetadata,
        config: Config,
    ) -> Optional[Finding]:
        if meta.total_downloads == 0:
            return None  # API unavailable - skip

        threshold = config.thresholds.min_total_downloads
        if meta.total_downloads < threshold:
            return self._finding(
                dep,
                config,
                f"`{dep.name}` has only {meta.total_downloads:,} total downloads "
                f"(threshold: {threshold:,}).",
                actual=f"{meta.total_downloads:,}",
                expected=f">= {threshold:,}",
            )
        return None
