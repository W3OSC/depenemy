"""R008 — Package is officially deprecated."""

from __future__ import annotations

from typing import Optional

from depenemy.config import Config
from depenemy.rules.base import BaseRule
from depenemy.types import Dependency, Finding, PackageMetadata


class R008Deprecated(BaseRule):
    id = "R008"
    name = "Deprecated package"
    description = "The package is officially marked as deprecated by its maintainer."

    def _check(
        self,
        dep: Dependency,
        meta: PackageMetadata,
        config: Config,
    ) -> Optional[Finding]:
        if not meta.is_deprecated:
            return None

        detail = f": {meta.deprecation_message}" if meta.deprecation_message else ""
        return self._finding(
            dep,
            config,
            f"`{dep.name}` is officially deprecated{detail}",
            actual="deprecated",
            expected="not deprecated",
        )
