"""C002 — Package has no license specified."""

from __future__ import annotations

from typing import Optional

from depenemy.config import Config
from depenemy.rules.base import BaseRule
from depenemy.types import Dependency, Finding, PackageMetadata


class C002NoLicense(BaseRule):
    id = "C002"
    name = "No license"
    description = "The package has no license specified, meaning all rights are reserved by default."

    def _check(
        self,
        dep: Dependency,
        meta: PackageMetadata,
        config: Config,
    ) -> Optional[Finding]:
        if meta.license:
            return None

        return self._finding(
            dep,
            config,
            f"`{dep.name}` has no license specified. "
            f"Without an explicit license, all rights are reserved.",
            actual="no license",
            expected="explicit open source license",
        )
