"""S006 - Package has no declared license."""

from __future__ import annotations

from typing import Optional

from depenemy.config import Config
from depenemy.rules.base import BaseRule
from depenemy.types import Dependency, Finding, PackageMetadata


class S006NoLicense(BaseRule):
    id = "S006"
    name = "No license declared"
    description = (
        "This package does not declare a valid license. "
        "Using such packages may introduce legal and compliance risks."
    )

    INVALID_LICENSE_VALUES = {
        None,
        "",
        "unknown",
        "unlicensed",
        "none",
    }

    def _check(
        self,
        dep: Dependency,
        meta: PackageMetadata,
        config: Config,
    ) -> Optional[Finding]:

        license_value = getattr(meta, "license", None)

        # Normalize license
        if isinstance(license_value, str):
            normalized = license_value.strip().lower()
        else:
            normalized = None

        # Check invalid or missing license
        if normalized not in self.INVALID_LICENSE_VALUES:
            return None

        return self._finding(
            dep,
            config,
            f"`{dep.name}` does not declare a valid license.",
            actual="no valid license declared",
        )