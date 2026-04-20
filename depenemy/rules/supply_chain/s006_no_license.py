"""S006 - Package has no declared license."""

from __future__ import annotations

from typing import Optional, Any

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

    # Common placeholder values treated as "no license"
    INVALID_LICENSE_VALUES = {
        "",
        "unknown",
        "unlicensed",
        "none",
        "n/a",
        "na",
    }

    def _normalize_license(self, value: Any) -> str:
        """
        Normalize license value into a comparable string.
        Handles strings, lists, dicts, and unexpected formats safely.
        """
        if value is None:
            return ""

        # Handle list format (some ecosystems return multiple licenses)
        if isinstance(value, list):
            value = " ".join(str(v) for v in value)

        # Handle dict format (e.g., {"type": "MIT"})
        if isinstance(value, dict):
            value = value.get("type") or value.get("name") or ""

        if not isinstance(value, str):
            return ""

        return value.strip().lower()

    def _check(
        self,
        dep: Dependency,
        meta: PackageMetadata,
        config: Config,
    ) -> Optional[Finding]:

        raw_license = getattr(meta, "license", None)
        normalized = self._normalize_license(raw_license)

        # Handle "SEE LICENSE IN ..." pattern (common in npm)
        if normalized.startswith("see license in"):
            normalized = ""

        # If valid license exists → no issue
        if normalized and normalized not in self.INVALID_LICENSE_VALUES:
            return None

        return self._finding(
            dep,
            config,
            f"`{dep.name}` does not declare a valid license.",
            actual="no valid license declared",
        )