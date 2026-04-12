"""B001 - Version range specifier used instead of exact pin."""

from __future__ import annotations

import re
from typing import Optional

from depenemy.config import Config
from depenemy.rules.base import BaseRule
from depenemy.types import Dependency, Finding, PackageMetadata

RANGE_PATTERN = re.compile(r"[\^~*]|>=|>|!=|\|\||\s")


class B001RangeSpecifier(BaseRule):
    id = "B001"
    name = "Range specifier"
    description = (
        "Dependency uses a version range instead of an exact pin. "
        "Ranges allow unreviewed updates to silently enter the supply chain "
        "(e.g. the axios supply chain attack exploited a ^ range)."
    )

    def _check(
        self,
        dep: Dependency,
        meta: PackageMetadata,
        config: Config,
    ) -> Optional[Finding]:
        if dep.is_dev:
            return None  # ranges are standard practice for dev/build tools
        spec = dep.version_spec.strip()
        if spec.startswith("workspace:"):
            return None  # monorepo local package reference, not a registry range
        if spec in ("*", "", "latest"):
            return self._finding(
                dep,
                config,
                f"`{dep.name}` uses `{spec}` - any version can be installed automatically "
                f"without your approval. This is how supply chain attacks like axios happen.",
                actual=spec,
                expected="exact version, e.g. 1.2.3",
            )
        if RANGE_PATTERN.search(spec):
            return self._finding(
                dep,
                config,
                f"`{dep.name}` uses range `{spec}` - a malicious update can be pulled in "
                f"automatically without your approval. Pin to an exact version.",
                actual=spec,
                expected="exact version, e.g. 1.2.3",
            )
        return None
