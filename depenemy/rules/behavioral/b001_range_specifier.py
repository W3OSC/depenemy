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
        "Ranges allow unreviewed updates to silently enter the supply chain."
    )

    def _check(
        self,
        dep: Dependency,
        meta: PackageMetadata,
        config: Config,
    ) -> Optional[Finding]:
        spec = dep.version_spec.strip()
        if spec in ("*", "", "latest"):
            return self._finding(
                dep,
                config,
                f"`{dep.name}` uses `{spec}` - installs any version, no pinning.",
                actual=spec,
                expected="exact version, e.g. 1.2.3",
            )
        if RANGE_PATTERN.search(spec):
            return self._finding(
                dep,
                config,
                f"`{dep.name}` uses range `{spec}` - pin to an exact version.",
                actual=spec,
                expected="exact version, e.g. 1.2.3",
            )
        return None
