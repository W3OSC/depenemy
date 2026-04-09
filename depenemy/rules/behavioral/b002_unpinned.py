"""B002 — No version specified at all."""

from __future__ import annotations

from typing import Optional

from depenemy.config import Config
from depenemy.rules.base import BaseRule
from depenemy.types import Dependency, Finding, PackageMetadata


class B002Unpinned(BaseRule):
    id = "B002"
    name = "Unpinned dependency"
    description = "Dependency has no version constraint, allowing any version to be installed."

    def _check(
        self,
        dep: Dependency,
        meta: PackageMetadata,
        config: Config,
    ) -> Optional[Finding]:
        spec = dep.version_spec.strip()
        if spec in ("", "*", "latest", "x"):
            return self._finding(
                dep,
                config,
                f"`{dep.name}` has no version pinned (`{spec}`). "
                f"Latest is {meta.latest_version}.",
                actual=spec or "(empty)",
                expected=meta.latest_version,
            )
        return None
