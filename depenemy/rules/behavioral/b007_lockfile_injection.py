"""B007 - package-lock.json resolved URL points to a different package name."""

from __future__ import annotations

from typing import Optional
from urllib.parse import urlparse

from depenemy.config import Config
from depenemy.rules.base import BaseRule
from depenemy.types import Dependency, Finding, PackageMetadata


class B007LockfileInjection(BaseRule):
    id = "B007"
    name = "Lockfile resolved URL injection"
    description = (
        "The `resolved` URL in package-lock.json points to a tarball whose path does "
        "not contain the expected package name. This is a strong indicator of a lockfile "
        "injection attack where the URL is manually replaced to serve a malicious tarball "
        "under a trusted package name."
    )

    def _check(
        self,
        dep: Dependency,
        meta: PackageMetadata,
        config: Config,
    ) -> Optional[Finding]:
        resolved = dep.lockfile_resolved
        if not resolved:
            return None

        try:
            path = urlparse(resolved).path
        except Exception:
            return None

        # Scoped packages: @scope/name → the path will contain scope%2fname or scope/name
        expected_name = dep.name.lower()
        # Normalise scoped names: @scope/pkg → scope/pkg for path matching
        if expected_name.startswith("@"):
            expected_name = expected_name.lstrip("@")

        path_lower = path.lower()
        # Allow URL-encoded slash for scoped packages
        path_decoded = path_lower.replace("%2f", "/")

        if expected_name not in path_decoded:
            return self._finding(
                dep,
                config,
                f"`{dep.name}` resolved URL `{resolved}` does not contain the "
                f"expected package name `{dep.name}` in its path. "
                f"This is a strong indicator of a lockfile injection attack where "
                f"the tarball URL was replaced to serve a different (malicious) package.",
                actual=f"resolved={resolved[:80]}",
            )

        return None
