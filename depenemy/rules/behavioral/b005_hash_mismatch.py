"""B005 - Integrity hash in package-lock.json doesn't match the registry hash."""

from __future__ import annotations

from typing import Optional

from depenemy.config import Config
from depenemy.rules.base import BaseRule
from depenemy.types import Dependency, Finding, PackageMetadata


class B005HashMismatch(BaseRule):
    id = "B005"
    name = "Lockfile integrity mismatch"
    description = (
        "The integrity hash recorded in package-lock.json does not match the hash "
        "published in the npm registry for the same version. "
        "This is a critical indicator of lockfile tampering — a known technique where "
        "an attacker modifies the lockfile to point at a malicious tarball while the "
        "version number remains unchanged."
    )

    def _check(
        self,
        dep: Dependency,
        meta: PackageMetadata,
        config: Config,
    ) -> Optional[Finding]:
        lock_hash = dep.lockfile_integrity
        registry_hash = meta.registry_integrity

        # Need both values to perform a comparison
        if not lock_hash or not registry_hash:
            return None

        # Normalise: strip whitespace, compare
        if lock_hash.strip() == registry_hash.strip():
            return None

        return self._finding(
            dep,
            config,
            f"`{dep.name}@{dep.resolved_version}` has a lockfile integrity hash "
            f"(`{lock_hash[:40]}…`) that differs from the registry hash "
            f"(`{registry_hash[:40]}…`). "
            f"This strongly indicates the tarball was replaced or the lockfile was "
            f"tampered with. Do NOT install until this is resolved.",
            actual=f"lock={lock_hash[:20]}… registry={registry_hash[:20]}…",
        )
