"""B006 - Package is resolved from a non-approved registry."""

from __future__ import annotations

from typing import Optional
from urllib.parse import urlparse

from depenemy.config import Config
from depenemy.rules.base import BaseRule
from depenemy.types import Dependency, Finding, PackageMetadata


class B006BadRegistry(BaseRule):
    id = "B006"
    name = "Non-approved registry"
    description = (
        "The package is resolved from a registry host that is not on the organisation's "
        "approved registry list. Packages served from unknown or private registries "
        "bypass the security controls of the official npm registry (malware scanning, "
        "2FA enforcement, provenance attestation)."
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
            host = urlparse(resolved).netloc
        except Exception:
            return None

        if not host:
            return None

        approved = config.approved_registries or ["registry.npmjs.org"]
        if any(host == allowed or host.endswith("." + allowed) for allowed in approved):
            return None

        return self._finding(
            dep,
            config,
            f"`{dep.name}` is resolved from `{host}` which is not on the approved "
            f"registry list ({', '.join(approved)}). "
            f"This package bypasses public registry security controls. "
            f"Add the registry to `approved_registries` in your config if intentional.",
            actual=f"registry={host}",
        )
