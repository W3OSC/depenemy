"""S006 - Package was published without Sigstore provenance attestation."""

from __future__ import annotations

from typing import Optional

from depenemy.config import Config
from depenemy.rules.base import BaseRule
from depenemy.types import Dependency, Finding, PackageMetadata


class S006MissingProvenance(BaseRule):
    id = "S006"
    name = "Missing provenance attestation"
    description = (
        "The package was not published with Sigstore OIDC provenance. "
        "Provenance links each published tarball to a specific source commit and CI run, "
        "making it extremely hard for a compromised publisher account to silently inject "
        "malicious code. Absence of provenance is a weak signal on its own but is a "
        "required component of the composite supply-chain risk score (C001)."
    )

    def _check(
        self,
        dep: Dependency,
        meta: PackageMetadata,
        config: Config,
    ) -> Optional[Finding]:
        if meta.has_provenance is None:
            # The fetcher for this ecosystem doesn't probe provenance yet
            # (e.g. PyPI PEP 740 support is unimplemented). Treat as unknown,
            # not absent - firing would be a blanket false positive.
            return None
        if meta.has_provenance:
            return None

        return self._finding(
            dep,
            config,
            f"`{dep.name}` has no Sigstore provenance attestation. "
            f"There is no verifiable link between the published tarball and a specific "
            f"source commit or CI pipeline. Consider packages with provenance for "
            f"security-sensitive roles.",
            actual="no provenance",
        )
