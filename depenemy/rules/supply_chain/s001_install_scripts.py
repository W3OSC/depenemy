"""S001 - Package has install scripts (postinstall/preinstall)."""

from __future__ import annotations

from typing import Optional

from depenemy.config import Config
from depenemy.rules.base import BaseRule
from depenemy.types import Dependency, Finding, PackageMetadata


class S001InstallScripts(BaseRule):
    id = "S001"
    name = "Install scripts present"
    description = (
        "The package defines preinstall/postinstall scripts that execute "
        "automatically on install - a common vector for supply chain attacks."
    )

    def _check(
        self,
        dep: Dependency,
        meta: PackageMetadata,
        config: Config,
    ) -> Optional[Finding]:
        if not meta.has_install_scripts:
            return None

        return self._finding(
            dep,
            config,
            f"`{dep.name}` runs code automatically on `npm install`. "
            f"If this package is compromised, the malicious code executes on every developer machine "
            f"and CI server without any prompt or approval. Audit the install script before use.",
            actual="has install scripts",
            expected="no install scripts",
        )
