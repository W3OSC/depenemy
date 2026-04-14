"""S002 - Package has no source repository linked."""

from __future__ import annotations

from typing import Optional

from depenemy.config import Config
from depenemy.rules.base import BaseRule
from depenemy.types import Dependency, Finding, PackageMetadata


class S002NoSourceRepo(BaseRule):
    id = "S002"
    name = "No source repository"
    description = (
        "The package has no repository URL in its metadata. "
        "Without a source repo, the code cannot be audited."
    )

    def _check(
        self,
        dep: Dependency,
        meta: PackageMetadata,
        config: Config,
    ) -> Optional[Finding]:
        if meta.repository_url:
            return None

        return self._finding(
            dep,
            config,
            f"`{dep.name}` has no source repository linked in its metadata. "
            f"The code cannot be independently audited.",
            actual="no repository URL",
        )
