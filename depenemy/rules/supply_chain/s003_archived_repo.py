"""S003 - Source repository is archived."""

from __future__ import annotations

from typing import Optional

from depenemy.config import Config
from depenemy.rules.base import BaseRule
from depenemy.types import Dependency, Finding, PackageMetadata


class S003ArchivedRepo(BaseRule):
    id = "S003"
    name = "Archived repository"
    description = (
        "The package's source repository is archived. "
        "Archived repos receive no updates or security fixes."
    )

    def _check(
        self,
        dep: Dependency,
        meta: PackageMetadata,
        config: Config,
    ) -> Optional[Finding]:
        if not meta.is_archived:
            return None

        return self._finding(
            dep,
            config,
            f"`{dep.name}` source repository is archived - "
            f"no further updates or security fixes will be made.",
            actual="archived",
        )
