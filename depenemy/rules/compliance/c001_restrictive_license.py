"""C001 — Package uses a restrictive license (GPL, AGPL, LGPL)."""

from __future__ import annotations

from typing import Optional

from depenemy.config import Config
from depenemy.rules.base import BaseRule
from depenemy.types import Dependency, Finding, PackageMetadata

RESTRICTIVE_LICENSES = {
    "GPL-2.0",
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "GPL-3.0",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "AGPL-3.0",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
    "LGPL-2.0",
    "LGPL-2.1",
    "LGPL-3.0",
    "EUPL-1.1",
    "EUPL-1.2",
    "OSL-3.0",
    "CC-BY-SA-4.0",
    "CC-BY-NC-4.0",
}


class C001RestrictiveLicense(BaseRule):
    id = "C001"
    name = "Restrictive license"
    description = (
        "The package uses a copyleft or restrictive license that may impose "
        "obligations on your project's distribution."
    )

    def _check(
        self,
        dep: Dependency,
        meta: PackageMetadata,
        config: Config,
    ) -> Optional[Finding]:
        if not meta.license:
            return None

        license_upper = meta.license.upper()
        for restrictive in RESTRICTIVE_LICENSES:
            if restrictive.upper() in license_upper:
                return self._finding(
                    dep,
                    config,
                    f"`{dep.name}` is licensed under `{meta.license}` which is copyleft. "
                    f"Using it may require you to open-source your project.",
                    actual=meta.license,
                    expected="permissive license (MIT, Apache-2.0, BSD, ISC)",
                )
        return None
