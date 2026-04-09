"""S004 — Dependency confusion: private/scoped package found on public registry."""

from __future__ import annotations

from typing import Optional

from depenemy.config import Config
from depenemy.rules.base import BaseRule
from depenemy.types import Dependency, Ecosystem, Finding, PackageMetadata


class S004DependencyConfusion(BaseRule):
    id = "S004"
    name = "Dependency confusion"
    description = (
        "A scoped or internal-looking package name exists on the public registry. "
        "This could indicate a dependency confusion attack."
    )

    _INTERNAL_PATTERNS = [
        "internal",
        "private",
        "local",
        "corp",
        "company",
        "intranet",
    ]

    def _check(
        self,
        dep: Dependency,
        meta: PackageMetadata,
        config: Config,
    ) -> Optional[Finding]:
        name = dep.name.lower()

        # Only flag packages that look internal but exist on public registry
        looks_internal = any(pattern in name for pattern in self._INTERNAL_PATTERNS)

        # For npm: unscoped packages with internal-sounding names are suspicious
        # For scoped packages (@company/pkg), if we resolved metadata → it's on public registry
        is_scoped = dep.ecosystem == Ecosystem.NPM and dep.name.startswith("@")

        if is_scoped:
            # We successfully fetched metadata → this scoped package IS on npm public registry
            # If the name looks like it should be private, that's suspicious
            scope = dep.name.split("/")[0].lstrip("@")
            # Only flag if scope looks like a company name (not well-known OSS orgs)
            known_public_scopes = {
                "babel", "angular", "vue", "nestjs", "types", "jest",
                "testing-library", "storybook", "mui", "emotion", "tanstack",
            }
            if scope not in known_public_scopes and looks_internal:
                return self._finding(
                    dep,
                    config,
                    f"`{dep.name}` is a scoped package that appears to be internal "
                    f"but exists on the public registry — verify this is intentional.",
                    actual=f"public registry: {dep.name}",
                    expected="private registry only",
                )

        elif looks_internal and meta.weekly_downloads < 100:
            return self._finding(
                dep,
                config,
                f"`{dep.name}` has an internal-sounding name and very low downloads "
                f"({meta.weekly_downloads:,}/week) — possible dependency confusion attack.",
                actual=f"{meta.weekly_downloads:,} weekly downloads",
                expected=">= 100 weekly downloads for public packages",
            )

        return None
