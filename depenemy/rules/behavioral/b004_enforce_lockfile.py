"""B004 - Manifest is missing an adjacent lockfile."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from depenemy.config import Config
from depenemy.rules.base import BaseRule
from depenemy.types import Dependency, Finding, PackageMetadata


# Manifest filename -> acceptable adjacent lockfile names.
# Any one of the listed lockfiles satisfies the rule.
LOCKFILES_BY_MANIFEST: dict[str, tuple[str, ...]] = {
    "package.json": (
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
    ),
    "Pipfile": ("Pipfile.lock",),
    "pyproject.toml": ("poetry.lock", "uv.lock", "pdm.lock"),
    "Cargo.toml": ("Cargo.lock",),
}


class B004EnforceLockfile(BaseRule):
    id = "B004"
    name = "Lockfile missing"
    description = (
        "The manifest has no adjacent lockfile. Without a lockfile, every "
        "fresh install re-resolves transitive dependencies, so a malicious "
        "version published after this commit can be picked up silently."
    )

    def _check(
        self,
        dep: Dependency,
        meta: PackageMetadata,
        config: Config,
    ) -> Optional[Finding]:
        # Project-level rule; per-dep check is a no-op.
        return None

    def _check_project(
        self,
        manifest_path: Path,
        deps: list[Dependency],
        config: Config,
    ) -> list[Finding]:
        if not deps:
            return []

        manifest_name = manifest_path.name

        # requirements*.txt acts as its own pin file when fully pinned;
        # treating its absence as a lockfile gap would be wrong.
        if manifest_name.startswith("requirements") and manifest_name.endswith(".txt"):
            return []

        candidates = LOCKFILES_BY_MANIFEST.get(manifest_name)
        if not candidates:
            return []

        for lockfile in candidates:
            if (manifest_path.parent / lockfile).exists():
                return []

        anchor = Dependency(
            name=str(manifest_path),
            version_spec="",
            ecosystem=deps[0].ecosystem,
            location=deps[0].location,
        )
        finding = Finding(
            rule_id=self.id,
            rule_name=self.name,
            severity=config.rule_severity(self.id),
            dependency=anchor,
            message=(
                f"`{manifest_name}` has no adjacent lockfile. Without one, every "
                f"fresh install resolves transitive versions anew - a malicious "
                f"version published after this commit can be picked up silently. "
                f"Expected one of: {', '.join(candidates)}."
            ),
            actual="no lockfile",
            expected=candidates[0],
        )
        return [finding]
