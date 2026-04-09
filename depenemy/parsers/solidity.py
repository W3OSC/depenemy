"""Parser for Solidity projects.

Hardhat projects are pure npm - the NpmParser handles them automatically.
Foundry projects declare Solidity dependencies in foundry.toml but install
them via git submodules, not a public registry. We delegate npm detection
to NpmParser and note that foundry.toml deps are out of scope for registry
lookups (no public registry to query).
"""

from __future__ import annotations

import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomllib  # type: ignore[no-redef]
    except ImportError:
        import tomli as tomllib  # type: ignore[no-redef,import-untyped]

from depenemy.parsers.base import BaseParser
from depenemy.parsers.npm import NpmParser
from depenemy.types import Dependency, Ecosystem, Location


class SolidityParser(BaseParser):
    """Detects Solidity projects and delegates to NpmParser for npm deps."""

    ecosystem = Ecosystem.SOLIDITY
    manifest_files = ["foundry.toml"]

    def __init__(self) -> None:
        self._npm_parser = NpmParser()

    def parse(self, path: Path) -> list[Dependency]:
        """Parse foundry.toml and also scan the project root for package.json."""
        deps: list[Dependency] = []

        # Check for adjacent package.json (Hardhat or npm-based tooling)
        pkg_json = path.parent / "package.json"
        if pkg_json.exists():
            deps.extend(self._npm_parser.parse(pkg_json))

        # Parse foundry remappings - informational only, no registry to check
        try:
            with open(path, "rb") as f:
                data = tomllib.load(f)
            remappings = data.get("profile", {}).get("default", {}).get("remappings", [])
            for remap in remappings:
                # Remappings are git submodules, not registry packages - skip
                _ = remap
        except (OSError, tomllib.TOMLDecodeError):
            pass

        return deps

    def find_and_parse(self, root: Path) -> list[Dependency]:
        """For Solidity projects, primarily delegate to NpmParser."""
        return self._npm_parser.find_and_parse(root)
