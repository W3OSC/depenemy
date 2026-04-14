"""Parser for Solidity projects.

Hardhat and Foundry projects manage their npm/JS tooling via package.json.
Foundry Solidity dependencies are git submodules with no public registry -
there is nothing to scan for them. We delegate entirely to NpmParser.
"""

from __future__ import annotations

from pathlib import Path

from depenemy.parsers.base import BaseParser
from depenemy.parsers.npm import NpmParser
from depenemy.types import Dependency, Ecosystem


class SolidityParser(BaseParser):
    """Detects Solidity projects and delegates to NpmParser for npm deps."""

    ecosystem = Ecosystem.SOLIDITY
    manifest_files = ["foundry.toml"]

    def __init__(self) -> None:
        self._npm_parser = NpmParser()

    def parse(self, path: Path) -> list[Dependency]:
        # foundry.toml remappings are git submodules, not registry packages.
        # Any npm tooling is picked up by find_and_parse via NpmParser.
        return []

    def find_and_parse(self, root: Path) -> list[Dependency]:
        return self._npm_parser.find_and_parse(root)
