"""Abstract base class for all ecosystem parsers."""

from __future__ import annotations

import warnings
from abc import ABC, abstractmethod
from pathlib import Path

from depenemy.types import Dependency, Ecosystem


class BaseParser(ABC):
    ecosystem: Ecosystem
    manifest_files: list[str]   # filenames this parser handles (e.g. ["package.json"])

    @abstractmethod
    def parse(self, path: Path) -> list[Dependency]:
        """Parse a single manifest/lockfile and return Dependency list."""

    def find_and_parse(self, root: Path) -> list[Dependency]:
        """Recursively find all matching manifests under root and parse them."""
        results: list[Dependency] = []
        for pattern in self.manifest_files:
            for manifest in root.rglob(pattern):
                if any(part.startswith(".") for part in manifest.parts):
                    continue
                if "node_modules" in manifest.parts:
                    continue
                if ".venv" in manifest.parts or "venv" in manifest.parts:
                    continue
                try:
                    results.extend(self.parse(manifest))
                except Exception as exc:
                    warnings.warn(f"Failed to parse {manifest}: {exc}", RuntimeWarning, stacklevel=2)
        return results
