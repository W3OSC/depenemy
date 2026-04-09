"""Abstract base class for registry fetchers."""

from __future__ import annotations

from abc import ABC, abstractmethod

from depenemy.types import Dependency, Ecosystem, PackageMetadata


class BaseFetcher(ABC):
    ecosystem: Ecosystem

    @abstractmethod
    async def fetch(self, dep: Dependency) -> PackageMetadata | None:
        """Fetch metadata for a single dependency. Returns None on failure."""
