"""Abstract base class for registry fetchers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional

from depenemy.types import Dependency, Ecosystem, PackageMetadata


def parse_date(value: Optional[str]) -> Optional[datetime]:
    """Parse an ISO-8601 date string, handling both 'Z' and '+00:00' suffixes."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


class BaseFetcher(ABC):
    ecosystem: Ecosystem

    @abstractmethod
    async def fetch(self, dep: Dependency) -> PackageMetadata | None:
        """Fetch metadata for a single dependency. Returns None on failure."""
