"""Abstract base class for all rules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from depenemy.config import Config
from depenemy.types import Dependency, Finding, PackageMetadata, Severity


def parse_semver(v: str) -> tuple[int, int, int]:
    """Parse a semver string into a (major, minor, patch) tuple. Returns (0,0,0) on failure."""
    try:
        parts = v.strip().lstrip("v").split(".")[:3]
        nums = [int(p.split("-")[0].split("+")[0]) for p in parts]
        while len(nums) < 3:
            nums.append(0)
        return (nums[0], nums[1], nums[2])
    except (ValueError, AttributeError):
        return (0, 0, 0)


class BaseRule(ABC):
    id: str
    name: str
    description: str

    def check(
        self,
        dep: Dependency,
        meta: PackageMetadata,
        config: Config,
    ) -> Optional[Finding]:
        if not config.is_rule_enabled(self.id):
            return None
        return self._check(dep, meta, config)

    @abstractmethod
    def _check(
        self,
        dep: Dependency,
        meta: PackageMetadata,
        config: Config,
    ) -> Optional[Finding]:
        """Perform the actual check. Return Finding or None."""

    def _finding(
        self,
        dep: Dependency,
        config: Config,
        message: str,
        actual: Optional[str] = None,
        expected: Optional[str] = None,
        severity: Optional[Severity] = None,
    ) -> Finding:
        return Finding(
            rule_id=self.id,
            rule_name=self.name,
            severity=severity if severity is not None else config.rule_severity(self.id),
            dependency=dep,
            message=message,
            actual=actual,
            expected=expected,
        )
