"""Abstract base class for all rules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from depenemy.config import Config
from depenemy.types import Dependency, Finding, PackageMetadata, Severity


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
    ) -> Finding:
        return Finding(
            rule_id=self.id,
            rule_name=self.name,
            severity=config.rule_severity(self.id),
            dependency=dep,
            message=message,
            actual=actual,
            expected=expected,
        )
