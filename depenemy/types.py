"""Core data types shared across all depenemy modules."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class Ecosystem(str, Enum):
    NPM = "npm"
    PYPI = "pypi"
    CARGO = "cargo"
    SOLIDITY = "solidity"


class Severity(str, Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"

    def __ge__(self, other: object) -> bool:
        order: list[Severity] = [Severity.INFO, Severity.WARNING, Severity.ERROR]
        if not isinstance(other, Severity):
            return NotImplemented
        return order.index(self) >= order.index(other)

    def __gt__(self, other: object) -> bool:
        order: list[Severity] = [Severity.INFO, Severity.WARNING, Severity.ERROR]
        if not isinstance(other, Severity):
            return NotImplemented
        return order.index(self) > order.index(other)


@dataclass
class Location:
    file: str
    line: int
    column: int = 1


@dataclass
class Dependency:
    name: str
    version_spec: str          # Raw spec from manifest: "^1.2.3", ">=2.0", "*"
    ecosystem: Ecosystem
    location: Location
    resolved_version: Optional[str] = None   # From lockfile if available
    is_dev: bool = False
    lockfile_integrity: Optional[str] = None  # _integrity from package-lock.json (B005)
    lockfile_resolved: Optional[str] = None   # resolved URL from package-lock.json (B006/B007)


@dataclass
class Advisory:
    id: str                    # e.g. GHSA-xxxx or CVE-xxxx
    severity: str              # critical | high | moderate | low
    affected_range: str        # e.g. "<3.2.1"
    patched_version: str       # e.g. "3.2.1"
    description: str = ""
    source: str = "osv"


@dataclass
class PackageMetadata:
    name: str
    ecosystem: Ecosystem
    latest_version: str
    target_version: str        # The version actually being analysed
    published_at: Optional[datetime] = None        # When target_version was published
    last_published_at: Optional[datetime] = None   # When latest_version was published
    weekly_downloads: int = 0
    total_downloads: int = 0
    author_name: Optional[str] = None
    author_account_created_at: Optional[datetime] = None
    contributor_count: int = 0
    maintainer_count: int = 0
    repository_url: Optional[str] = None
    is_deprecated: bool = False
    deprecation_message: str = ""
    has_install_scripts: bool = False
    license: Optional[str] = None
    is_archived: bool = False
    advisories: list[Advisory] = field(default_factory=list)
    malicious_advisories: list[Advisory] = field(default_factory=list)
    # Versions OSV records as security fixes for this package (any `fixed` event
    # across all advisories). Used by R010 to bypass the cooldown when the user
    # has landed on a known fix, even if it was published recently.
    security_fix_versions: set[str] = field(default_factory=set)
    # Provenance (S006). None = fetcher did not check this ecosystem yet; False
    # = checked and absent; True = checked and present. S006 fires only on False.
    has_provenance: Optional[bool] = None
    registry_integrity: Optional[str] = None       # dist.integrity from registry (B005)
    # Publisher identity (S009)
    publisher_name: Optional[str] = None            # npm account that published target_version
    publisher_has_github: bool = True               # False if publisher has no GitHub account
    # Behavioral signals - GitHub repo (S007)
    repo_commit_count: int = 0
    repo_issue_count: int = 0
    repo_pr_count: int = 0
    repo_has_ci: bool = False
    repo_created_at: Optional[datetime] = None
    # Behavioral signals - author activity (S008)
    author_package_burst_count: int = 0             # packages published in bulk_publish_window_hours window


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    severity: Severity
    dependency: Dependency
    message: str
    actual: Optional[str] = None
    expected: Optional[str] = None


@dataclass
class ScanResult:
    dependencies: list[Dependency]
    findings: list[Finding]
    scanned_files: list[str]

    @property
    def errors(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.ERROR]

    @property
    def warnings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.WARNING]

    @property
    def infos(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.INFO]
