"""Shared pytest fixtures and helpers for depenemy tests."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

try:
    import pytest
except ImportError:
    class _FakePytest:  # type: ignore[no-redef]
        @staticmethod
        def fixture(func=None, **kwargs):
            if func is None:
                return lambda f: f
            return func
    pytest = _FakePytest()  # type: ignore[assignment]

from depenemy.config import Config
from depenemy.parsers.npm import NpmParser
from depenemy.types import Dependency, Ecosystem, Location, PackageMetadata

FIXTURES_NPM = Path(__file__).parent / "fixtures" / "npm"


def make_meta(
    name: str,
    latest_version: str = "9.9.9",
    target_version: Optional[str] = None,
    *,
    is_deprecated: bool = False,
    has_install_scripts: bool = False,
    weekly_downloads: int = 500_000,
    total_downloads: int = 50_000_000,
    maintainer_count: int = 5,
    contributor_count: int = 20,
    license: Optional[str] = "MIT",
    is_archived: bool = False,
    repository_url: Optional[str] = "https://github.com/test/test",
) -> PackageMetadata:
    """Build a PackageMetadata with safe defaults for unit tests."""
    return PackageMetadata(
        name=name,
        ecosystem=Ecosystem.NPM,
        latest_version=latest_version,
        target_version=target_version or latest_version,
        is_deprecated=is_deprecated,
        has_install_scripts=has_install_scripts,
        weekly_downloads=weekly_downloads,
        total_downloads=total_downloads,
        maintainer_count=maintainer_count,
        contributor_count=contributor_count,
        license=license,
        is_archived=is_archived,
        repository_url=repository_url,
    )


def make_dep(
    name: str,
    version_spec: str,
    ecosystem: Ecosystem = Ecosystem.NPM,
    is_dev: bool = False,
    file: str = "package.json",
    line: int = 1,
) -> Dependency:
    """Build a Dependency for use in unit tests."""
    return Dependency(
        name=name,
        version_spec=version_spec,
        ecosystem=ecosystem,
        location=Location(file=file, line=line),
        is_dev=is_dev,
    )


@pytest.fixture
def default_config() -> Config:
    return Config()


@pytest.fixture
def npm_parser() -> NpmParser:
    return NpmParser()
