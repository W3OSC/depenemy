"""Shared test fixtures."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from depenemy.config import Config, Thresholds
from depenemy.types import Dependency, Ecosystem, Location, PackageMetadata


@pytest.fixture
def config() -> Config:
    return Config()


@pytest.fixture
def npm_dep() -> Dependency:
    return Dependency(
        name="lodash",
        version_spec="^4.17.21",
        ecosystem=Ecosystem.NPM,
        location=Location(file="package.json", line=5, column=3),
        resolved_version="4.17.21",
    )


@pytest.fixture
def pypi_dep() -> Dependency:
    return Dependency(
        name="requests",
        version_spec=">=2.0",
        ecosystem=Ecosystem.PYPI,
        location=Location(file="requirements.txt", line=1, column=1),
        resolved_version="2.31.0",
    )


def make_meta(
    name: str = "test-pkg",
    ecosystem: Ecosystem = Ecosystem.NPM,
    latest: str = "2.0.0",
    target: str = "2.0.0",
    weekly_dl: int = 50000,
    total_dl: int = 500000,
    published_days_ago: int = 365,
    last_published_days_ago: int = 30,
    author_age_days: int = 500,
    contributors: int = 10,
    maintainers: int = 2,
    repo_url: str = "https://github.com/example/test-pkg",
    deprecated: bool = False,
    install_scripts: bool = False,
    archived: bool = False,
    license: str = "MIT",
) -> PackageMetadata:
    now = datetime.now(timezone.utc)
    return PackageMetadata(
        name=name,
        ecosystem=ecosystem,
        latest_version=latest,
        target_version=target,
        published_at=datetime.fromtimestamp(
            now.timestamp() - published_days_ago * 86400, tz=timezone.utc
        ),
        last_published_at=datetime.fromtimestamp(
            now.timestamp() - last_published_days_ago * 86400, tz=timezone.utc
        ),
        weekly_downloads=weekly_dl,
        total_downloads=total_dl,
        author_account_created_at=datetime.fromtimestamp(
            now.timestamp() - author_age_days * 86400, tz=timezone.utc
        ),
        contributor_count=contributors,
        maintainer_count=maintainers,
        repository_url=repo_url,
        is_deprecated=deprecated,
        has_install_scripts=install_scripts,
        is_archived=archived,
        license=license,
    )
