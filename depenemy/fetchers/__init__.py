"""Registry fetchers."""

from depenemy.fetchers.crates import CratesFetcher
from depenemy.fetchers.github import GitHubFetcher
from depenemy.fetchers.npm import NpmFetcher
from depenemy.fetchers.pypi import PyPIFetcher

__all__ = ["NpmFetcher", "PyPIFetcher", "CratesFetcher", "GitHubFetcher"]
