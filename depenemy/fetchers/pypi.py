"""Fetcher for PyPI registry."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Optional

import httpx

from depenemy.cache import Cache
from depenemy.fetchers.base import BaseFetcher
from depenemy.types import Dependency, Ecosystem, PackageMetadata


class PyPIFetcher(BaseFetcher):
    ecosystem = Ecosystem.PYPI

    API = "https://pypi.org/pypi"

    def __init__(self, client: httpx.AsyncClient, cache: Cache) -> None:
        self._client = client
        self._cache = cache

    async def fetch(self, dep: Dependency) -> Optional[PackageMetadata]:
        cache_key = f"pypi:{dep.name}"
        cached = self._cache.get(cache_key)
        if cached:
            return _from_cache(cached, dep)

        try:
            resp = await self._client.get(f"{self.API}/{dep.name}/json", timeout=10)
            if resp.status_code != 200:
                return None
            data = resp.json()
        except (httpx.HTTPError, json.JSONDecodeError):
            return None

        info: dict[str, Any] = data.get("info", {})
        latest = info.get("version", "")
        target = dep.resolved_version or dep.version_spec.lstrip("^~>=<! ").split(",")[0] or latest

        # Package creation date = earliest release ever published
        releases: dict[str, list[dict[str, Any]]] = data.get("releases", {})
        all_dates = [
            d for files in releases.values()
            for d in [_earliest_upload(files)] if d
        ]
        published_at = min(all_dates) if all_dates else None

        # Latest version publish date
        latest_files = releases.get(latest, [])
        last_published_at = _earliest_upload(latest_files)

        # Downloads (PyPI doesn't provide total downloads in the JSON API -
        # BigQuery is needed for that; we use 0 as placeholder)
        weekly_downloads = 0
        total_downloads = 0

        # License
        license_val = info.get("license", "") or ""

        # Repository URL - PyPI packages use inconsistent key names,
        # so scan all project_urls for a GitHub/GitLab URL first
        project_urls: dict[str, str] = info.get("project_urls") or {}
        repo_url = _find_repo_url(project_urls, info.get("home_page"))

        # Deprecated: PyPI uses yanked releases
        is_deprecated = info.get("yanked", False)
        deprecation_message = info.get("yanked_reason", "") or ""

        # Maintainers - PyPI JSON API exposes author field only
        author_name = info.get("author", "")
        maintainer_count = 1 if author_name else 0

        serializable = {
            "latest": latest,
            "target": target,
            "published_at": published_at.isoformat() if published_at else None,
            "last_published_at": last_published_at.isoformat() if last_published_at else None,
            "weekly_downloads": weekly_downloads,
            "total_downloads": total_downloads,
            "is_deprecated": is_deprecated,
            "deprecation_message": deprecation_message,
            "has_install_scripts": False,  # handled by setup.py but not exposed in API
            "license": license_val,
            "repo_url": repo_url,
            "maintainer_count": maintainer_count,
            "author_name": author_name,
        }
        self._cache.set(cache_key, serializable)

        return PackageMetadata(
            name=dep.name,
            ecosystem=Ecosystem.PYPI,
            latest_version=latest,
            target_version=target,
            published_at=published_at,
            last_published_at=last_published_at,
            weekly_downloads=weekly_downloads,
            total_downloads=total_downloads,
            maintainer_count=maintainer_count,
            author_name=author_name or None,
            repository_url=repo_url or None,
            is_deprecated=is_deprecated,
            deprecation_message=deprecation_message,
            license=license_val or None,
        )


_REPO_HOSTS = ("github.com", "gitlab.com", "bitbucket.org")
_PREFERRED_KEYS = ("Source", "Source Code", "Source code", "Repository", "Code", "GitHub", "GitLab")


def _find_repo_url(project_urls: dict[str, str], home_page: Optional[str]) -> Optional[str]:
    """Find a source repository URL from PyPI project_urls, trying preferred keys first,
    then falling back to any URL that points to a known code hosting service."""
    for key in _PREFERRED_KEYS:
        url = project_urls.get(key)
        if url and any(h in url for h in _REPO_HOSTS):
            return url
    # Scan all values for a repo host URL
    for url in project_urls.values():
        if url and any(h in url for h in _REPO_HOSTS):
            return url
    # Last resort: home_page if it points to a repo host
    if home_page and any(h in home_page for h in _REPO_HOSTS):
        return home_page
    return None


def _earliest_upload(files: list[dict[str, Any]]) -> Optional[datetime]:
    dates = []
    for f in files:
        upload_time = f.get("upload_time_iso_8601") or f.get("upload_time")
        if upload_time:
            try:
                dates.append(datetime.fromisoformat(upload_time.replace("Z", "+00:00")))
            except ValueError:
                pass
    return min(dates) if dates else None


def _from_cache(data: dict[str, Any], dep: Dependency) -> PackageMetadata:
    def _parse(v: Optional[str]) -> Optional[datetime]:
        if not v:
            return None
        try:
            return datetime.fromisoformat(v)
        except ValueError:
            return None

    return PackageMetadata(
        name=dep.name,
        ecosystem=Ecosystem.PYPI,
        latest_version=data["latest"],
        target_version=data["target"],
        published_at=_parse(data.get("published_at")),
        last_published_at=_parse(data.get("last_published_at")),
        weekly_downloads=data.get("weekly_downloads", 0),
        total_downloads=data.get("total_downloads", 0),
        maintainer_count=data.get("maintainer_count", 0),
        author_name=data.get("author_name") or None,
        repository_url=data.get("repo_url") or None,
        is_deprecated=data.get("is_deprecated", False),
        deprecation_message=data.get("deprecation_message", ""),
        license=data.get("license") or None,
    )
