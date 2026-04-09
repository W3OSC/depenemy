"""Fetcher for npm registry."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

from depenemy.cache import Cache
from depenemy.fetchers.base import BaseFetcher
from depenemy.types import Dependency, Ecosystem, PackageMetadata


class NpmFetcher(BaseFetcher):
    ecosystem = Ecosystem.NPM

    REGISTRY = "https://registry.npmjs.org"
    DOWNLOADS_API = "https://api.npmjs.org/downloads/point"

    def __init__(self, client: httpx.AsyncClient, cache: Cache) -> None:
        self._client = client
        self._cache = cache

    async def fetch(self, dep: Dependency) -> Optional[PackageMetadata]:
        cache_key = f"npm:{dep.name}"
        cached = self._cache.get(cache_key)
        if cached:
            return _from_cache(cached, dep)

        try:
            resp = await self._client.get(f"{self.REGISTRY}/{dep.name}", timeout=10)
            if resp.status_code != 200:
                return None
            data = resp.json()
        except (httpx.HTTPError, json.JSONDecodeError):
            return None

        target = dep.resolved_version or dep.version_spec.lstrip("^~>=<! ")
        latest = data.get("dist-tags", {}).get("latest", "")

        versions: dict[str, Any] = data.get("versions", {})
        target_info = versions.get(target, versions.get(latest, {}))

        # Download stats
        weekly, total = await self._fetch_downloads(dep.name)

        # Deprecated flag
        deprecated_msg = target_info.get("deprecated", "")
        is_deprecated = bool(deprecated_msg)

        # Install scripts
        scripts = target_info.get("scripts", {})
        has_install_scripts = any(
            k in scripts for k in ("preinstall", "install", "postinstall")
        )

        # License
        license_val = target_info.get("license", "")
        if isinstance(license_val, dict):
            license_val = license_val.get("type", "")

        # Repository URL
        repo = target_info.get("repository", {})
        repo_url: Optional[str] = None
        if isinstance(repo, dict):
            repo_url = repo.get("url", "").replace("git+", "").replace(".git", "")
        elif isinstance(repo, str):
            repo_url = repo

        # Publish dates
        times = data.get("time", {})
        published_at = _parse_date(times.get(target))
        last_published_at = _parse_date(times.get(latest))

        # Maintainers
        maintainers = data.get("maintainers", [])
        maintainer_count = len(maintainers)

        serializable = {
            "latest": latest,
            "target": target,
            "published_at": published_at.isoformat() if published_at else None,
            "last_published_at": last_published_at.isoformat() if last_published_at else None,
            "weekly_downloads": weekly,
            "total_downloads": total,
            "is_deprecated": is_deprecated,
            "deprecation_message": str(deprecated_msg) if is_deprecated else "",
            "has_install_scripts": has_install_scripts,
            "license": license_val,
            "repo_url": repo_url,
            "maintainer_count": maintainer_count,
            "maintainers": [m.get("name", "") for m in maintainers if isinstance(m, dict)],
        }
        self._cache.set(cache_key, serializable)

        return PackageMetadata(
            name=dep.name,
            ecosystem=Ecosystem.NPM,
            latest_version=latest,
            target_version=target,
            published_at=published_at,
            last_published_at=last_published_at,
            weekly_downloads=weekly,
            total_downloads=total,
            maintainer_count=maintainer_count,
            repository_url=repo_url,
            is_deprecated=is_deprecated,
            deprecation_message=str(deprecated_msg) if is_deprecated else "",
            has_install_scripts=has_install_scripts,
            license=license_val or None,
        )

    async def _fetch_downloads(self, name: str) -> tuple[int, int]:
        cache_key = f"npm:dl:{name}"
        cached = self._cache.get(cache_key)
        if cached:
            return cached["weekly"], cached["total"]

        try:
            weekly_resp, total_resp = await _parallel_get(
                self._client,
                f"{self.DOWNLOADS_API}/last-week/{name}",
                f"{self.DOWNLOADS_API}/2010-01-01:2099-12-31/{name}",
            )
            weekly = weekly_resp.get("downloads", 0) if weekly_resp else 0
            total = total_resp.get("downloads", 0) if total_resp else 0
        except httpx.HTTPError:
            weekly, total = 0, 0

        self._cache.set(cache_key, {"weekly": weekly, "total": total})
        return weekly, total


async def _parallel_get(
    client: httpx.AsyncClient, *urls: str
) -> list[Optional[dict[str, Any]]]:
    import anyio

    results: list[Optional[dict[str, Any]]] = [None] * len(urls)

    async def fetch_one(i: int, url: str) -> None:
        try:
            resp = await client.get(url, timeout=10)
            if resp.status_code == 200:
                results[i] = resp.json()
        except (httpx.HTTPError, json.JSONDecodeError):
            pass

    async with anyio.create_task_group() as tg:
        for i, url in enumerate(urls):
            tg.start_soon(fetch_one, i, url)

    return results


def _parse_date(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _from_cache(data: dict[str, Any], dep: Dependency) -> PackageMetadata:
    return PackageMetadata(
        name=dep.name,
        ecosystem=Ecosystem.NPM,
        latest_version=data["latest"],
        target_version=data["target"],
        published_at=_parse_date(data.get("published_at")),
        last_published_at=_parse_date(data.get("last_published_at")),
        weekly_downloads=data.get("weekly_downloads", 0),
        total_downloads=data.get("total_downloads", 0),
        maintainer_count=data.get("maintainer_count", 0),
        repository_url=data.get("repo_url"),
        is_deprecated=data.get("is_deprecated", False),
        deprecation_message=data.get("deprecation_message", ""),
        has_install_scripts=data.get("has_install_scripts", False),
        license=data.get("license") or None,
    )
