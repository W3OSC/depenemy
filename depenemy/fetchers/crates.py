"""Fetcher for crates.io (Rust ecosystem)."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Optional

import httpx

from depenemy import __version__
from depenemy.cache import Cache
from depenemy.fetchers.base import BaseFetcher
from depenemy.types import Dependency, Ecosystem, PackageMetadata


class CratesFetcher(BaseFetcher):
    ecosystem = Ecosystem.CARGO

    API = "https://crates.io/api/v1"
    HEADERS = {"User-Agent": f"depenemy/{__version__} (https://github.com/W3OSC/depenemy)"}

    def __init__(self, client: httpx.AsyncClient, cache: Cache) -> None:
        self._client = client
        self._cache = cache

    async def fetch(self, dep: Dependency) -> Optional[PackageMetadata]:
        cache_key = f"cargo:{dep.name}"
        cached = self._cache.get(cache_key)
        if cached:
            return _from_cache(cached, dep)

        try:
            resp = await self._client.get(
                f"{self.API}/crates/{dep.name}",
                headers=self.HEADERS,
                timeout=10,
            )
            if resp.status_code != 200:
                return None
            data = resp.json()
        except (httpx.HTTPError, json.JSONDecodeError):
            return None

        crate: dict[str, Any] = data.get("crate", {})
        latest = crate.get("newest_version", "")
        target = dep.resolved_version or dep.version_spec.lstrip("^~>=<! ").split(",")[0] or latest

        weekly_downloads = crate.get("recent_downloads", 0) or 0
        total_downloads = crate.get("downloads", 0) or 0
        repo_url = crate.get("repository") or None
        last_published_at = _parse_date(crate.get("updated_at"))

        # Find target version publish date
        versions_data = data.get("versions", [])
        published_at: Optional[datetime] = None
        for v in versions_data:
            if v.get("num") == target:
                published_at = _parse_date(v.get("created_at"))
                break

        serializable = {
            "latest": latest,
            "target": target,
            "published_at": published_at.isoformat() if published_at else None,
            "last_published_at": last_published_at.isoformat() if last_published_at else None,
            "weekly_downloads": weekly_downloads,
            "total_downloads": total_downloads,
            "repo_url": repo_url,
        }
        self._cache.set(cache_key, serializable)

        return PackageMetadata(
            name=dep.name,
            ecosystem=Ecosystem.CARGO,
            latest_version=latest,
            target_version=target,
            published_at=published_at,
            last_published_at=last_published_at,
            weekly_downloads=weekly_downloads,
            total_downloads=total_downloads,
            repository_url=repo_url,
        )


def _parse_date(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


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
        ecosystem=Ecosystem.CARGO,
        latest_version=data["latest"],
        target_version=data["target"],
        published_at=_parse(data.get("published_at")),
        last_published_at=_parse(data.get("last_published_at")),
        weekly_downloads=data.get("weekly_downloads", 0),
        total_downloads=data.get("total_downloads", 0),
        repository_url=data.get("repo_url"),
    )
