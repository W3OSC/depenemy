"""Fetcher for GitHub metadata: author account age, contributor count, archived status."""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any, Optional

import httpx

from depenemy.cache import Cache


class GitHubFetcher:
    API = "https://api.github.com"

    def __init__(
        self,
        client: httpx.AsyncClient,
        cache: Cache,
        token: Optional[str] = None,
    ) -> None:
        self._client = client
        self._cache = cache
        self._headers = {"Accept": "application/vnd.github+json"}
        if token:
            self._headers["Authorization"] = f"Bearer {token}"

    async def enrich(
        self,
        name: str,
        repo_url: Optional[str],
        author_name: Optional[str],
        *,
        ecosystem_key: str,
    ) -> dict[str, Any]:
        """Return dict with contributor_count, author_account_created_at, is_archived."""
        cache_key = f"gh:{ecosystem_key}:{name}"
        cached = self._cache.get(cache_key)
        if cached:
            return cached  # type: ignore[return-value]

        result: dict[str, Any] = {
            "contributor_count": 0,
            "author_account_created_at": None,
            "is_archived": False,
        }

        if repo_url:
            owner, repo = _parse_github_repo(repo_url)
            if owner and repo:
                repo_data = await self._get_repo(owner, repo)
                if repo_data:
                    result["is_archived"] = repo_data.get("archived", False)
                    result["contributor_count"] = await self._get_contributor_count(owner, repo)

                    # Author from repo owner if not known
                    if not author_name:
                        author_name = owner

        if author_name:
            user_data = await self._get_user(author_name)
            if user_data and user_data.get("created_at"):
                result["author_account_created_at"] = user_data["created_at"]

        self._cache.set(cache_key, result)
        return result

    async def _get_repo(self, owner: str, repo: str) -> Optional[dict[str, Any]]:
        try:
            resp = await self._client.get(
                f"{self.API}/repos/{owner}/{repo}",
                headers=self._headers,
                timeout=10,
            )
            if resp.status_code == 200:
                return resp.json()  # type: ignore[return-value]
        except (httpx.HTTPError, json.JSONDecodeError):
            pass
        return None

    async def _get_contributor_count(self, owner: str, repo: str) -> int:
        try:
            resp = await self._client.get(
                f"{self.API}/repos/{owner}/{repo}/contributors",
                headers=self._headers,
                params={"per_page": 100, "anon": "false"},
                timeout=10,
            )
            if resp.status_code == 200:
                return len(resp.json())
        except (httpx.HTTPError, json.JSONDecodeError):
            pass
        return 0

    async def _get_user(self, username: str) -> Optional[dict[str, Any]]:
        cache_key = f"gh:user:{username}"
        cached = self._cache.get(cache_key)
        if cached:
            return cached  # type: ignore[return-value]
        try:
            resp = await self._client.get(
                f"{self.API}/users/{username}",
                headers=self._headers,
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                self._cache.set(cache_key, data)
                return data  # type: ignore[return-value]
        except (httpx.HTTPError, json.JSONDecodeError):
            pass
        return None


def _parse_github_repo(url: str) -> tuple[Optional[str], Optional[str]]:
    """Extract (owner, repo) from a GitHub URL."""
    patterns = [
        r"github\.com[:/]([^/]+)/([^/.\s]+?)(?:\.git)?$",
    ]
    for pattern in patterns:
        m = re.search(pattern, url)
        if m:
            return m.group(1), m.group(2)
    return None, None


def parse_github_date(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
