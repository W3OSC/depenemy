"""Fetcher for GitHub metadata: author account age, contributor count, archived status."""

from __future__ import annotations

import json
import re
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
        publisher_name: Optional[str] = None,
    ) -> dict[str, Any]:
        """Return dict with contributor_count, author_account_created_at, is_archived, and new S007/S009 signals."""
        cache_key = f"gh:{ecosystem_key}:{name}"
        cached = self._cache.get(cache_key)
        if cached:
            return cached  # type: ignore[no-any-return]

        result: dict[str, Any] = {
            "contributor_count": 0,
            "author_account_created_at": None,
            "is_archived": False,
            # S007 ghost repo signals
            "repo_commit_count": 0,
            "repo_issue_count": 0,
            "repo_pr_count": 0,
            "repo_has_ci": False,
            "repo_created_at": None,
            # S009 publisher identity
            "publisher_has_github": True,
        }

        if repo_url:
            owner, repo = _parse_github_repo(repo_url)
            if owner and repo:
                repo_data = await self._get_repo(owner, repo)
                if repo_data:
                    result["is_archived"] = repo_data.get("archived", False)
                    result["repo_created_at"] = repo_data.get("created_at")
                    result["contributor_count"] = await self._get_contributor_count(owner, repo)

                    # Ghost repo signals (S007)
                    result["repo_commit_count"] = await self._get_commit_count(owner, repo)
                    result["repo_issue_count"] = await self._get_item_count(owner, repo, "issues")
                    result["repo_pr_count"] = await self._get_item_count(owner, repo, "pulls")
                    result["repo_has_ci"] = await self._has_ci(owner, repo)

                    # Author from repo owner if not known
                    if not author_name:
                        author_name = owner

        if author_name:
            user_data = await self._get_user(author_name)
            if user_data and user_data.get("created_at"):
                result["author_account_created_at"] = user_data["created_at"]

        # Publisher identity check (S009): does the npm publisher have a GitHub account?
        if publisher_name and publisher_name != author_name:
            pub_data = await self._get_user(publisher_name)
            result["publisher_has_github"] = pub_data is not None

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
                return resp.json()  # type: ignore[no-any-return]
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

    async def _get_commit_count(self, owner: str, repo: str) -> int:
        """Return commit count, capped at 3 for ghost-repo detection (avoids expensive full count)."""
        try:
            resp = await self._client.get(
                f"{self.API}/repos/{owner}/{repo}/commits",
                headers=self._headers,
                params={"per_page": 3},
                timeout=10,
            )
            if resp.status_code == 200:
                commits = resp.json()
                if isinstance(commits, list):
                    return len(commits)
        except (httpx.HTTPError, json.JSONDecodeError):
            pass
        return 0

    async def _get_item_count(self, owner: str, repo: str, item_type: str) -> int:
        """Return count of issues or pulls (state=all) by reading Link header for total."""
        try:
            resp = await self._client.get(
                f"{self.API}/repos/{owner}/{repo}/{item_type}",
                headers=self._headers,
                params={"state": "all", "per_page": 1},
                timeout=10,
            )
            if resp.status_code == 200:
                link = resp.headers.get("link", "")
                if 'rel="last"' in link:
                    # Extract page number from last link: ...&page=42>; rel="last"
                    import re
                    m = re.search(r'[?&]page=(\d+)>;\s*rel="last"', link)
                    if m:
                        return int(m.group(1))
                # No pagination — count items in response
                items = resp.json()
                if isinstance(items, list):
                    return len(items)
        except (httpx.HTTPError, json.JSONDecodeError):
            pass
        return 0

    async def _has_ci(self, owner: str, repo: str) -> bool:
        """Check if the repository has any CI configuration files."""
        ci_paths = [
            ".github/workflows",
            ".travis.yml",
            ".circleci/config.yml",
            ".gitlab-ci.yml",
            "Jenkinsfile",
            ".buildkite",
        ]
        for path in ci_paths:
            try:
                resp = await self._client.get(
                    f"{self.API}/repos/{owner}/{repo}/contents/{path}",
                    headers=self._headers,
                    timeout=10,
                )
                if resp.status_code == 200:
                    return True
            except httpx.HTTPError:
                pass
        return False

    async def _get_user(self, username: str) -> Optional[dict[str, Any]]:
        cache_key = f"gh:user:{username}"
        cached = self._cache.get(cache_key)
        if cached:
            return cached  # type: ignore[no-any-return]
        try:
            resp = await self._client.get(
                f"{self.API}/users/{username}",
                headers=self._headers,
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                self._cache.set(cache_key, data)
                return data  # type: ignore[no-any-return]
        except (httpx.HTTPError, json.JSONDecodeError):
            pass
        return None


_GITHUB_REPO_RE = re.compile(r"github\.com[:/]([^/]+)/([^/.\s]+?)(?:\.git)?$")


def _parse_github_repo(url: str) -> tuple[Optional[str], Optional[str]]:
    """Extract (owner, repo) from a GitHub URL."""
    m = _GITHUB_REPO_RE.search(url)
    if m:
        return m.group(1), m.group(2)
    return None, None


