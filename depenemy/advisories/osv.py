"""Query OSV.dev for known security advisories."""

from __future__ import annotations

import json
from typing import Any, Optional

import httpx

from depenemy.cache import Cache
from depenemy.types import Advisory, Ecosystem


_ECOSYSTEM_MAP = {
    Ecosystem.NPM: "npm",
    Ecosystem.PYPI: "PyPI",
    Ecosystem.CARGO: "crates.io",
}


class OSVAdvisor:
    API = "https://api.osv.dev/v1"

    def __init__(self, client: httpx.AsyncClient, cache: Cache) -> None:
        self._client = client
        self._cache = cache

    async def get_advisories(
        self,
        name: str,
        version: str,
        ecosystem: Ecosystem,
    ) -> list[Advisory]:
        osv_ecosystem = _ECOSYSTEM_MAP.get(ecosystem)
        if not osv_ecosystem:
            return []

        cache_key = f"osv:{osv_ecosystem}:{name}:{version}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return [Advisory(**a) for a in cached]

        payload = {
            "version": version,
            "package": {"name": name, "ecosystem": osv_ecosystem},
        }

        try:
            resp = await self._client.post(
                f"{self.API}/query",
                json=payload,
                timeout=10,
            )
            if resp.status_code != 200:
                return []
            data = resp.json()
        except (httpx.HTTPError, json.JSONDecodeError):
            return []

        advisories = _parse_osv_response(data)
        self._cache.set(cache_key, [
            {"id": a.id, "severity": a.severity, "affected_range": a.affected_range,
             "patched_version": a.patched_version, "description": a.description, "source": a.source}
            for a in advisories
        ])
        return advisories

    async def get_patched_version(
        self,
        name: str,
        ecosystem: Ecosystem,
    ) -> Optional[str]:
        """Return the minimum patched version across all advisories for a package."""
        osv_ecosystem = _ECOSYSTEM_MAP.get(ecosystem)
        if not osv_ecosystem:
            return None

        cache_key = f"osv:pkg:{osv_ecosystem}:{name}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached.get("patched")

        payload = {"package": {"name": name, "ecosystem": osv_ecosystem}}
        try:
            resp = await self._client.post(
                f"{self.API}/query",
                json=payload,
                timeout=10,
            )
            if resp.status_code != 200:
                return None
            data = resp.json()
        except (httpx.HTTPError, json.JSONDecodeError):
            return None

        advisories = _parse_osv_response(data)
        if not advisories:
            self._cache.set(cache_key, {"patched": None})
            return None

        # Find the highest patched version
        patched_versions = [a.patched_version for a in advisories if a.patched_version]
        result = patched_versions[-1] if patched_versions else None
        self._cache.set(cache_key, {"patched": result})
        return result


_MALICIOUS_KEYWORDS = frozenset([
    "malicious", "backdoor", "supply chain attack", "typosquat",
    "compromised", "hijack", "exfiltrat", "credential steal",
])


class MaliciousAdvisoryChecker:
    """Checks if a package has any history of malicious activity in OSV."""

    def __init__(self, advisor: "OSVAdvisor") -> None:
        self._advisor = advisor

    async def check(self, name: str, ecosystem: Ecosystem) -> list[Advisory]:
        osv_ecosystem = _ECOSYSTEM_MAP.get(ecosystem)
        if not osv_ecosystem:
            return []

        cache_key = f"osv:mal:{osv_ecosystem}:{name}"
        cached = self._advisor._cache.get(cache_key)
        if cached is not None:
            return [Advisory(**a) for a in cached]

        payload = {"package": {"name": name, "ecosystem": osv_ecosystem}}
        try:
            resp = await self._advisor._client.post(
                f"{self._advisor.API}/query",
                json=payload,
                timeout=10,
            )
            if resp.status_code != 200:
                return []
            data = resp.json()
        except (httpx.HTTPError, json.JSONDecodeError):
            return []

        results = []
        for vuln in data.get("vulns", []):
            text = (
                (vuln.get("summary", "") or "") + " " +
                (vuln.get("details", "") or "")
            ).lower()
            if any(kw in text for kw in _MALICIOUS_KEYWORDS):
                results.append(Advisory(
                    id=vuln.get("id", ""),
                    severity="critical",
                    affected_range="",
                    patched_version="",
                    description=(vuln.get("summary", "") or vuln.get("details", ""))[:300],
                    source="osv",
                ))

        serializable = [
            {"id": a.id, "severity": a.severity, "affected_range": a.affected_range,
             "patched_version": a.patched_version, "description": a.description, "source": a.source}
            for a in results
        ]
        self._advisor._cache.set(cache_key, serializable)
        return results


def _parse_osv_response(data: dict[str, Any]) -> list[Advisory]:
    advisories = []
    for vuln in data.get("vulns", []):
        vuln_id = vuln.get("id", "")
        severity = _extract_severity(vuln)
        affected_range, patched = _extract_range_and_patch(vuln)
        summary = vuln.get("summary", "") or vuln.get("details", "")[:200]

        if patched:
            advisories.append(Advisory(
                id=vuln_id,
                severity=severity,
                affected_range=affected_range,
                patched_version=patched,
                description=summary,
                source="osv",
            ))
    return advisories


def _extract_severity(vuln: dict[str, Any]) -> str:
    severities = vuln.get("severity", [])
    for s in severities:
        score = s.get("score", "")
        if "CRITICAL" in score:
            return "critical"
        if "HIGH" in score:
            return "high"
        if "MEDIUM" in score or "MODERATE" in score:
            return "moderate"
    return "low"


def _extract_range_and_patch(vuln: dict[str, Any]) -> tuple[str, str]:
    for affected in vuln.get("affected", []):
        for r in affected.get("ranges", []):
            if r.get("type") != "SEMVER":
                continue
            introduced = ""
            fixed = ""
            for event in r.get("events", []):
                if "introduced" in event:
                    introduced = event["introduced"]
                if "fixed" in event:
                    fixed = event["fixed"]
            if fixed:
                affected_range = f">={introduced},<{fixed}" if introduced else f"<{fixed}"
                return affected_range, fixed
    return "", ""
