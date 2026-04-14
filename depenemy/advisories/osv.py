"""Query OSV.dev for known security advisories."""

from __future__ import annotations

import json
from typing import Any

import httpx

from depenemy.cache import Cache
from depenemy.types import Advisory, Ecosystem


_ECOSYSTEM_MAP = {
    Ecosystem.NPM: "npm",
    Ecosystem.PYPI: "PyPI",
    Ecosystem.CARGO: "crates.io",
}

_MALICIOUS_PHRASES = [
    "published with malicious code",
    "embedded malicious code",
    "including malicious code",
    "malicious code was introduced",
    "malicious code was added",
    "malicious code that was introduced",
    "considered malicious",
    "malicious actor added this package",
    "malicious npm package",
    "malicious pypi package",
    "package was compromised",
    "account was compromised",
    "backdoor",
    "supply chain attack on",
]


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

    async def check_malicious(self, name: str, ecosystem: Ecosystem, version: str = "") -> list[Advisory]:
        """Return advisories that describe malicious activity for this package."""
        osv_ecosystem = _ECOSYSTEM_MAP.get(ecosystem)
        if not osv_ecosystem:
            return []

        cache_key = f"osv:mal:{osv_ecosystem}:{name}:{version}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return [Advisory(**a) for a in cached]

        payload: dict[str, Any] = {"package": {"name": name, "ecosystem": osv_ecosystem}}
        if version:
            payload["version"] = version
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

        results = []
        for vuln in data.get("vulns", []):
            text = (
                (vuln.get("summary", "") or "") + " " +
                (vuln.get("details", "") or "")
            ).lower()
            if any(phrase in text for phrase in _MALICIOUS_PHRASES):
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
        self._cache.set(cache_key, serializable)
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
