"""Main scanner orchestrator."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import anyio
import httpx

from depenemy.advisories.osv import MaliciousAdvisoryChecker, OSVAdvisor
from depenemy.cache import Cache
from depenemy.config import Config
from depenemy.fetchers.crates import CratesFetcher
from depenemy.fetchers.github import GitHubFetcher, parse_github_date
from depenemy.fetchers.npm import NpmFetcher
from depenemy.fetchers.pypi import PyPIFetcher
from depenemy.parsers.npm import NpmParser
from depenemy.parsers.python import PythonParser
from depenemy.parsers.rust import RustParser
from depenemy.rules import ALL_RULES
from depenemy.types import Dependency, Ecosystem, Finding, PackageMetadata, ScanResult

_CONCURRENCY = 10  # max parallel registry requests


async def scan(paths: list[Path], config: Config) -> ScanResult:
    """Full scan pipeline: parse → fetch → evaluate → return results."""

    # 1. Parse all manifests
    all_deps: list[Dependency] = []
    scanned_files: list[str] = []

    parsers = _get_parsers(config)
    for parser in parsers:
        for root in paths:
            found = parser.find_and_parse(root)
            all_deps.extend(found)
            scanned_files.extend({d.location.file for d in found})

    scanned_files = sorted(set(scanned_files))

    # Filter ignored packages
    deps = [
        d for d in all_deps
        if not config.is_ignored(d.name, d.ecosystem)
    ]

    if not deps:
        return ScanResult(dependencies=[], findings=[], scanned_files=scanned_files)

    # 2. Deduplicate by (name, ecosystem, resolved_version)
    seen: set[tuple[str, str]] = set()
    unique_deps: list[Dependency] = []
    for dep in deps:
        key = (dep.name, dep.ecosystem.value)
        if key not in seen:
            seen.add(key)
            unique_deps.append(dep)

    # 3. Fetch metadata
    token = config.github_token or os.environ.get("GITHUB_TOKEN")
    cache = Cache(config.cache_dir, disabled=config.no_cache)

    async with httpx.AsyncClient(follow_redirects=True) as client:
        npm_fetcher = NpmFetcher(client, cache)
        pypi_fetcher = PyPIFetcher(client, cache)
        crates_fetcher = CratesFetcher(client, cache)
        github_fetcher = GitHubFetcher(client, cache, token=token)
        osv_advisor = OSVAdvisor(client, cache)
        malicious_checker = MaliciousAdvisoryChecker(osv_advisor)

        metadata_map: dict[tuple[str, str], PackageMetadata] = {}

        limiter = anyio.CapacityLimiter(_CONCURRENCY)

        async def fetch_one(dep: Dependency) -> None:
            async with limiter:
                meta: Optional[PackageMetadata] = None

                if dep.ecosystem == Ecosystem.NPM:
                    meta = await npm_fetcher.fetch(dep)
                elif dep.ecosystem == Ecosystem.PYPI:
                    meta = await pypi_fetcher.fetch(dep)
                elif dep.ecosystem == Ecosystem.CARGO:
                    meta = await crates_fetcher.fetch(dep)

                if meta is None:
                    return

                # Enrich with GitHub data
                gh_data = await github_fetcher.enrich(
                    dep.name,
                    meta.repository_url,
                    meta.author_name,
                    ecosystem_key=dep.ecosystem.value,
                )
                meta.contributor_count = gh_data.get("contributor_count", 0)
                meta.is_archived = gh_data.get("is_archived", False)
                if gh_data.get("author_account_created_at"):
                    meta.author_account_created_at = parse_github_date(
                        gh_data["author_account_created_at"]
                    )

                # Fetch security advisories
                target = meta.target_version
                if target:
                    meta.advisories = await osv_advisor.get_advisories(
                        dep.name, target, dep.ecosystem
                    )

                # Check for malicious activity history
                meta.malicious_advisories = await malicious_checker.check(
                    dep.name, dep.ecosystem
                )

                metadata_map[(dep.name, dep.ecosystem.value)] = meta

        async with anyio.create_task_group() as tg:
            for dep in unique_deps:
                tg.start_soon(fetch_one, dep)

    # 4. Run rules against every dep, deduplicate by (package, rule_id)
    findings: list[Finding] = []
    seen_findings: set[tuple[str, str, str]] = set()
    for dep in deps:
        meta = metadata_map.get((dep.name, dep.ecosystem.value))
        if meta is None:
            continue
        for rule in ALL_RULES:
            finding = rule.check(dep, meta, config)
            if finding:
                key = (dep.name, dep.ecosystem.value, rule.id)
                if key not in seen_findings:
                    seen_findings.add(key)
                    findings.append(finding)

    return ScanResult(
        dependencies=unique_deps,
        findings=findings,
        scanned_files=scanned_files,
    )


def _get_parsers(config: Config) -> list:
    ecosystems = config.ecosystems
    all_parsers = [NpmParser(), PythonParser(), RustParser()]
    if not ecosystems:
        return all_parsers
    return [p for p in all_parsers if p.ecosystem in ecosystems]
