"""Main scanner orchestrator."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import anyio
import httpx

from depenemy.advisories.osv import OSVAdvisor
from depenemy.cache import Cache
from depenemy.config import Config
from depenemy.fetchers.base import parse_date
from depenemy.fetchers.crates import CratesFetcher
from depenemy.fetchers.github import GitHubFetcher
from depenemy.fetchers.npm import NpmFetcher
from depenemy.fetchers.pypi import PyPIFetcher
from depenemy.parsers.base import BaseParser
from depenemy.parsers.npm import NpmParser
from depenemy.parsers.python import PythonParser
from depenemy.parsers.rust import RustParser
from depenemy.rules import ALL_RULES
from depenemy.types import Dependency, Ecosystem, Finding, PackageMetadata, ScanResult, Severity

_CONCURRENCY = 10  # max parallel registry requests

# Rules whose findings contribute to the C001 composite risk score.
_C001_CONTRIBUTING_RULES = {"S007", "S008", "S009", "R003", "R004", "R006"}


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
                    publisher_name=meta.publisher_name,
                )
                meta.contributor_count = gh_data.get("contributor_count", 0)
                meta.is_archived = gh_data.get("is_archived", False)
                if gh_data.get("author_account_created_at"):
                    meta.author_account_created_at = parse_date(
                        gh_data["author_account_created_at"]
                    )
                # S007 ghost repo signals
                meta.repo_commit_count = gh_data.get("repo_commit_count", 0)
                meta.repo_issue_count = gh_data.get("repo_issue_count", 0)
                meta.repo_pr_count = gh_data.get("repo_pr_count", 0)
                meta.repo_has_ci = gh_data.get("repo_has_ci", False)
                if gh_data.get("repo_created_at"):
                    meta.repo_created_at = parse_date(gh_data["repo_created_at"])
                # S009 publisher identity
                meta.publisher_has_github = gh_data.get("publisher_has_github", True)

                # Fetch security advisories
                target = meta.target_version
                if target:
                    meta.advisories = await osv_advisor.get_advisories(
                        dep.name, target, dep.ecosystem
                    )

                # Package-level fix versions so R010 can exempt a freshly
                # published version when it's the security fix for a CVE
                # affecting earlier versions of the same package.
                meta.security_fix_versions = await osv_advisor.get_fixed_versions(
                    dep.name, dep.ecosystem
                )

                # Check for malicious activity history (version-scoped)
                meta.malicious_advisories = await osv_advisor.check_malicious(
                    dep.name, dep.ecosystem, version=target or ""
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
                finding_key = (dep.name, dep.ecosystem.value, rule.id)
                if finding_key not in seen_findings:
                    seen_findings.add(finding_key)
                    findings.append(finding)

    # 5. Run project-level rules once per scanned manifest.
    deps_by_manifest: dict[str, list[Dependency]] = {}
    for dep in deps:
        deps_by_manifest.setdefault(dep.location.file, []).append(dep)
    seen_project: set[tuple[str, str]] = set()
    for manifest_file, manifest_deps in deps_by_manifest.items():
        manifest_path = Path(manifest_file)
        for rule in ALL_RULES:
            for finding in rule.check_project(manifest_path, manifest_deps, config):
                key = (manifest_file, rule.id)
                if key in seen_project:
                    continue
                seen_project.add(key)
                findings.append(finding)

    # 6. C001 — Composite supply-chain risk score.
    #    After all per-dep findings are collected, aggregate contributing signal counts
    #    per package. If a package accumulates enough signals, emit a C001 BLOCK finding.
    package_signals: dict[tuple[str, str], set[str]] = {}
    for finding in findings:
        dep_key = (finding.dependency.name, finding.dependency.ecosystem.value)
        if finding.rule_id in _C001_CONTRIBUTING_RULES:
            package_signals.setdefault(dep_key, set()).add(finding.rule_id)

    threshold = config.thresholds.composite_score_threshold
    c001_seen: set[tuple[str, str]] = set()
    for (pkg_name, eco_val), fired_rules in package_signals.items():
        if len(fired_rules) < threshold:
            continue
        if (pkg_name, eco_val) in c001_seen:
            continue
        c001_seen.add((pkg_name, eco_val))

        # Find the first Dependency object for this package to anchor the finding
        anchor_dep = next(
            (d for d in deps if d.name == pkg_name and d.ecosystem.value == eco_val),
            None,
        )
        if anchor_dep is None:
            continue

        signal_list = ", ".join(sorted(fired_rules))
        findings.append(
            Finding(
                rule_id="C001",
                rule_name="Composite supply-chain risk",
                severity=Severity.ERROR,
                dependency=anchor_dep,
                message=(
                    f"`{pkg_name}` triggered {len(fired_rules)} independent supply-chain "
                    f"risk signals ({signal_list}), reaching the composite risk threshold "
                    f"of {threshold}. The combination of these signals strongly indicates "
                    f"this package is malicious or has been compromised."
                ),
                actual=f"score={len(fired_rules)}/{threshold}",
            )
        )

    return ScanResult(
        dependencies=unique_deps,
        findings=findings,
        scanned_files=scanned_files,
    )


def _get_parsers(config: Config) -> list[BaseParser]:
    ecosystems = config.ecosystems
    all_parsers = [NpmParser(), PythonParser(), RustParser()]
    if not ecosystems:
        return all_parsers
    return [p for p in all_parsers if p.ecosystem in ecosystems]
