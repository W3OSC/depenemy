# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.5] - 2026-05-14

### Added
- B004: Enforce lockfile - flags manifests with no adjacent lockfile (Warning). Supports `package.json`/`Pipfile`/`pyproject.toml`/`Cargo.toml`; `requirements*.txt` skipped (it is itself a pin source).
- `BaseRule.check_project()` hook for project-level rules that operate on a manifest as a whole.
- B005: Lockfile integrity hash mismatch - detects tarball tampering (Error).
- B006: Package resolved from unapproved/unknown registry (Error).
- B007: Lockfile injection - resolved URL path doesn't match package name (Error).
- S006: Missing Sigstore provenance attestation (Warning).
- S007: Ghost repository - facade repo with minimal activity (Warning).
- S008: Bulk publish burst - attacker registering many packages rapidly (Warning).
- S009: Publisher/GitHub identity mismatch - account takeover signal (Warning).
- C001: Composite supply-chain risk score - fires when a package accumulates ≥4 independent signals from {S007, S008, S009, R003, R004, R006} (Error).
- npm parser extracts `integrity` and `resolved` fields from lockfile v2/v3.
- npm fetcher pulls `registry_integrity`, `has_provenance`, `publisher_name`, and `author_package_burst_count` from the registry API.
- GitHub fetcher pulls `repo_commit_count`, `repo_issue_count`, `repo_pr_count`, `repo_has_ci`, and `publisher_has_github` signals.
- Configurable thresholds: `ghost_repo_max_commits`, `bulk_publish_window_hours`, `bulk_publish_min_packages`, `composite_score_threshold`, and `approved_registries` list.
- README: contributions section with collaboration guidelines.

## [0.1.4] - 2026-04-16

### Fixed
- npm fetcher now uses target version publish date instead of package creation date (fixes R002 and R010 for npm)

## [0.1.3] - 2026-04-16

### Added
- R010: Recently published version - flags versions published less than 7 days ago (Error)

## [0.1.2] - 2026-04-16

### Changed
- Version is now read dynamically from package metadata - only one place to update on release
- Moved GitHub Action to separate repo `W3OSC/depenemy-action`

### Fixed
- README clarifications: pre-commit setup, GitHub Action workflow, Code Scanning public repo requirement

## [0.1.1] - 2026-04-15

### Fixed
- Added `.pre-commit-hooks.yaml` so the pre-commit hook actually works
- Updated README with full GitHub Action workflow example

## [0.1.0] - 2026-04-09

### Added
- Initial release
- npm and PyPI ecosystem support
- Behavioral checks: range specifiers, unpinned versions, lagging versions
- Reputation checks: author age, package age, download counts, contributors, staleness, known CVEs, deprecated packages, typosquatting
- Supply chain checks: install scripts, missing source repo, archived repo, dependency confusion, known malicious packages
- Deprecated package detection
- OSV.dev integration for security advisories
- SARIF 2.1.0 output (GitHub Code Scanning compatible)
- Rich terminal table output
- JSON output
- Disk-backed caching
- GitHub Action support
- Pre-commit hook support
- Configurable thresholds via `.depenemy.yml`
