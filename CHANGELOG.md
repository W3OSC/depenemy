# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
