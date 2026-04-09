# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-04-09

### Added
- Initial release
- npm and PyPI ecosystem support
- Behavioral checks: range specifiers, unpinned versions, lagging versions
- Reputation checks: author age, package age, download counts, contributors, staleness
- Supply chain checks: install scripts, missing source repo, archived repo, dependency confusion
- Compliance checks: restrictive licenses, missing license
- Quality checks: single maintainer
- Typosquatting detection via Levenshtein distance
- Deprecated package detection
- OSV.dev integration for security advisories
- SARIF 2.1.0 output (GitHub Code Scanning compatible)
- Rich terminal table output
- JSON output
- Disk-backed caching
- GitHub Action support
- Pre-commit hook support
- Configurable thresholds via `.depenemy.yml`
