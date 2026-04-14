<div align="center">

<img src="assets/logos/logo.svg" alt="depenemy" width="380"/>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 320 100" width="320" height="100">
  <!-- Background -->
  <rect width="320" height="100" rx="14" fill="#0d1117"/>

  <!-- "dep" in white -->
  <text x="26" y="68"
    font-family="'Courier New', Courier, monospace"
    font-size="52"
    font-weight="700"
    fill="#ecf0f1"
    letter-spacing="-1">dep</text>

  <!-- "enemy" in red -->
  <text x="126" y="68"
    font-family="'Courier New', Courier, monospace"
    font-size="52"
    font-weight="700"
    fill="#e74c3c"
    letter-spacing="-1">enemy</text>

  <!-- Underline accent under "enemy" -->
  <rect x="126" y="74" width="169" height="3" rx="1.5" fill="#c0392b"/>

  <!-- Small dot separator -->
  <circle cx="118" cy="66" r="3.5" fill="#555"/>
</svg>
**Your dependencies could be your enemy.**

Depenemy scans your project for supply chain risks, behavioral issues, and reputation red flags - before they can do damage.

[![CI](https://github.com/W3OSC/depenemy/actions/workflows/ci.yml/badge.svg)](https://github.com/W3OSC/depenemy/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/depenemy)](https://pypi.org/project/depenemy/)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

</div>

---

## Why depenemy?

Modern projects pull in hundreds of dependencies. Each one is a potential entry point for a supply chain attack - a compromised maintainer account, a typosquatted package, an old version with a known CVE, or a package that runs arbitrary code on install.

Depenemy gives you **a single command** that audits all your dependencies across npm, Python, Rust, and Solidity - and tells you exactly what looks suspicious and why.

---

## What it detects

### Behavioral risks

| ID | Name | Description | Severity |
|----|------|-------------|----------|
| B001 | Range specifier | Version uses `^`, `~`, `>=`, `*` - allows unexpected updates | Warning |
| B002 | No version pinned | No version specified at all | Error |
| B003 | Lagging version | Pinned version is significantly behind latest | Warning |

### Reputation signals

| ID | Name | Description | Severity |
|----|------|-------------|----------|
| R001 | Young author account | Package author's GitHub account is < 12 months old | Warning |
| R002 | New package | Package was first published < 6 months ago | Warning |
| R003 | Low weekly downloads | < 1,000 weekly downloads | Warning |
| R004 | Low total downloads | < 10,000 total downloads | Warning |
| R005 | No updates in 2+ years | Last publish was over 2 years ago | Warning |
| R006 | Few contributors | Fewer than 5 contributors on GitHub | Warning |
| R007 | Known vulnerable version | Your version is below a known security patch (OSV/CVE) | Error |
| R008 | Deprecated package | Package is officially marked as deprecated | Warning |
| R009 | Typosquatting suspected | Name is suspiciously close to a popular package | Warning |

### Supply chain risks

| ID | Name | Description | Severity |
|----|------|-------------|----------|
| S001 | Install scripts | Package runs code at install time (`postinstall`, `preinstall`) | Error |
| S002 | No source repository | No GitHub/GitLab link in package metadata | Warning |
| S003 | Archived repository | Source repo has been archived or deleted | Warning |
| S004 | Dependency confusion | Private package name found on public registry | Warning |
| S005 | Known malicious package | Package has a recorded history of malicious activity (OSV) | Error |

---

## Supported ecosystems

| Ecosystem | Manifest files |
|-----------|----------------|
| **npm / Node.js** | `package.json`, `package-lock.json`, `yarn.lock` |
| **Python** | `requirements*.txt`, `pyproject.toml`, `Pipfile` |
| **Rust** | `Cargo.toml` |
| **Solidity** | Foundry / Hardhat (delegates to npm) |

---

## Installation

```bash
pip install depenemy
```

---

## Usage

### CLI

```bash
# Scan your project
depenemy scan .

# Scan a specific file
depenemy scan pyproject.toml

# Output as SARIF (for GitHub Code Scanning)
depenemy scan . --output sarif --output-file results.sarif

# Output as JSON to a custom filename (table scan always writes depenemy-results.json automatically)
depenemy scan . --output json --output-file my-results.json

# Pipe JSON output to another tool
depenemy scan . --output json | jq '.findings'

# Fail the command if any warnings exist (useful in CI)
depenemy scan . --fail-on warning

# List all available rules
depenemy rules
```

**Example output:**
<img width="1070" height="711" alt="image" src="https://github.com/user-attachments/assets/96d22774-9649-4b2e-ba09-c3311df8ae3c" />


---

### GitHub Action

Add to your workflow and results appear automatically as [Code Scanning alerts](https://docs.github.com/en/code-security/code-scanning) on every pull request:

```yaml
- name: Scan dependencies
  uses: W3OSC/depenemy@v0.1.0
  with:
    token: ${{ secrets.GITHUB_TOKEN }}
    fail-on: error
```

---

### Pre-commit hook

Block pushes that introduce risky dependencies. Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/W3OSC/depenemy
    rev: v0.1.0
    hooks:
      - id: depenemy
```

---

## Configuration

Create `.depenemy.yml` in your repository root to customize thresholds, severities, and ignore specific packages:

```yaml
thresholds:
  min_weekly_downloads: 1000       # R003 threshold
  min_total_downloads: 10000       # R004 threshold
  min_author_account_age_days: 365 # R001 threshold
  min_package_age_days: 180        # R002 threshold
  max_stale_days: 730              # R005 threshold
  min_contributors: 5              # R006 threshold
  max_version_lag: 10              # B003 threshold (minor versions)
  typosquatting_distance: 1        # R009 threshold (edit distance)

rules:
  B001: warning   # downgrade range specifier to warning
  R003: false     # disable low downloads check entirely

ignore:
  - name: my-internal-package
    ecosystem: npm
    reason: "Internal fork, not on public registry"
  - name: legacy-tool
    ecosystem: pypi
    reason: "Approved exception, tracked in JIRA-1234"
```

Set a rule to `false` to disable it entirely. All other rules accept `warning` or `error`.

---

## Output formats

| Format | Flag | Best for |
|--------|------|----------|
| Table (default) | `--output table` | Terminal / CI logs |
| SARIF | `--output sarif` | GitHub Code Scanning |
| JSON | `--output json` | Custom integrations, dashboards |

---

## How it works

<img width="619" height="813" alt="image" src="https://github.com/user-attachments/assets/07a028e4-5c1f-402e-804e-c9e63148d0aa" />

API responses are cached for **6 hours** in `.depenemy_cache/` to avoid rate limits on repeated runs. Use `--no-cache` to force fresh data.

---

## GitHub Token

A GitHub token unlocks author account age (R001) and contributor count (R006) checks. Without it, those rules are skipped.

```bash
# CLI
depenemy scan . --github-token ghp_xxxx

# Or via environment variable
GITHUB_TOKEN=ghp_xxxx depenemy scan .
```

In GitHub Actions, `${{ secrets.GITHUB_TOKEN }}` is available automatically.

---

## License

MIT - see [LICENSE](LICENSE)
