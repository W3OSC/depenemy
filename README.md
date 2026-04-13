# depenemy

**Your dependencies could be your enemy.** Depenemy scans your project for supply chain risks, behavioral issues, and reputation red flags before they can do damage.

[![CI](https://github.com/W3OSC/depenemy/actions/workflows/ci.yml/badge.svg)](https://github.com/W3OSC/depenemy/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/depenemy)](https://pypi.org/project/depenemy/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## What it detects

| Category | Check | ID |
|----------|-------|----|
| Behavioral | Range specifier (`^`, `~`, `>=`, `*`) | B001 |
| Behavioral | No version pinned | B002 |
| Behavioral | Version significantly behind latest | B003 |
| Reputation | Young author account (< 12 months) | R001 |
| Reputation | New package (< 6 months since first release) | R002 |
| Reputation | Low weekly downloads (< 1,000) | R003 |
| Reputation | Low total downloads (< 10,000) | R004 |
| Reputation | No updates in 2+ years | R005 |
| Reputation | Few contributors (< 5 on GitHub) | R006 |
| Reputation | Known vulnerable version (OSV CVE) | R007 |
| Reputation | Package officially deprecated | R008 |
| Reputation | Typosquatting suspected | R009 |
| Supply Chain | Install scripts (postinstall/preinstall) | S001 |
| Supply Chain | No source repository linked | S002 |
| Supply Chain | Source repository archived | S003 |
| Supply Chain | Dependency confusion (private pkg on public registry) | S004 |
| Supply Chain | Known malicious package history | S005 |

## Supported ecosystems

| Ecosystem | Files |
|-----------|-------|
| npm / Node.js | `package.json`, `package-lock.json`, `yarn.lock` |
| Python | `requirements*.txt`, `pyproject.toml`, `Pipfile` |
| Rust | `Cargo.toml` |
| Solidity | Foundry/Hardhat (delegates to npm) |

## Installation

```bash
pip install depenemy
```

## Usage

### CLI

```bash
# Scan current directory
depenemy scan .

# Scan with specific output format
depenemy scan . --output sarif --output-file results.sarif

# Fail on warnings too
depenemy scan . --fail-on warning

# List all rules
depenemy rules
```

### GitHub Action

```yaml
- name: Scan dependencies
  uses: W3OSC/depenemy@v0.1.0
  with:
    token: ${{ secrets.GITHUB_TOKEN }}
    fail-on: error
```

Results appear as [Code Scanning alerts](https://docs.github.com/en/code-security/code-scanning) on your pull requests.

### Pre-commit hook

Add to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/W3OSC/depenemy
    rev: v0.1.0
    hooks:
      - id: depenemy
```

## Configuration

Create `.depenemy.yml` in your repository root:

```yaml
thresholds:
  min_weekly_downloads: 1000
  min_author_account_age_days: 365
  min_package_age_days: 180
  max_stale_days: 730
  min_contributors: 5

rules:
  B001: warning
  R001: error
  S001: error

ignore:
  - name: my-internal-package
    ecosystem: npm
    reason: "Internal fork"
```

Set a rule to `false` to disable it entirely.

## Output formats

| Format | Flag | Use case |
|--------|------|----------|
| Table | `--output table` | Terminal / CI logs |
| SARIF | `--output sarif` | GitHub Code Scanning |
| JSON | `--output json` | Custom integrations |

## How it works

1. **Parse** — finds all manifest files in the target path
2. **Fetch** — queries npm, PyPI, crates.io, and GitHub APIs (with disk cache)
3. **Advise** — checks [OSV.dev](https://osv.dev) for known CVEs
4. **Evaluate** — runs all enabled rules against each dependency
5. **Report** — outputs findings in the requested format

API responses are cached for 6 hours in `.depenemy_cache/` to avoid rate limits on repeated runs.

## License

MIT — see [LICENSE](LICENSE)
