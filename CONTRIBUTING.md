# Contributing to depenemy

Thank you for your interest in contributing. This guide covers how to set up the project locally, run tests, add new rules, and add support for new ecosystems.

---

## Setup

**Requirements:** Python 3.9+, git

```bash
git clone https://github.com/W3OSC/depenemy.git
cd depenemy
pip install -e ".[dev]"
```

This installs depenemy in editable mode along with all dev dependencies (pytest, ruff, mypy, etc.).

---

## Running tests

```bash
pytest
```

Run a specific test file:

```bash
pytest tests/test_rules/test_b003_lagging.py
```

Run with no coverage output:

```bash
pytest --no-cov
```

---

## Linting and type checking

```bash
ruff check .
mypy depenemy
```

Both run automatically in CI on every push.

---

## Adding a new rule

Rules live in `depenemy/rules/` organized by category:

- `behavioral/` - version pinning and update hygiene (B-prefix)
- `reputation/` - author, download, and maintenance signals (R-prefix)
- `supply_chain/` - install scripts, source repo, known malicious (S-prefix)

### Step 1 - Create the rule file

Pick the next available ID in your category and create the file. For example, a new behavioral rule `B004`:

```python
# depenemy/rules/behavioral/b004_example.py
"""B004 - Short description."""

from __future__ import annotations

from typing import Optional

from depenemy.config import Config
from depenemy.rules.base import BaseRule
from depenemy.types import Dependency, Finding, PackageMetadata


class B004Example(BaseRule):
    id = "B004"
    name = "Example rule"
    description = "One sentence describing what this rule detects."

    def _check(
        self,
        dep: Dependency,
        meta: PackageMetadata,
        config: Config,
    ) -> Optional[Finding]:
        # Return None if the rule does not apply
        if not meta.some_field:
            return None

        # Return a Finding if the rule fires
        return self._finding(
            dep,
            config,
            message=f"`{dep.name}` has a problem because ...",
            actual="what we found",
            expected="what we wanted",
        )
```

**Key fields available on `PackageMetadata`:**

| Field | Type | Description |
|-------|------|-------------|
| `latest_version` | `str` | Latest published version |
| `target_version` | `str` | Version being scanned |
| `published_at` | `datetime` | When target version was published |
| `last_published_at` | `datetime` | When latest version was published |
| `weekly_downloads` | `int` | Weekly download count |
| `total_downloads` | `int` | Total download count |
| `author_account_created_at` | `datetime` | GitHub account creation date |
| `contributor_count` | `int` | Number of GitHub contributors |
| `repository_url` | `str` | Source repository URL |
| `is_deprecated` | `bool` | Whether the package is deprecated |
| `has_install_scripts` | `bool` | Whether it runs code on install |
| `is_archived` | `bool` | Whether the source repo is archived |
| `advisories` | `list[Advisory]` | Known CVE advisories |
| `malicious_advisories` | `list[Advisory]` | Known malicious activity records |

**Tips:**
- Skip dev dependencies when the rule is not relevant to dev tools: `if dep.is_dev: return None`
- Skip when data is unavailable rather than false-positive: `if not meta.author_account_created_at: return None`
- Use `config.thresholds` for configurable thresholds instead of hardcoded values
- Use `parse_semver()` from `depenemy.rules.base` for version comparisons

### Step 2 - Export from the category `__init__.py`

```python
# depenemy/rules/behavioral/__init__.py
from depenemy.rules.behavioral.b004_example import B004Example
```

### Step 3 - Register in `ALL_RULES`

```python
# depenemy/rules/__init__.py
from depenemy.rules.behavioral import B001RangeSpecifier, B002Unpinned, B003LaggingVersion, B004Example

ALL_RULES: list[BaseRule] = [
    ...
    B004Example(),
]
```

### Step 4 - Add a default severity in `config.py`

```python
# depenemy/config.py
DEFAULT_RULES: dict[str, Severity] = {
    ...
    "B004": Severity.WARNING,  # short reason
}
```

Use `Severity.ERROR` only for active threats (code that executes, known CVEs, known malicious). Everything else is `WARNING`.

### Step 5 - Write tests

Create `tests/test_rules/test_b004_example.py`. Use `make_dep` and `make_meta` from `tests/conftest.py`:

```python
from depenemy.config import Config
from depenemy.rules.behavioral.b004_example import B004Example
from tests.conftest import make_dep, make_meta


class TestB004Example:
    rule = B004Example()

    def test_fires_when_condition_met(self):
        dep = make_dep("some-pkg", "1.0.0")
        meta = make_meta("some-pkg", ...)
        result = self.rule.check(dep, meta, Config())
        assert result is not None
        assert result.rule_id == "B004"

    def test_silent_when_condition_not_met(self):
        dep = make_dep("safe-pkg", "1.0.0")
        meta = make_meta("safe-pkg", ...)
        result = self.rule.check(dep, meta, Config())
        assert result is None

    def test_rule_disabled_returns_none(self):
        config = Config(rules={})
        dep = make_dep("some-pkg", "1.0.0")
        result = self.rule.check(dep, make_meta("some-pkg"), config)
        assert result is None
```

### Step 6 - Update the README

Add the new rule to the table in `README.md` under the correct category with ID, name, description, and severity.

---

## Pull request checklist

- [ ] Tests pass: `pytest`
- [ ] No lint errors: `ruff check .`
- [ ] No type errors: `mypy depenemy`
- [ ] New rule added to `ALL_RULES` and `DEFAULT_RULES`
- [ ] README table updated
- [ ] Test covers: fires, silent, rule disabled

---

## Adding a new ecosystem

To add support for a new package ecosystem (e.g. Go, Ruby, Java):

1. **Add the ecosystem value** to `Ecosystem` enum in `depenemy/types.py`
2. **Create a parser** in `depenemy/parsers/` — reads the manifest file and returns a list of `Dependency` objects
3. **Create a fetcher** in `depenemy/fetchers/` — calls the registry API and returns `PackageMetadata`
4. **Register the parser** in `depenemy/scanner.py` inside `_get_parsers()`
5. **Add fixture files** in `tests/fixtures/` with sample manifest files for testing
6. **Write parser tests** in `tests/test_parsers/`

Look at `depenemy/parsers/python.py` and `depenemy/fetchers/pypi.py` as a reference — they are the simplest and cleanest examples.

---

## Project structure

```
depenemy/
  cli.py              # CLI entry point (typer)
  scanner.py          # Main orchestrator: parse -> fetch -> evaluate
  config.py           # Config loading and defaults
  types.py            # Core data types (Dependency, PackageMetadata, Finding)
  cache.py            # Disk cache for API responses
  parsers/            # Manifest file parsers (npm, python, rust)
  fetchers/           # Registry API clients (npm, pypi, crates, github)
  advisories/         # OSV security advisory integration
  rules/              # All detection rules
  reporters/          # Output formatters (table, sarif, json)
tests/
  conftest.py         # Shared fixtures: make_dep(), make_meta()
  fixtures/           # Sample manifest files for parser tests
  test_rules/         # One file per rule
  test_parsers/       # Parser tests
  test_reporters/     # Reporter tests
```
