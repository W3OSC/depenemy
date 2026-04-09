"""Configuration loading and defaults for depenemy."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import yaml as _yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False

from depenemy.types import Ecosystem, Severity


@dataclass
class IgnoreEntry:
    name: str
    ecosystem: Optional[str] = None
    reason: str = ""


@dataclass
class Thresholds:
    min_weekly_downloads: int = 1000
    min_total_downloads: int = 10000
    min_author_account_age_days: int = 365
    min_package_age_days: int = 180
    max_stale_days: int = 730
    min_contributors: int = 5
    max_version_lag: int = 5
    typosquatting_distance: int = 2


DEFAULT_RULES: dict[str, Severity] = {
    "B001": Severity.WARNING,
    "B002": Severity.WARNING,
    "B003": Severity.WARNING,
    "R001": Severity.ERROR,
    "R002": Severity.WARNING,
    "R003": Severity.WARNING,
    "R004": Severity.WARNING,
    "R005": Severity.WARNING,
    "R006": Severity.WARNING,
    "R007": Severity.ERROR,
    "R008": Severity.ERROR,
    "R009": Severity.ERROR,
    "S001": Severity.ERROR,
    "S002": Severity.WARNING,
    "S003": Severity.ERROR,
    "S004": Severity.ERROR,
    "Q001": Severity.WARNING,
}


@dataclass
class Config:
    thresholds: Thresholds = field(default_factory=Thresholds)
    rules: dict[str, Severity] = field(default_factory=lambda: dict(DEFAULT_RULES))
    ignore: list[IgnoreEntry] = field(default_factory=list)
    ecosystems: list[Ecosystem] = field(default_factory=list)
    github_token: Optional[str] = None
    cache_dir: Path = field(default_factory=lambda: Path(".depenemy_cache"))
    no_cache: bool = False

    def is_rule_enabled(self, rule_id: str) -> bool:
        return rule_id in self.rules

    def rule_severity(self, rule_id: str) -> Severity:
        return self.rules.get(rule_id, Severity.WARNING)

    def is_ignored(self, name: str, ecosystem: Optional[Ecosystem] = None) -> bool:
        for entry in self.ignore:
            if entry.name == name:
                if entry.ecosystem is None or ecosystem is None:
                    return True
                if entry.ecosystem == ecosystem.value:
                    return True
        return False


def load_config(path: Optional[Path] = None) -> Config:
    """Load config from .depenemy.yml, falling back to defaults."""
    config_path = path or _find_config()
    if config_path is None or not config_path.exists():
        return Config()

    with open(config_path) as f:
        content = f.read()
    if not _HAS_YAML:
        return Config()
    raw = _yaml.safe_load(content) or {}

    config = Config()

    if "thresholds" in raw:
        t = raw["thresholds"]
        thresholds = Thresholds(
            min_weekly_downloads=t.get("min_weekly_downloads", 1000),
            min_total_downloads=t.get("min_total_downloads", 10000),
            min_author_account_age_days=t.get("min_author_account_age_days", 365),
            min_package_age_days=t.get("min_package_age_days", 180),
            max_stale_days=t.get("max_stale_days", 730),
            min_contributors=t.get("min_contributors", 5),
            max_version_lag=t.get("max_version_lag", 5),
            typosquatting_distance=t.get("typosquatting_distance", 2),
        )
        config.thresholds = thresholds

    if "rules" in raw:
        rules: dict[str, Severity] = {}
        for rule_id, value in raw["rules"].items():
            if value is False:
                continue
            try:
                rules[rule_id] = Severity(str(value))
            except ValueError:
                pass
        config.rules = rules

    if "ignore" in raw and raw["ignore"]:
        config.ignore = [
            IgnoreEntry(
                name=entry["name"],
                ecosystem=entry.get("ecosystem"),
                reason=entry.get("reason", ""),
            )
            for entry in raw["ignore"]
        ]

    if "ecosystems" in raw and raw["ecosystems"]:
        config.ecosystems = [Ecosystem(e) for e in raw["ecosystems"]]

    return config


def _find_config() -> Optional[Path]:
    """Walk up from cwd looking for .depenemy.yml."""
    current = Path.cwd()
    for parent in [current, *current.parents]:
        candidate = parent / ".depenemy.yml"
        if candidate.exists():
            return candidate
    return None
