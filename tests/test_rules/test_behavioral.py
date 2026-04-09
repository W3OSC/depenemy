"""Tests for behavioral rules."""

from __future__ import annotations

import pytest

from depenemy.config import Config
from depenemy.rules.behavioral import B001RangeSpecifier, B002Unpinned, B003LaggingVersion
from depenemy.types import Dependency, Ecosystem, Location
from tests.conftest import make_meta


def dep(spec: str, resolved: str | None = None) -> Dependency:
    return Dependency(
        name="test-pkg",
        version_spec=spec,
        ecosystem=Ecosystem.NPM,
        location=Location(file="package.json", line=1),
        resolved_version=resolved,
    )


def meta(latest: str = "2.0.0", target: str = "2.0.0") -> object:
    return make_meta(latest=latest, target=target)


class TestB001RangeSpecifier:
    rule = B001RangeSpecifier()

    def test_flags_caret(self) -> None:
        result = self.rule.check(dep("^1.2.3"), meta(), Config())
        assert result is not None
        assert result.rule_id == "B001"

    def test_flags_tilde(self) -> None:
        assert self.rule.check(dep("~1.2.3"), meta(), Config()) is not None

    def test_flags_wildcard(self) -> None:
        assert self.rule.check(dep("*"), meta(), Config()) is not None

    def test_flags_gte(self) -> None:
        assert self.rule.check(dep(">=1.0.0"), meta(), Config()) is not None

    def test_passes_exact(self) -> None:
        assert self.rule.check(dep("1.2.3"), meta(), Config()) is None

    def test_disabled_by_config(self) -> None:
        cfg = Config()
        cfg.rules = {}
        assert self.rule.check(dep("^1.2.3"), meta(), cfg) is None


class TestB002Unpinned:
    rule = B002Unpinned()

    def test_flags_empty(self) -> None:
        assert self.rule.check(dep(""), meta(), Config()) is not None

    def test_flags_star(self) -> None:
        assert self.rule.check(dep("*"), meta(), Config()) is not None

    def test_flags_latest(self) -> None:
        assert self.rule.check(dep("latest"), meta(), Config()) is not None

    def test_passes_exact(self) -> None:
        assert self.rule.check(dep("1.2.3"), meta(), Config()) is None

    def test_passes_range(self) -> None:
        # B002 only catches fully unpinned, not ranges (B001 handles that)
        assert self.rule.check(dep("^1.0.0"), meta(), Config()) is None


class TestB003LaggingVersion:
    rule = B003LaggingVersion()

    def test_flags_major_lag(self) -> None:
        result = self.rule.check(dep("1.0.0", resolved="1.0.0"), meta("3.0.0", "1.0.0"), Config())
        assert result is not None
        assert "1.0.0" in result.message

    def test_flags_minor_lag_beyond_threshold(self) -> None:
        result = self.rule.check(dep("1.0.0", resolved="1.0.0"), meta("1.6.0", "1.0.0"), Config())
        assert result is not None

    def test_passes_within_threshold(self) -> None:
        result = self.rule.check(dep("1.0.0", resolved="1.0.0"), meta("1.2.0", "1.0.0"), Config())
        assert result is None

    def test_passes_up_to_date(self) -> None:
        result = self.rule.check(dep("2.0.0", resolved="2.0.0"), meta("2.0.0", "2.0.0"), Config())
        assert result is None
