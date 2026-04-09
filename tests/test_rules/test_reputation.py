"""Tests for reputation rules."""

from __future__ import annotations

import pytest

from depenemy.config import Config
from depenemy.rules.reputation import (
    R001YoungAuthor,
    R002YoungPackage,
    R003LowWeeklyDownloads,
    R004LowTotalDownloads,
    R005StalePackage,
    R006FewContributors,
    R007BelowSecurityPatch,
    R008Deprecated,
)
from depenemy.types import Advisory, Dependency, Ecosystem, Location
from tests.conftest import make_meta


def dep() -> Dependency:
    return Dependency(
        name="test-pkg",
        version_spec="1.0.0",
        ecosystem=Ecosystem.NPM,
        location=Location(file="package.json", line=1),
        resolved_version="1.0.0",
    )


class TestR001YoungAuthor:
    rule = R001YoungAuthor()

    def test_flags_young_author(self) -> None:
        result = self.rule.check(dep(), make_meta(author_age_days=100), Config())
        assert result is not None
        assert result.rule_id == "R001"

    def test_passes_old_author(self) -> None:
        result = self.rule.check(dep(), make_meta(author_age_days=500), Config())
        assert result is None

    def test_passes_no_author_data(self) -> None:
        meta = make_meta()
        meta.author_account_created_at = None
        assert self.rule.check(dep(), meta, Config()) is None


class TestR002YoungPackage:
    rule = R002YoungPackage()

    def test_flags_young_package(self) -> None:
        result = self.rule.check(dep(), make_meta(published_days_ago=30), Config())
        assert result is not None

    def test_passes_old_package(self) -> None:
        result = self.rule.check(dep(), make_meta(published_days_ago=400), Config())
        assert result is None


class TestR003LowWeeklyDownloads:
    rule = R003LowWeeklyDownloads()

    def test_flags_low(self) -> None:
        result = self.rule.check(dep(), make_meta(weekly_dl=500), Config())
        assert result is not None

    def test_passes_high(self) -> None:
        result = self.rule.check(dep(), make_meta(weekly_dl=50000), Config())
        assert result is None

    def test_skips_zero(self) -> None:
        # Zero means API unavailable
        result = self.rule.check(dep(), make_meta(weekly_dl=0), Config())
        assert result is None


class TestR004LowTotalDownloads:
    rule = R004LowTotalDownloads()

    def test_flags_low(self) -> None:
        result = self.rule.check(dep(), make_meta(total_dl=5000), Config())
        assert result is not None

    def test_passes_high(self) -> None:
        result = self.rule.check(dep(), make_meta(total_dl=500000), Config())
        assert result is None


class TestR005StalePackage:
    rule = R005StalePackage()

    def test_flags_stale(self) -> None:
        result = self.rule.check(dep(), make_meta(last_published_days_ago=800), Config())
        assert result is not None

    def test_passes_recent(self) -> None:
        result = self.rule.check(dep(), make_meta(last_published_days_ago=100), Config())
        assert result is None


class TestR006FewContributors:
    rule = R006FewContributors()

    def test_flags_few(self) -> None:
        result = self.rule.check(dep(), make_meta(contributors=2), Config())
        assert result is not None

    def test_passes_many(self) -> None:
        result = self.rule.check(dep(), make_meta(contributors=20), Config())
        assert result is None

    def test_skips_zero(self) -> None:
        result = self.rule.check(dep(), make_meta(contributors=0), Config())
        assert result is None


class TestR007BelowSecurityPatch:
    rule = R007BelowSecurityPatch()

    def test_flags_below_patch(self) -> None:
        meta = make_meta(target="1.0.0", latest="2.0.0")
        meta.advisories = [
            Advisory(
                id="GHSA-test",
                severity="high",
                affected_range="<1.2.0",
                patched_version="1.2.0",
            )
        ]
        result = self.rule.check(dep(), meta, Config())
        assert result is not None
        assert "GHSA-test" in result.message

    def test_passes_above_patch(self) -> None:
        meta = make_meta(target="2.0.0", latest="2.0.0")
        meta.advisories = [
            Advisory(
                id="GHSA-test",
                severity="high",
                affected_range="<1.2.0",
                patched_version="1.2.0",
            )
        ]
        result = self.rule.check(dep(), meta, Config())
        assert result is None


class TestR008Deprecated:
    rule = R008Deprecated()

    def test_flags_deprecated(self) -> None:
        meta = make_meta(deprecated=True)
        meta.deprecation_message = "Use newpkg instead"
        result = self.rule.check(dep(), meta, Config())
        assert result is not None
        assert "deprecated" in result.message.lower()

    def test_passes_not_deprecated(self) -> None:
        result = self.rule.check(dep(), make_meta(deprecated=False), Config())
        assert result is None
