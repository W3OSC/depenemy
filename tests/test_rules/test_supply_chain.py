"""Tests for supply chain rules."""

from __future__ import annotations

from depenemy.config import Config
from depenemy.rules.supply_chain import (
    S001InstallScripts,
    S002NoSourceRepo,
    S003ArchivedRepo,
)
from depenemy.types import Dependency, Ecosystem, Location
from tests.conftest import make_meta


def dep() -> Dependency:
    return Dependency(
        name="test-pkg",
        version_spec="1.0.0",
        ecosystem=Ecosystem.NPM,
        location=Location(file="package.json", line=1),
    )


class TestS001InstallScripts:
    rule = S001InstallScripts()

    def test_flags_install_scripts(self) -> None:
        result = self.rule.check(dep(), make_meta(install_scripts=True), Config())
        assert result is not None
        assert result.rule_id == "S001"

    def test_passes_no_scripts(self) -> None:
        result = self.rule.check(dep(), make_meta(install_scripts=False), Config())
        assert result is None


class TestS002NoSourceRepo:
    rule = S002NoSourceRepo()

    def test_flags_missing_repo(self) -> None:
        meta = make_meta(repo_url="")
        meta.repository_url = None
        result = self.rule.check(dep(), meta, Config())
        assert result is not None

    def test_passes_with_repo(self) -> None:
        result = self.rule.check(dep(), make_meta(repo_url="https://github.com/ex/pkg"), Config())
        assert result is None


class TestS003ArchivedRepo:
    rule = S003ArchivedRepo()

    def test_flags_archived(self) -> None:
        result = self.rule.check(dep(), make_meta(archived=True), Config())
        assert result is not None

    def test_passes_active(self) -> None:
        result = self.rule.check(dep(), make_meta(archived=False), Config())
        assert result is None
