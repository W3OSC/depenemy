"""Tests for supply chain rules."""

from __future__ import annotations

import unittest

from depenemy.config import Config
from depenemy.rules.supply_chain import S001InstallScripts, S002NoSourceRepo, S003ArchivedRepo
from tests.conftest import make_dep, make_meta


def _dep() -> object:
    return make_dep("test-pkg", "1.0.0")


class TestS001InstallScripts(unittest.TestCase):
    rule = S001InstallScripts()

    def test_flags_install_scripts(self) -> None:
        meta = make_meta("test-pkg", has_install_scripts=True)
        result = self.rule.check(_dep(), meta, Config())  # type: ignore[arg-type]
        self.assertIsNotNone(result)
        self.assertEqual(result.rule_id, "S001")  # type: ignore[union-attr]

    def test_passes_no_scripts(self) -> None:
        meta = make_meta("test-pkg", has_install_scripts=False)
        self.assertIsNone(self.rule.check(_dep(), meta, Config()))  # type: ignore[arg-type]


class TestS002NoSourceRepo(unittest.TestCase):
    rule = S002NoSourceRepo()

    def test_flags_missing_repo(self) -> None:
        meta = make_meta("test-pkg", repository_url=None)
        self.assertIsNotNone(self.rule.check(_dep(), meta, Config()))  # type: ignore[arg-type]

    def test_passes_with_repo(self) -> None:
        meta = make_meta("test-pkg", repository_url="https://github.com/ex/pkg")
        self.assertIsNone(self.rule.check(_dep(), meta, Config()))  # type: ignore[arg-type]


class TestS003ArchivedRepo(unittest.TestCase):
    rule = S003ArchivedRepo()

    def test_flags_archived(self) -> None:
        meta = make_meta("test-pkg", is_archived=True)
        self.assertIsNotNone(self.rule.check(_dep(), meta, Config()))  # type: ignore[arg-type]

    def test_passes_active(self) -> None:
        meta = make_meta("test-pkg", is_archived=False)
        self.assertIsNone(self.rule.check(_dep(), meta, Config()))  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
