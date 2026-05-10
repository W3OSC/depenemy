"""Tests for new behavioral rules: B005, B006, B007."""

from __future__ import annotations

import unittest

from depenemy.config import Config
from depenemy.rules.behavioral.b005_hash_mismatch import B005HashMismatch
from depenemy.rules.behavioral.b006_bad_registry import B006BadRegistry
from depenemy.rules.behavioral.b007_lockfile_injection import B007LockfileInjection
from tests.conftest import make_dep, make_meta


class TestB005HashMismatch(unittest.TestCase):
    def setUp(self) -> None:
        self.rule = B005HashMismatch()
        self.cfg = Config()

    def _dep(self, integrity: str | None = None) -> object:
        d = make_dep("pkg", "1.0.0")
        d.lockfile_integrity = integrity
        return d

    def _meta(self, registry_hash: str | None = None) -> object:
        m = make_meta("pkg")
        m.registry_integrity = registry_hash
        return m

    def test_flags_mismatch(self) -> None:
        dep = self._dep("sha512-AAAA")
        meta = self._meta("sha512-BBBB")
        result = self.rule.check(dep, meta, self.cfg)
        self.assertIsNotNone(result)
        self.assertEqual(result.rule_id, "B005")

    def test_passes_match(self) -> None:
        dep = self._dep("sha512-EXACT")
        meta = self._meta("sha512-EXACT")
        self.assertIsNone(self.rule.check(dep, meta, self.cfg))

    def test_skips_no_lock_hash(self) -> None:
        dep = self._dep(None)
        meta = self._meta("sha512-SOMETHING")
        self.assertIsNone(self.rule.check(dep, meta, self.cfg))

    def test_skips_no_registry_hash(self) -> None:
        dep = self._dep("sha512-SOMETHING")
        meta = self._meta(None)
        self.assertIsNone(self.rule.check(dep, meta, self.cfg))

    def test_skips_both_missing(self) -> None:
        dep = self._dep(None)
        meta = self._meta(None)
        self.assertIsNone(self.rule.check(dep, meta, self.cfg))


class TestB006BadRegistry(unittest.TestCase):
    def setUp(self) -> None:
        self.rule = B006BadRegistry()
        self.cfg = Config()
        self.meta = make_meta("pkg")

    def _dep(self, resolved: str | None) -> object:
        d = make_dep("pkg", "1.0.0")
        d.lockfile_resolved = resolved
        return d

    def test_passes_official_registry(self) -> None:
        dep = self._dep("https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz")
        self.assertIsNone(self.rule.check(dep, self.meta, self.cfg))

    def test_flags_unknown_registry(self) -> None:
        dep = self._dep("https://evil.example.com/pkg/-/pkg-1.0.0.tgz")
        result = self.rule.check(dep, self.meta, self.cfg)
        self.assertIsNotNone(result)
        self.assertEqual(result.rule_id, "B006")

    def test_passes_custom_approved_registry(self) -> None:
        from depenemy.config import Config
        cfg = Config(approved_registries=["myregistry.internal"])
        dep = self._dep("https://myregistry.internal/pkg/-/pkg-1.0.0.tgz")
        self.assertIsNone(self.rule.check(dep, meta=self.meta, config=cfg))

    def test_skips_no_resolved_url(self) -> None:
        dep = self._dep(None)
        self.assertIsNone(self.rule.check(dep, self.meta, self.cfg))


class TestB007LockfileInjection(unittest.TestCase):
    def setUp(self) -> None:
        self.rule = B007LockfileInjection()
        self.cfg = Config()
        self.meta = make_meta("lodash")

    def _dep(self, name: str, resolved: str | None) -> object:
        d = make_dep(name, "4.17.21")
        d.lockfile_resolved = resolved
        return d

    def test_passes_correct_url(self) -> None:
        dep = self._dep("lodash", "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
        self.assertIsNone(self.rule.check(dep, self.meta, self.cfg))

    def test_flags_wrong_package_in_url(self) -> None:
        dep = self._dep("lodash", "https://registry.npmjs.org/evil-pkg/-/evil-pkg-4.17.21.tgz")
        result = self.rule.check(dep, self.meta, self.cfg)
        self.assertIsNotNone(result)
        self.assertEqual(result.rule_id, "B007")

    def test_passes_scoped_package(self) -> None:
        scoped_meta = make_meta("@babel/core")
        dep = self._dep(
            "@babel/core",
            "https://registry.npmjs.org/@babel/core/-/core-7.0.0.tgz",
        )
        self.assertIsNone(self.rule.check(dep, scoped_meta, self.cfg))

    def test_skips_no_resolved_url(self) -> None:
        dep = self._dep("lodash", None)
        self.assertIsNone(self.rule.check(dep, self.meta, self.cfg))
