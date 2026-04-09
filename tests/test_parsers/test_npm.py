"""Tests for the npm parser."""

from __future__ import annotations

import json
import unittest
from pathlib import Path


class TestNpmParser(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile
        self.tmp = Path(tempfile.mkdtemp())
        pkg = {
            "name": "my-app", "version": "1.0.0",
            "dependencies": {"express": "^4.18.2", "lodash": "4.17.21"},
            "devDependencies": {"jest": "^29.0.0"},
        }
        (self.tmp / "package.json").write_text(json.dumps(pkg, indent=2))
        lock = {
            "lockfileVersion": 3,
            "packages": {
                "node_modules/express": {"version": "4.18.2"},
                "node_modules/lodash": {"version": "4.17.21"},
                "node_modules/jest": {"version": "29.6.0"},
            },
        }
        (self.tmp / "package-lock.json").write_text(json.dumps(lock))

    def _parse(self) -> list:
        from depenemy.parsers.npm import NpmParser
        return NpmParser().parse(self.tmp / "package.json")

    def test_parses_dependencies(self) -> None:
        names = {d.name for d in self._parse()}
        self.assertIn("express", names)
        self.assertIn("lodash", names)
        self.assertIn("jest", names)

    def test_ecosystem_is_npm(self) -> None:
        from depenemy.types import Ecosystem
        self.assertTrue(all(d.ecosystem == Ecosystem.NPM for d in self._parse()))

    def test_dev_flag(self) -> None:
        deps = {d.name: d for d in self._parse()}
        self.assertTrue(deps["jest"].is_dev)
        self.assertFalse(deps["express"].is_dev)

    def test_resolved_version_from_lockfile(self) -> None:
        deps = {d.name: d for d in self._parse()}
        self.assertEqual(deps["express"].resolved_version, "4.18.2")

    def test_version_spec_preserved(self) -> None:
        deps = {d.name: d for d in self._parse()}
        self.assertEqual(deps["express"].version_spec, "^4.18.2")

    def test_excludes_node_modules(self) -> None:
        from depenemy.parsers.npm import NpmParser
        nm = self.tmp / "node_modules" / "evil"
        nm.mkdir(parents=True)
        (nm / "package.json").write_text(json.dumps({"dependencies": {"malware": "1.0.0"}}))
        deps = NpmParser().find_and_parse(self.tmp)
        self.assertFalse(any(d.name == "malware" for d in deps))


if __name__ == "__main__":
    unittest.main()
