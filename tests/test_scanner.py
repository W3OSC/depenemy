"""Tests for the scanner module."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import anyio

from depenemy.config import Config
from depenemy.scanner import _get_parsers, scan


class TestGetParsers(unittest.TestCase):
    def test_returns_all_parsers_when_no_ecosystem_filter(self) -> None:
        config = Config()
        parsers = _get_parsers(config)
        self.assertEqual(len(parsers), 3)

    def test_ecosystem_names_covered(self) -> None:
        config = Config()
        parsers = _get_parsers(config)
        ecosystems = {p.ecosystem for p in parsers}
        from depenemy.types import Ecosystem
        self.assertIn(Ecosystem.NPM, ecosystems)
        self.assertIn(Ecosystem.PYPI, ecosystems)
        self.assertIn(Ecosystem.CARGO, ecosystems)

    def test_filters_to_npm_only(self) -> None:
        from depenemy.types import Ecosystem
        config = Config(ecosystems=[Ecosystem.NPM])
        parsers = _get_parsers(config)
        self.assertEqual(len(parsers), 1)
        self.assertEqual(parsers[0].ecosystem, Ecosystem.NPM)

    def test_filters_to_pypi_only(self) -> None:
        from depenemy.types import Ecosystem
        config = Config(ecosystems=[Ecosystem.PYPI])
        parsers = _get_parsers(config)
        self.assertEqual(len(parsers), 1)
        self.assertEqual(parsers[0].ecosystem, Ecosystem.PYPI)

    def test_filters_to_multiple_ecosystems(self) -> None:
        from depenemy.types import Ecosystem
        config = Config(ecosystems=[Ecosystem.NPM, Ecosystem.CARGO])
        parsers = _get_parsers(config)
        self.assertEqual(len(parsers), 2)


class TestScanEmptyDirectory(unittest.TestCase):
    def test_empty_directory_returns_empty_result(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config = Config(no_cache=True)
            result = anyio.run(scan, [Path(tmpdir)], config)
            self.assertEqual(result.dependencies, [])
            self.assertEqual(result.findings, [])

    def test_empty_result_has_no_scanned_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config = Config(no_cache=True)
            result = anyio.run(scan, [Path(tmpdir)], config)
            self.assertEqual(result.scanned_files, [])


class TestScanIgnoredPackages(unittest.TestCase):
    def test_ignored_package_not_in_deps(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            pkg_json = Path(tmpdir) / "package.json"
            pkg_json.write_text('{"dependencies": {"lodash": "4.17.21"}}')

            from depenemy.config import IgnoreEntry
            config = Config(
                no_cache=True,
                ignore=[IgnoreEntry(name="lodash", ecosystem="npm", reason="test")],
            )
            result = anyio.run(scan, [Path(tmpdir)], config)
            names = [d.name for d in result.dependencies]
            self.assertNotIn("lodash", names)


class TestScanDeduplication(unittest.TestCase):
    def test_same_package_in_two_files_deduplicated(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            # Two package.json files with the same dependency
            sub = Path(tmpdir) / "sub"
            sub.mkdir()
            (Path(tmpdir) / "package.json").write_text('{"dependencies": {"lodash": "4.17.21"}}')
            (sub / "package.json").write_text('{"dependencies": {"lodash": "4.17.21"}}')

            config = Config(no_cache=True)
            result = anyio.run(scan, [Path(tmpdir)], config)
            # lodash should appear only once in unique deps
            lodash_deps = [d for d in result.dependencies if d.name == "lodash"]
            self.assertEqual(len(lodash_deps), 1)


if __name__ == "__main__":
    unittest.main()
