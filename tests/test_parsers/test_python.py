"""Tests for the Python parser."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path


class TestPythonParser(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())

    def _parse(self, filename: str, content: str) -> list:
        from depenemy.parsers.python import PythonParser
        p = self.tmp / filename
        p.write_text(content)
        return PythonParser().parse(p)

    def test_parse_requirements_basic(self) -> None:
        deps = self._parse("requirements.txt", "requests>=2.0\nflask==2.3.0\n# comment\nnumpy\n")
        names = {d.name for d in deps}
        self.assertIn("requests", names)
        self.assertIn("flask", names)
        self.assertIn("numpy", names)

    def test_version_spec_preserved(self) -> None:
        deps = self._parse("requirements.txt", "flask==2.3.0\n")
        self.assertEqual(deps[0].version_spec, "==2.3.0")

    def test_strips_markers(self) -> None:
        deps = self._parse("requirements.txt", "pywin32>=1.0 ; sys_platform == 'win32'\n")
        self.assertTrue(any(d.name == "pywin32" for d in deps))

    def test_ecosystem_is_pypi(self) -> None:
        from depenemy.types import Ecosystem
        deps = self._parse("requirements.txt", "flask==2.3.0\n")
        self.assertTrue(all(d.ecosystem == Ecosystem.PYPI for d in deps))

    def test_line_numbers(self) -> None:
        deps = self._parse("requirements.txt", "requests>=2.0\nflask==2.3.0\n")
        by_name = {d.name: d for d in deps}
        self.assertEqual(by_name["flask"].location.line, 2)

    def test_parse_pyproject_pep621(self) -> None:
        content = (
            '[project]\nname = "myapp"\n'
            'dependencies = [\n    "requests>=2.0",\n    "pydantic==2.0.0",\n]\n'
        )
        deps = self._parse("pyproject.toml", content)
        names = {d.name for d in deps}
        self.assertIn("requests", names)
        self.assertIn("pydantic", names)


if __name__ == "__main__":
    unittest.main()
