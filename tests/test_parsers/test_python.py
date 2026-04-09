"""Tests for the Python parser."""

from __future__ import annotations

from pathlib import Path

import pytest

from depenemy.parsers.python import PythonParser
from depenemy.types import Ecosystem


def test_parse_requirements_txt(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        "requests>=2.0\n"
        "flask==2.3.0\n"
        "# this is a comment\n"
        "numpy\n"
        "-r other.txt\n"
    )
    parser = PythonParser()
    deps = parser.parse(tmp_path / "requirements.txt")

    names = {d.name for d in deps}
    assert "requests" in names
    assert "flask" in names
    assert "numpy" in names


def test_parse_requirements_version_spec(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("flask==2.3.0\n")
    parser = PythonParser()
    deps = parser.parse(tmp_path / "requirements.txt")
    flask = next(d for d in deps if d.name == "flask")
    assert flask.version_spec == "==2.3.0"


def test_parse_requirements_strips_markers(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        "pywin32>=1.0 ; sys_platform == 'win32'\n"
    )
    parser = PythonParser()
    deps = parser.parse(tmp_path / "requirements.txt")
    assert any(d.name == "pywin32" for d in deps)


def test_parse_pyproject_pep621(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\n'
        'name = "myapp"\n'
        'dependencies = [\n'
        '    "requests>=2.0",\n'
        '    "pydantic==2.0.0",\n'
        ']\n'
    )
    parser = PythonParser()
    deps = parser.parse(tmp_path / "pyproject.toml")
    names = {d.name for d in deps}
    assert "requests" in names
    assert "pydantic" in names


def test_ecosystem_is_pypi(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("flask==2.3.0\n")
    parser = PythonParser()
    deps = parser.parse(tmp_path / "requirements.txt")
    assert all(d.ecosystem == Ecosystem.PYPI for d in deps)


def test_line_number_recorded(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests>=2.0\nflask==2.3.0\n")
    parser = PythonParser()
    deps = parser.parse(tmp_path / "requirements.txt")
    flask = next(d for d in deps if d.name == "flask")
    assert flask.location.line == 2
