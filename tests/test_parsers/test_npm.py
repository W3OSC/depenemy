"""Tests for the npm parser."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from depenemy.parsers.npm import NpmParser
from depenemy.types import Ecosystem


@pytest.fixture
def tmp_npm_project(tmp_path: Path) -> Path:
    pkg = {
        "name": "my-app",
        "version": "1.0.0",
        "dependencies": {
            "express": "^4.18.2",
            "lodash": "4.17.21",
        },
        "devDependencies": {
            "jest": "^29.0.0",
        },
    }
    (tmp_path / "package.json").write_text(json.dumps(pkg, indent=2))

    lock = {
        "lockfileVersion": 3,
        "packages": {
            "node_modules/express": {"version": "4.18.2"},
            "node_modules/lodash": {"version": "4.17.21"},
            "node_modules/jest": {"version": "29.6.0"},
        },
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))
    return tmp_path


def test_parses_dependencies(tmp_npm_project: Path) -> None:
    parser = NpmParser()
    deps = parser.parse(tmp_npm_project / "package.json")

    names = {d.name for d in deps}
    assert "express" in names
    assert "lodash" in names
    assert "jest" in names


def test_ecosystem_is_npm(tmp_npm_project: Path) -> None:
    parser = NpmParser()
    deps = parser.parse(tmp_npm_project / "package.json")
    assert all(d.ecosystem == Ecosystem.NPM for d in deps)


def test_dev_flag(tmp_npm_project: Path) -> None:
    parser = NpmParser()
    deps = parser.parse(tmp_npm_project / "package.json")
    jest_dep = next(d for d in deps if d.name == "jest")
    express_dep = next(d for d in deps if d.name == "express")
    assert jest_dep.is_dev is True
    assert express_dep.is_dev is False


def test_resolved_version_from_lockfile(tmp_npm_project: Path) -> None:
    parser = NpmParser()
    deps = parser.parse(tmp_npm_project / "package.json")
    express_dep = next(d for d in deps if d.name == "express")
    assert express_dep.resolved_version == "4.18.2"


def test_version_spec_preserved(tmp_npm_project: Path) -> None:
    parser = NpmParser()
    deps = parser.parse(tmp_npm_project / "package.json")
    express_dep = next(d for d in deps if d.name == "express")
    assert express_dep.version_spec == "^4.18.2"


def test_find_and_parse_excludes_node_modules(tmp_path: Path) -> None:
    (tmp_path / "node_modules" / "some-pkg").mkdir(parents=True)
    (tmp_path / "node_modules" / "some-pkg" / "package.json").write_text(
        json.dumps({"name": "some-pkg", "dependencies": {"evil": "1.0.0"}})
    )
    pkg = {"name": "app", "dependencies": {"react": "18.0.0"}}
    (tmp_path / "package.json").write_text(json.dumps(pkg))

    parser = NpmParser()
    deps = parser.find_and_parse(tmp_path)
    assert all(d.name != "evil" for d in deps)
    assert any(d.name == "react" for d in deps)
