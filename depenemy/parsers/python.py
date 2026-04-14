"""Parser for Python ecosystem: requirements.txt, pyproject.toml, poetry.lock."""

from __future__ import annotations

import re
import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomllib  # type: ignore[no-redef]
    except ImportError:
        import tomli as tomllib  # type: ignore[no-redef,import-untyped]

from depenemy.parsers.base import BaseParser
from depenemy.types import Dependency, Ecosystem, Location


class PythonParser(BaseParser):
    ecosystem = Ecosystem.PYPI
    manifest_files = ["requirements*.txt", "pyproject.toml", "Pipfile"]

    def parse(self, path: Path) -> list[Dependency]:
        name = path.name.lower()
        if name == "pyproject.toml":
            return _parse_pyproject(path)
        if name == "pipfile":
            return _parse_pipfile(path)
        # requirements*.txt
        return _parse_requirements(path)


def _parse_requirements(path: Path) -> list[Dependency]:
    deps: list[Dependency] = []
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return deps

    for i, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Handle inline comments
        line = line.split("#")[0].strip()
        if not line:
            continue

        # Parse: name[extras]>=version,<version ; markers
        match = re.match(r"^([A-Za-z0-9_.\-]+)(\[.*?\])?(.*?)$", line)
        if not match:
            continue

        pkg_name = match.group(1)
        version_spec = match.group(3).strip().split(";")[0].strip()  # strip markers

        deps.append(
            Dependency(
                name=pkg_name,
                version_spec=version_spec or "*",
                ecosystem=Ecosystem.PYPI,
                location=Location(file=str(path), line=i, column=1),
            )
        )
    return deps


def _parse_pyproject(path: Path) -> list[Dependency]:
    deps: list[Dependency] = []
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError):
        return deps

    lines = path.read_text().splitlines()

    # PEP 621 [project].dependencies
    project_deps = data.get("project", {}).get("dependencies", [])
    for dep_str in project_deps:
        name, spec = _split_pep508(dep_str)
        line = _find_line(lines, name)
        deps.append(
            Dependency(
                name=name,
                version_spec=spec,
                ecosystem=Ecosystem.PYPI,
                location=Location(file=str(path), line=line, column=1),
            )
        )

    # Poetry [tool.poetry.dependencies]
    poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    poetry_dev = data.get("tool", {}).get("poetry", {}).get("dev-dependencies", {})
    for pkg, spec in {**poetry_deps, **poetry_dev}.items():
        if pkg.lower() == "python":
            continue
        version_spec = spec if isinstance(spec, str) else (spec.get("version", "*") if isinstance(spec, dict) else "*")
        line = _find_line(lines, pkg)
        deps.append(
            Dependency(
                name=pkg,
                version_spec=version_spec,
                ecosystem=Ecosystem.PYPI,
                location=Location(file=str(path), line=line, column=1),
                is_dev=pkg in poetry_dev,
            )
        )

    return deps


def _parse_pipfile(path: Path) -> list[Dependency]:
    deps: list[Dependency] = []
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError):
        return deps

    lines = path.read_text().splitlines()
    for section, is_dev in [("packages", False), ("dev-packages", True)]:
        for pkg, spec in data.get(section, {}).items():
            version_spec = spec if isinstance(spec, str) else "*"
            line = _find_line(lines, pkg)
            deps.append(
                Dependency(
                    name=pkg,
                    version_spec=version_spec,
                    ecosystem=Ecosystem.PYPI,
                    location=Location(file=str(path), line=line, column=1),
                    is_dev=is_dev,
                )
            )
    return deps


def _split_pep508(dep_str: str) -> tuple[str, str]:
    """Split 'requests>=2.0,<3.0' into ('requests', '>=2.0,<3.0')."""
    match = re.match(r"^([A-Za-z0-9_.\-]+)(\[.*?\])?(.*?)$", dep_str.split(";")[0].strip())
    if match:
        return match.group(1), match.group(3).strip() or "*"
    return dep_str.strip(), "*"


def _find_line(lines: list[str], name: str) -> int:
    pattern = re.compile(r"(?<![A-Za-z0-9_-])" + re.escape(name) + r"(?![A-Za-z0-9_-])")
    for i, line in enumerate(lines, start=1):
        if pattern.search(line):
            return i
    return 1
