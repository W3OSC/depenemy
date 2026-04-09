"""Parser for npm ecosystem: package.json and package-lock.json."""

from __future__ import annotations

import json
from pathlib import Path

from depenemy.parsers.base import BaseParser
from depenemy.types import Dependency, Ecosystem, Location


class NpmParser(BaseParser):
    ecosystem = Ecosystem.NPM
    manifest_files = ["package.json"]

    def parse(self, path: Path) -> list[Dependency]:
        with open(path) as f:
            data = json.load(f)

        deps: list[Dependency] = []

        # Read resolved versions from adjacent lockfile if available
        resolved = _read_lockfile(path.parent)

        dep_sections = {
            "dependencies": False,
            "devDependencies": True,
            "peerDependencies": False,
            "optionalDependencies": False,
        }

        for section, is_dev in dep_sections.items():
            section_data = data.get(section, {})
            if not isinstance(section_data, dict):
                continue
            # Find line numbers for better SARIF locations
            line_map = _build_line_map(path, section)
            for name, version_spec in section_data.items():
                if not isinstance(version_spec, str):
                    continue
                line, col = line_map.get(name, (1, 1))
                deps.append(
                    Dependency(
                        name=name,
                        version_spec=version_spec,
                        ecosystem=Ecosystem.NPM,
                        location=Location(file=str(path), line=line, column=col),
                        resolved_version=resolved.get(name),
                        is_dev=is_dev,
                    )
                )

        return deps


def _read_lockfile(directory: Path) -> dict[str, str]:
    """Extract name→version map from package-lock.json or yarn.lock."""
    lockfile = directory / "package-lock.json"
    if lockfile.exists():
        try:
            with open(lockfile) as f:
                data = json.load(f)
            # v2/v3 lockfile format
            packages = data.get("packages", {})
            result: dict[str, str] = {}
            for pkg_path, info in packages.items():
                if not pkg_path:  # root package
                    continue
                name = pkg_path.removeprefix("node_modules/")
                if isinstance(info, dict) and "version" in info:
                    result[name] = info["version"]
            return result
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _build_line_map(path: Path, section: str) -> dict[str, tuple[int, int]]:
    """Build a map of package name → (line, column) within a JSON section."""
    result: dict[str, tuple[int, int]] = {}
    try:
        lines = path.read_text().splitlines()
        in_section = False
        for i, line in enumerate(lines, start=1):
            stripped = line.strip()
            if f'"{section}"' in stripped:
                in_section = True
                continue
            if in_section:
                if stripped.startswith("}"):
                    break
                if stripped.startswith('"') and ":" in stripped:
                    name = stripped.split('"')[1]
                    col = len(line) - len(line.lstrip()) + 1
                    result[name] = (i, col)
    except OSError:
        pass
    return result
