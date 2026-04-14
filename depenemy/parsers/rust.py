"""Parser for Rust ecosystem: Cargo.toml."""

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


class RustParser(BaseParser):
    ecosystem = Ecosystem.CARGO
    manifest_files = ["Cargo.toml"]

    def parse(self, path: Path) -> list[Dependency]:
        deps: list[Dependency] = []
        try:
            with open(path, "rb") as f:
                data = tomllib.load(f)
        except (OSError, tomllib.TOMLDecodeError):
            return deps

        lines = path.read_text().splitlines()

        sections = {
            "dependencies": False,
            "dev-dependencies": True,
            "build-dependencies": False,
        }

        for section, is_dev in sections.items():
            for name, spec in data.get(section, {}).items():
                if isinstance(spec, str):
                    version_spec = spec
                elif isinstance(spec, dict):
                    version_spec = spec.get("version", "*")
                else:
                    continue

                line = _find_line(lines, name)
                deps.append(
                    Dependency(
                        name=name,
                        version_spec=version_spec,
                        ecosystem=Ecosystem.CARGO,
                        location=Location(file=str(path), line=line, column=1),
                        is_dev=is_dev,
                    )
                )

        return deps


def _find_line(lines: list[str], name: str) -> int:
    pattern = re.compile(r"(?<![A-Za-z0-9_-])" + re.escape(name) + r"(?![A-Za-z0-9_-])")
    for i, line in enumerate(lines, start=1):
        if pattern.search(line):
            return i
    return 1
