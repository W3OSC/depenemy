"""R009 — Package name resembles a popular package (typosquatting)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from rapidfuzz.distance import Levenshtein

from depenemy.config import Config
from depenemy.rules.base import BaseRule
from depenemy.types import Dependency, Ecosystem, Finding, PackageMetadata

_DATA_DIR = Path(__file__).parent.parent.parent / "data"
_TOP_NPM: list[str] = []
_TOP_PYPI: list[str] = []


def _load_top_packages() -> None:
    global _TOP_NPM, _TOP_PYPI
    if not _TOP_NPM:
        p = _DATA_DIR / "top_npm_packages.json"
        if p.exists():
            _TOP_NPM = json.loads(p.read_text())
    if not _TOP_PYPI:
        p = _DATA_DIR / "top_pypi_packages.json"
        if p.exists():
            _TOP_PYPI = json.loads(p.read_text())


class R009Typosquatting(BaseRule):
    id = "R009"
    name = "Typosquatting suspected"
    description = (
        "The package name is suspiciously similar to a popular package. "
        "This is a common supply chain attack vector."
    )

    def _check(
        self,
        dep: Dependency,
        meta: PackageMetadata,
        config: Config,
    ) -> Optional[Finding]:
        _load_top_packages()

        top = _TOP_NPM if dep.ecosystem == Ecosystem.NPM else _TOP_PYPI
        if not top:
            return None

        name = dep.name.lower()
        max_distance = config.thresholds.typosquatting_distance

        for popular in top:
            if popular.lower() == name:
                return None  # exact match = it IS the popular package
            dist = Levenshtein.distance(name, popular.lower(), score_cutoff=max_distance)
            if dist <= max_distance:
                return self._finding(
                    dep,
                    config,
                    f"`{dep.name}` is suspiciously similar to `{popular}` "
                    f"(edit distance: {dist}). Possible typosquatting.",
                    actual=dep.name,
                    expected=f"not similar to `{popular}`",
                )
        return None
