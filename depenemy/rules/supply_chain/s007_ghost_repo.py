"""S007 - Package repository shows signs of being a ghost (placeholder) repo."""

from __future__ import annotations

from typing import Optional

from depenemy.config import Config
from depenemy.rules.base import BaseRule
from depenemy.types import Dependency, Finding, PackageMetadata

# A real active project will typically have at least some of these indicators.
_MIN_COMMITS = 3
_MIN_ISSUES_OR_PRS = 1


class S007GhostRepo(BaseRule):
    id = "S007"
    name = "Ghost repository"
    description = (
        "The linked GitHub repository has very few commits, no issues, no pull requests, "
        "and no CI configuration — a strong indicator the repo was created as a facade "
        "to make the package appear legitimate while the real malicious payload is "
        "embedded in the npm tarball."
    )

    def _check(
        self,
        dep: Dependency,
        meta: PackageMetadata,
        config: Config,
    ) -> Optional[Finding]:
        if not meta.repository_url:
            return None  # S002 covers missing repo separately

        max_commits = config.thresholds.ghost_repo_max_commits

        few_commits = meta.repo_commit_count < max_commits
        no_activity = (meta.repo_issue_count + meta.repo_pr_count) < _MIN_ISSUES_OR_PRS
        no_ci = not meta.repo_has_ci

        ghost_signals = sum([few_commits, no_activity, no_ci])
        if ghost_signals < 2:
            return None

        reasons: list[str] = []
        if few_commits:
            reasons.append(f"{meta.repo_commit_count} commit(s) (threshold: {max_commits})")
        if no_activity:
            reasons.append(
                f"{meta.repo_issue_count} issue(s) + {meta.repo_pr_count} PR(s)"
            )
        if no_ci:
            reasons.append("no CI configuration found")

        detail = "; ".join(reasons)
        return self._finding(
            dep,
            config,
            f"`{dep.name}` repository looks like a ghost/facade: {detail}. "
            f"Real packages typically have commit history, issue tracker activity, "
            f"and a CI pipeline. This pattern is used by typosquatting and "
            f"dependency confusion attacks.",
            actual=detail,
        )
