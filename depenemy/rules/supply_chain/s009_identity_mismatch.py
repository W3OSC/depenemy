"""S009 - npm publisher has no GitHub account or doesn't match the repo owner."""

from __future__ import annotations

from typing import Optional

from depenemy.config import Config
from depenemy.rules.base import BaseRule
from depenemy.types import Dependency, Finding, PackageMetadata


def _repo_owner(repo_url: Optional[str]) -> Optional[str]:
    if not repo_url:
        return None
    # Accept https://github.com/owner/repo or git+https://... or git://...
    for prefix in ("https://github.com/", "http://github.com/", "git+https://github.com/"):
        if repo_url.startswith(prefix):
            remainder = repo_url[len(prefix):]
            parts = remainder.split("/")
            if parts:
                return parts[0].lower()
    return None


class S009IdentityMismatch(BaseRule):
    id = "S009"
    name = "Publisher identity mismatch"
    description = (
        "The npm publisher who last released this package either has no GitHub account "
        "or is not the owner of the declared source repository. "
        "This mismatch is a strong indicator of an account takeover, a stolen credential, "
        "or a fake publisher identity used in a supply chain attack."
    )

    def _check(
        self,
        dep: Dependency,
        meta: PackageMetadata,
        config: Config,
    ) -> Optional[Finding]:
        if not meta.publisher_name:
            return None

        no_github = not meta.publisher_has_github
        owner = _repo_owner(meta.repository_url)
        owner_mismatch = (
            owner is not None and owner != meta.publisher_name.lower()
        )

        if not (no_github or owner_mismatch):
            return None

        reasons: list[str] = []
        if no_github:
            reasons.append(f"publisher `{meta.publisher_name}` has no GitHub account")
        if owner_mismatch:
            reasons.append(
                f"publisher `{meta.publisher_name}` ≠ repo owner `{owner}`"
            )

        detail = "; ".join(reasons)
        return self._finding(
            dep,
            config,
            f"`{dep.name}` shows a publisher identity mismatch: {detail}. "
            f"This can indicate account takeover, credential theft, or a fake identity "
            f"used to slip malicious code through an update.",
            actual=detail,
        )
