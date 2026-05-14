"""Tests for new supply chain rules: S006, S007, S008, S009."""

from __future__ import annotations

import unittest

from depenemy.config import Config
from depenemy.rules.supply_chain.s006_missing_provenance import S006MissingProvenance
from depenemy.rules.supply_chain.s007_ghost_repo import S007GhostRepo
from depenemy.rules.supply_chain.s008_bulk_publish import S008BulkPublish
from depenemy.rules.supply_chain.s009_identity_mismatch import S009IdentityMismatch
from tests.conftest import make_dep, make_meta


class TestS006MissingProvenance(unittest.TestCase):
    def setUp(self) -> None:
        self.rule = S006MissingProvenance()
        self.dep = make_dep("pkg", "1.0.0")
        self.cfg = Config()

    def test_flags_no_provenance(self) -> None:
        meta = make_meta("pkg")
        meta.has_provenance = False
        result = self.rule.check(self.dep, meta, self.cfg)
        self.assertIsNotNone(result)
        self.assertEqual(result.rule_id, "S006")

    def test_passes_with_provenance(self) -> None:
        meta = make_meta("pkg")
        meta.has_provenance = True
        self.assertIsNone(self.rule.check(self.dep, meta, self.cfg))

    def test_skips_when_provenance_not_checked(self) -> None:
        # None = the fetcher for this ecosystem doesn't probe provenance yet
        # (e.g. PyPI - PEP 740 support is unimplemented). Firing would be a
        # blanket false positive across the entire ecosystem.
        meta = make_meta("pkg")
        meta.has_provenance = None
        self.assertIsNone(self.rule.check(self.dep, meta, self.cfg))


class TestS007GhostRepo(unittest.TestCase):
    def setUp(self) -> None:
        self.rule = S007GhostRepo()
        self.dep = make_dep("pkg", "1.0.0")
        self.cfg = Config()

    def _meta(self, commits: int, issues: int, prs: int, has_ci: bool) -> object:
        from datetime import datetime, timezone
        m = make_meta("pkg")
        m.repo_commit_count = commits
        m.repo_issue_count = issues
        m.repo_pr_count = prs
        m.repo_has_ci = has_ci
        # Setting repo_created_at marks the GitHub fetch as successful;
        # without it S007 now treats the repo as "unknown" and skips.
        m.repo_created_at = datetime(2024, 1, 1, tzinfo=timezone.utc)
        return m

    def test_flags_ghost_repo(self) -> None:
        # 0 commits, 0 issues, no CI - ghost
        meta = self._meta(0, 0, 0, False)
        result = self.rule.check(self.dep, meta, self.cfg)
        self.assertIsNotNone(result)
        self.assertEqual(result.rule_id, "S007")

    def test_flags_few_commits_no_ci(self) -> None:
        # 1 commit (< threshold of 2), has activity, no CI - 2 signals (commits + no CI)
        meta = self._meta(1, 10, 5, False)
        result = self.rule.check(self.dep, meta, self.cfg)
        self.assertIsNotNone(result)

    def test_passes_healthy_repo(self) -> None:
        meta = self._meta(100, 50, 30, True)
        self.assertIsNone(self.rule.check(self.dep, meta, self.cfg))

    def test_skips_no_repo_url(self) -> None:
        meta = make_meta("pkg", repository_url=None)
        self.assertIsNone(self.rule.check(self.dep, meta, self.cfg))

    def test_one_ghost_signal_not_enough(self) -> None:
        # Only 1 signal (no CI) - should not fire
        meta = self._meta(100, 50, 30, False)
        self.assertIsNone(self.rule.check(self.dep, meta, self.cfg))

    def test_skips_when_github_fetch_failed(self) -> None:
        # GitHub fetcher returned no data (no token, rate limited, 404, private).
        # All signal fields remain at default zeros and repo_created_at stays None.
        # Firing here would be a false positive against legitimate packages
        # (typer, httpx, etc.) whose repos depenemy simply couldn't read.
        meta = make_meta("pkg")
        meta.repo_commit_count = 0
        meta.repo_issue_count = 0
        meta.repo_pr_count = 0
        meta.repo_has_ci = False
        meta.repo_created_at = None
        self.assertIsNone(self.rule.check(self.dep, meta, self.cfg))


class TestS008BulkPublish(unittest.TestCase):
    def setUp(self) -> None:
        self.rule = S008BulkPublish()
        self.dep = make_dep("pkg", "1.0.0")
        self.cfg = Config()

    def test_flags_bulk_burst(self) -> None:
        meta = make_meta("pkg")
        meta.publisher_name = "attacker"
        meta.author_package_burst_count = 50  # default threshold is 20
        result = self.rule.check(self.dep, meta, self.cfg)
        self.assertIsNotNone(result)
        self.assertEqual(result.rule_id, "S008")

    def test_passes_normal_publisher(self) -> None:
        meta = make_meta("pkg")
        meta.publisher_name = "trusted"
        meta.author_package_burst_count = 1  # well below threshold of 3
        self.assertIsNone(self.rule.check(self.dep, meta, self.cfg))

    def test_skips_no_publisher_name(self) -> None:
        meta = make_meta("pkg")
        meta.publisher_name = None
        meta.author_package_burst_count = 100
        self.assertIsNone(self.rule.check(self.dep, meta, self.cfg))

    def test_exactly_at_threshold_not_flagged(self) -> None:
        from depenemy.config import Config
        threshold = Config().thresholds.bulk_publish_min_packages
        meta = make_meta("pkg")
        meta.publisher_name = "borderline"
        meta.author_package_burst_count = threshold - 1
        self.assertIsNone(self.rule.check(self.dep, meta, self.cfg))


class TestS009IdentityMismatch(unittest.TestCase):
    def setUp(self) -> None:
        self.rule = S009IdentityMismatch()
        self.dep = make_dep("pkg", "1.0.0")
        self.cfg = Config()

    def test_flags_no_github_account(self) -> None:
        meta = make_meta("pkg", repository_url="https://github.com/myorg/pkg")
        meta.publisher_name = "ghost-user"
        meta.publisher_has_github = False
        result = self.rule.check(self.dep, meta, self.cfg)
        self.assertIsNotNone(result)
        self.assertEqual(result.rule_id, "S009")

    def test_flags_repo_owner_mismatch(self) -> None:
        meta = make_meta("pkg", repository_url="https://github.com/legit-org/pkg")
        meta.publisher_name = "attacker"
        meta.publisher_has_github = True
        result = self.rule.check(self.dep, meta, self.cfg)
        self.assertIsNotNone(result)

    def test_passes_matching_publisher(self) -> None:
        meta = make_meta("pkg", repository_url="https://github.com/myorg/pkg")
        meta.publisher_name = "myorg"
        meta.publisher_has_github = True
        self.assertIsNone(self.rule.check(self.dep, meta, self.cfg))

    def test_skips_no_publisher_name(self) -> None:
        meta = make_meta("pkg")
        meta.publisher_name = None
        meta.publisher_has_github = False
        self.assertIsNone(self.rule.check(self.dep, meta, self.cfg))

    def test_skips_no_repo_url_with_github(self) -> None:
        # No repo URL + has github = no mismatch detectable
        meta = make_meta("pkg", repository_url=None)
        meta.publisher_name = "someone"
        meta.publisher_has_github = True
        self.assertIsNone(self.rule.check(self.dep, meta, self.cfg))
