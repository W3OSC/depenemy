"""Tests for the OSV advisor."""
from __future__ import annotations

import unittest
from unittest.mock import AsyncMock, MagicMock

from depenemy.advisories.osv import OSVAdvisor
from depenemy.types import Ecosystem


def _response(json_data: dict) -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.json = MagicMock(return_value=json_data)
    return resp


class TestGetFixedVersions(unittest.IsolatedAsyncioTestCase):
    """get_fixed_versions powers R010's security-fix carve-out, so it has to
    correctly extract every `fixed` SEMVER event from the OSV response."""

    async def test_collects_fixed_versions_across_advisories(self) -> None:
        osv_json = {
            "vulns": [
                {
                    "id": "GHSA-aaaa",
                    "affected": [{
                        "ranges": [{
                            "type": "SEMVER",
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "1.0.1"},
                            ],
                        }],
                    }],
                },
                {
                    "id": "GHSA-bbbb",
                    "affected": [{
                        "ranges": [{
                            "type": "SEMVER",
                            "events": [
                                {"introduced": "1.0.0"},
                                {"fixed": "1.2.0"},
                            ],
                        }],
                    }],
                },
            ]
        }
        client = MagicMock()
        client.post = AsyncMock(return_value=_response(osv_json))
        cache = MagicMock()
        cache.get = MagicMock(return_value=None)

        advisor = OSVAdvisor(client, cache)
        fixed = await advisor.get_fixed_versions("test-pkg", Ecosystem.NPM)

        self.assertEqual(fixed, {"1.0.1", "1.2.0"})

    async def test_ignores_non_semver_ranges(self) -> None:
        osv_json = {
            "vulns": [{
                "id": "GHSA-ecosystem-only",
                "affected": [{
                    "ranges": [{
                        "type": "ECOSYSTEM",
                        "events": [{"fixed": "1.0.1"}],
                    }],
                }],
            }]
        }
        client = MagicMock()
        client.post = AsyncMock(return_value=_response(osv_json))
        cache = MagicMock()
        cache.get = MagicMock(return_value=None)

        advisor = OSVAdvisor(client, cache)
        fixed = await advisor.get_fixed_versions("test-pkg", Ecosystem.NPM)

        self.assertEqual(fixed, set())

    async def test_empty_response(self) -> None:
        client = MagicMock()
        client.post = AsyncMock(return_value=_response({"vulns": []}))
        cache = MagicMock()
        cache.get = MagicMock(return_value=None)

        advisor = OSVAdvisor(client, cache)
        fixed = await advisor.get_fixed_versions("test-pkg", Ecosystem.NPM)

        self.assertEqual(fixed, set())

    async def test_uses_cache(self) -> None:
        client = MagicMock()
        client.post = AsyncMock()
        cache = MagicMock()
        cache.get = MagicMock(return_value=["1.0.1", "1.2.0"])

        advisor = OSVAdvisor(client, cache)
        fixed = await advisor.get_fixed_versions("test-pkg", Ecosystem.NPM)

        self.assertEqual(fixed, {"1.0.1", "1.2.0"})
        client.post.assert_not_called()

    async def test_unsupported_ecosystem_returns_empty(self) -> None:
        client = MagicMock()
        client.post = AsyncMock()
        cache = MagicMock()

        advisor = OSVAdvisor(client, cache)
        fixed = await advisor.get_fixed_versions("test-pkg", Ecosystem.SOLIDITY)

        self.assertEqual(fixed, set())
        client.post.assert_not_called()


if __name__ == "__main__":
    unittest.main()
