"""Tests for the PyPI fetcher."""
from __future__ import annotations

import unittest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

from depenemy.fetchers.pypi import PyPIFetcher
from depenemy.types import Ecosystem
from tests.conftest import make_dep


def _response(json_data: dict) -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.json = MagicMock(return_value=json_data)
    return resp


class TestPyPIFetcherPublishedAt(unittest.IsolatedAsyncioTestCase):
    """published_at must reflect the target version's upload date, not the package's first-ever upload."""

    async def test_published_at_uses_target_version_upload_date(self) -> None:
        # PyPI JSON: package born long ago at 0.1.0, target version 0.1.5 published recently.
        pypi_json = {
            "info": {"version": "0.1.5"},
            "releases": {
                "0.1.0": [{"upload_time_iso_8601": "2026-04-09T10:00:00Z"}],
                "0.1.1": [{"upload_time_iso_8601": "2026-04-15T10:00:00Z"}],
                "0.1.5": [{"upload_time_iso_8601": "2026-05-14T10:00:00Z"}],
            },
        }
        client = MagicMock()
        client.get = AsyncMock(return_value=_response(pypi_json))
        cache = MagicMock()
        cache.get = MagicMock(return_value=None)

        fetcher = PyPIFetcher(client, cache)
        dep = make_dep("depenemy", "0.1.5", ecosystem=Ecosystem.PYPI, file="requirements.txt")

        meta = await fetcher.fetch(dep)

        assert meta is not None
        self.assertEqual(meta.target_version, "0.1.5")
        self.assertEqual(meta.published_at, datetime(2026, 5, 14, 10, 0, tzinfo=timezone.utc))
        # last_published_at follows the latest version, which here is also 0.1.5
        self.assertEqual(meta.last_published_at, datetime(2026, 5, 14, 10, 0, tzinfo=timezone.utc))

    async def test_published_at_not_confused_with_earliest_release(self) -> None:
        # Regression: previously the fetcher set published_at to the earliest release of ANY version.
        # A fresh target version pinned in a manifest must surface its own publish date so R010 can fire.
        pypi_json = {
            "info": {"version": "2.0.0"},
            "releases": {
                "1.0.0": [{"upload_time_iso_8601": "2020-01-01T00:00:00Z"}],
                "2.0.0": [{"upload_time_iso_8601": "2026-05-14T00:00:00Z"}],
            },
        }
        client = MagicMock()
        client.get = AsyncMock(return_value=_response(pypi_json))
        cache = MagicMock()
        cache.get = MagicMock(return_value=None)

        fetcher = PyPIFetcher(client, cache)
        dep = make_dep("legacy-pkg", "2.0.0", ecosystem=Ecosystem.PYPI, file="requirements.txt")

        meta = await fetcher.fetch(dep)

        assert meta is not None
        self.assertEqual(meta.published_at, datetime(2026, 5, 14, 0, 0, tzinfo=timezone.utc))
        self.assertNotEqual(meta.published_at, datetime(2020, 1, 1, 0, 0, tzinfo=timezone.utc))
