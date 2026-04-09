"""Disk-backed JSON cache to avoid redundant registry API calls."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Optional


class Cache:
    """Simple disk cache with TTL. Keys are hashed to filenames."""

    DEFAULT_TTL = 3600 * 6  # 6 hours

    def __init__(self, cache_dir: Path, ttl: int = DEFAULT_TTL, disabled: bool = False) -> None:
        self._dir = cache_dir
        self._ttl = ttl
        self._disabled = disabled
        if not disabled:
            cache_dir.mkdir(parents=True, exist_ok=True)

    def get(self, key: str) -> Optional[Any]:
        if self._disabled:
            return None
        path = self._path(key)
        if not path.exists():
            return None
        try:
            with open(path) as f:
                entry = json.load(f)
            if time.time() - entry["ts"] > self._ttl:
                path.unlink(missing_ok=True)
                return None
            return entry["data"]
        except (json.JSONDecodeError, KeyError, OSError):
            return None

    def set(self, key: str, value: Any) -> None:
        if self._disabled:
            return
        path = self._path(key)
        try:
            with open(path, "w") as f:
                json.dump({"ts": time.time(), "data": value}, f)
        except OSError:
            pass

    def clear(self) -> None:
        if self._dir.exists():
            for f in self._dir.glob("*.json"):
                f.unlink(missing_ok=True)

    def _path(self, key: str) -> Path:
        hashed = hashlib.sha256(key.encode()).hexdigest()
        return self._dir / f"{hashed}.json"
