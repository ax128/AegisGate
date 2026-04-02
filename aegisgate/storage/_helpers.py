"""Shared helpers for storage backends."""

from __future__ import annotations

import json
import threading
from collections import OrderedDict
from typing import Any


def json_dumps(data: dict[str, Any]) -> str:
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def json_loads(data: str) -> dict[str, Any]:
    loaded = json.loads(data)
    if isinstance(loaded, dict):
        return loaded
    return {}


def to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


class LRUMappingCache:
    """Thread-safe LRU cache for redaction mappings."""

    def __init__(self, max_entries: int = 5000) -> None:
        self.max_entries = max_entries
        self._cache: OrderedDict[tuple[str, str], dict[str, str]] = OrderedDict()
        self._lock = threading.Lock()

    def set(self, session_id: str, request_id: str, mapping: dict[str, str]) -> None:
        key = (session_id, request_id)
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
            self._cache[key] = dict(mapping)
            while len(self._cache) > self.max_entries:
                self._cache.popitem(last=False)

    def get(self, session_id: str, request_id: str) -> dict[str, str] | None:
        key = (session_id, request_id)
        with self._lock:
            data = self._cache.get(key)
            if data is None:
                return None
            self._cache.move_to_end(key)
            return dict(data)

    def pop(self, session_id: str, request_id: str) -> dict[str, str] | None:
        key = (session_id, request_id)
        with self._lock:
            data = self._cache.pop(key, None)
            return dict(data) if data is not None else None
