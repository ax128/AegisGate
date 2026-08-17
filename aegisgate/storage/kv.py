"""KV abstraction for redaction mappings."""

from __future__ import annotations

from abc import ABC, abstractmethod


class KVStore(ABC):
    @abstractmethod
    def set_mapping(self, session_id: str, request_id: str, mapping: dict[str, str]) -> None:
        """Persist one request mapping."""

    @abstractmethod
    def get_mapping(self, session_id: str, request_id: str) -> dict[str, str]:
        """Read one request mapping without consuming it."""

    @abstractmethod
    def consume_mapping(self, session_id: str, request_id: str) -> dict[str, str]:
        """Read and delete mapping atomically for one-time restoration."""

    @abstractmethod
    def prune_pending_confirmations(self, now_ts: int) -> int:
        """Delete expired retained confirmation records."""

    @abstractmethod
    def clear_all_pending_confirmations(self) -> int:
        """Clear all pending confirmation records during startup recovery."""

    def close(self) -> None:
        # File-backed stores do not need shutdown logic, but long-lived
        # networked backends can override this to release pooled resources.
        return None
