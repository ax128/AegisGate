"""KV abstraction for redaction mappings."""

from __future__ import annotations

from abc import ABC, abstractmethod


class KVStore(ABC):
    @abstractmethod
    def set_mapping(self, session_id: str, request_id: str, mapping: dict[str, str]) -> None:
        pass

    @abstractmethod
    def get_mapping(self, session_id: str, request_id: str) -> dict[str, str]:
        pass

    @abstractmethod
    def consume_mapping(self, session_id: str, request_id: str) -> dict[str, str]:
        """Read and delete mapping atomically for one-time restoration."""
        pass
