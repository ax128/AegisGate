"""KV abstraction for redaction mappings."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


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
    def save_pending_confirmation(
        self,
        *,
        confirm_id: str,
        session_id: str,
        route: str,
        request_id: str,
        model: str,
        upstream_base: str,
        pending_request_payload: dict[str, Any],
        pending_request_hash: str,
        reason: str,
        summary: str,
        created_at: int,
        expires_at: int,
        retained_until: int,
        tenant_id: str = "default",
    ) -> None:
        """Persist one pending confirmation record."""

    @abstractmethod
    def get_latest_pending_confirmation(
        self,
        session_id: str,
        now_ts: int,
        *,
        tenant_id: str = "default",
    ) -> dict[str, Any] | None:
        """Return the newest pending confirmation for a session."""

    @abstractmethod
    def get_single_pending_confirmation(
        self,
        *,
        session_id: str,
        route: str,
        now_ts: int,
        tenant_id: str = "default",
        recover_executing_before: int | None = None,
    ) -> dict[str, Any] | None:
        """Return the single routable confirmation or None when ambiguous."""

    @abstractmethod
    def compare_and_update_pending_confirmation_status(
        self,
        *,
        confirm_id: str,
        expected_status: str,
        new_status: str,
        now_ts: int,
    ) -> bool:
        """Atomically transition status when the current status matches."""

    @abstractmethod
    def get_pending_confirmation(self, confirm_id: str) -> dict[str, Any] | None:
        """Load one confirmation record by ID."""

    @abstractmethod
    def update_pending_confirmation_status(self, *, confirm_id: str, status: str, now_ts: int) -> None:
        """Update one confirmation status."""

    @abstractmethod
    def delete_pending_confirmation(self, *, confirm_id: str) -> bool:
        """Delete one confirmation record."""

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
