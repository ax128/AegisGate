"""Background task for pending confirmation cache cleanup."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
import time

from aegisgate.config.settings import settings
from aegisgate.core.security_boundary import now_ts
from aegisgate.storage.offload import run_store_io
from aegisgate.util.logger import logger


class ConfirmationCacheTask:
    """Owns periodic retention cleanup for pending confirmation cache."""

    def __init__(
        self,
        *,
        prune_func: Callable[[int], int],
        mapping_prune_func: Callable[[int], int] | None = None,
    ) -> None:
        self._prune_func = prune_func
        self._mapping_prune_func = mapping_prune_func
        self._last_mapping_prune_at: float = 0.0
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        if self._task is not None:
            return
        self._task = asyncio.create_task(self._run_loop(), name="aegisgate-confirmation-cache-prune")
        logger.info("confirmation cache task started")

    async def stop(self) -> None:
        if self._task is None:
            return
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass
        finally:
            self._task = None
        logger.info("confirmation cache task stopped")

    async def _run_loop(self) -> None:
        interval = max(5, int(settings.pending_prune_interval_seconds))
        mapping_interval = max(60, int(getattr(settings, "mapping_prune_interval_seconds", 3600)))
        while True:
            try:
                current_ts = int(now_ts())
                removed = int(await run_store_io(self._prune_func, current_ts))
                if removed > 0:
                    logger.info("confirmation cache pruned removed=%s now_ts=%s", removed, current_ts)
                if (
                    self._mapping_prune_func is not None
                    and (time.monotonic() - self._last_mapping_prune_at) >= mapping_interval
                ):
                    max_age_seconds = int(settings.pending_data_ttl_seconds)
                    pruned = int(await run_store_io(self._mapping_prune_func, max_age_seconds))
                    self._last_mapping_prune_at = time.monotonic()
                    if pruned > 0:
                        logger.info(
                            "mapping store pruned removed=%s max_age_seconds=%s",
                            pruned,
                            max_age_seconds,
                        )
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # pragma: no cover - operational guard
                logger.warning("confirmation cache prune task failed: %s", exc)
            await asyncio.sleep(interval)
