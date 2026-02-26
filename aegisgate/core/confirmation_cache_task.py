"""Background task for pending confirmation cache cleanup."""

from __future__ import annotations

import asyncio
from collections.abc import Callable

from aegisgate.config.settings import settings
from aegisgate.core.security_boundary import now_ts
from aegisgate.util.logger import logger


class ConfirmationCacheTask:
    """Owns periodic retention cleanup for pending confirmation cache."""

    def __init__(self, *, prune_func: Callable[[int], int]) -> None:
        self._prune_func = prune_func
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
        while True:
            try:
                current_ts = int(now_ts())
                if settings.enable_thread_offload:
                    removed = int(await asyncio.to_thread(self._prune_func, current_ts))
                else:
                    removed = int(self._prune_func(current_ts))
                if removed > 0:
                    logger.info("confirmation cache pruned removed=%s now_ts=%s", removed, current_ts)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # pragma: no cover - operational guard
                logger.warning("confirmation cache prune task failed: %s", exc)
            await asyncio.sleep(interval)
