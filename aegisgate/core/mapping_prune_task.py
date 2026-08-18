"""Background task for periodic redaction-mapping retention cleanup."""

from __future__ import annotations

import asyncio
from collections.abc import Callable

from aegisgate.config.settings import settings
from aegisgate.storage.offload import run_store_io
from aegisgate.util.logger import logger


class MappingPruneTask:
    """Owns periodic retention cleanup for the redaction mapping store.

    Mappings are written on every redacted request and consumed on restoration,
    but a request whose response never arrives leaves its mapping behind, so a
    long-running instance needs a sweep. Rows older than
    ``pending_data_ttl_seconds`` are deleted every
    ``mapping_prune_interval_seconds``.
    """

    def __init__(self, *, mapping_prune_func: Callable[[int], int]) -> None:
        self._mapping_prune_func = mapping_prune_func
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        if self._task is not None:
            return
        self._task = asyncio.create_task(
            self._run_loop(), name="aegisgate-mapping-prune"
        )
        logger.info("mapping prune task started")

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
        logger.info("mapping prune task stopped")

    async def _run_loop(self) -> None:
        interval = max(60, int(settings.mapping_prune_interval_seconds))
        while True:
            try:
                max_age_seconds = int(settings.pending_data_ttl_seconds)
                pruned = int(
                    await run_store_io(self._mapping_prune_func, max_age_seconds)
                )
                if pruned > 0:
                    logger.info(
                        "mapping store pruned removed=%s max_age_seconds=%s",
                        pruned,
                        max_age_seconds,
                    )
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # pragma: no cover - operational guard
                logger.warning("mapping prune task failed: %s", exc)
            await asyncio.sleep(interval)
