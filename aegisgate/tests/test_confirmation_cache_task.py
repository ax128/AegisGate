"""Tests for aegisgate.core.confirmation_cache_task — periodic cache cleanup."""

from __future__ import annotations

import asyncio

import pytest

from aegisgate.core.confirmation_cache_task import ConfirmationCacheTask


@pytest.fixture
def prune_log():
    """Track prune function calls."""
    calls = []

    def _prune(ts: int) -> int:
        calls.append(ts)
        return 0

    return _prune, calls


async def test_start_creates_task(monkeypatch, prune_log):
    from aegisgate.config.settings import settings
    monkeypatch.setattr(settings, "pending_prune_interval_seconds", 5)
    monkeypatch.setattr(settings, "enable_thread_offload", False)

    prune_func, calls = prune_log
    task = ConfirmationCacheTask(prune_func=prune_func)

    await task.start()
    assert task._task is not None

    # Let it run one iteration
    await asyncio.sleep(0.05)
    await task.stop()
    assert task._task is None


async def test_start_idempotent(monkeypatch, prune_log):
    from aegisgate.config.settings import settings
    monkeypatch.setattr(settings, "pending_prune_interval_seconds", 5)
    monkeypatch.setattr(settings, "enable_thread_offload", False)

    prune_func, _ = prune_log
    task = ConfirmationCacheTask(prune_func=prune_func)

    await task.start()
    first_task = task._task
    await task.start()
    assert task._task is first_task

    await task.stop()


async def test_stop_noop_when_not_started(prune_log):
    prune_func, _ = prune_log
    task = ConfirmationCacheTask(prune_func=prune_func)
    await task.stop()  # Should not raise


async def test_prune_func_called(monkeypatch, prune_log):
    from aegisgate.config.settings import settings
    monkeypatch.setattr(settings, "pending_prune_interval_seconds", 5)
    monkeypatch.setattr(settings, "enable_thread_offload", False)

    prune_func, calls = prune_log
    task = ConfirmationCacheTask(prune_func=prune_func)

    await task.start()
    # Give the loop time to execute at least once
    await asyncio.sleep(0.1)
    await task.stop()

    assert len(calls) >= 1
    assert isinstance(calls[0], int)


async def test_prune_with_thread_offload(monkeypatch, prune_log):
    from aegisgate.config.settings import settings
    monkeypatch.setattr(settings, "pending_prune_interval_seconds", 5)
    monkeypatch.setattr(settings, "enable_thread_offload", True)

    prune_func, calls = prune_log
    task = ConfirmationCacheTask(prune_func=prune_func)

    await task.start()
    await asyncio.sleep(0.1)
    await task.stop()

    assert len(calls) >= 1


async def test_prune_logs_when_items_removed(monkeypatch):
    from aegisgate.config.settings import settings
    monkeypatch.setattr(settings, "pending_prune_interval_seconds", 5)
    monkeypatch.setattr(settings, "enable_thread_offload", False)

    def _prune_with_removal(ts: int) -> int:
        return 3  # Simulate 3 items removed

    task = ConfirmationCacheTask(prune_func=_prune_with_removal)
    await task.start()
    await asyncio.sleep(0.1)
    await task.stop()
