"""SSE frame splitting: a CRLF pair cut across chunks, and large-frame cost."""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncGenerator

import pytest

from aegisgate.adapters.openai_compat.stream_utils import _iter_sse_frames

# 1 KiB slices of one frame. 256 KiB is the per-byte baseline; 1 MiB is the
# case that used to recopy and rescan the whole buffer on every slice.
_CHUNK_SIZE = 1024
_SMALL_FRAME_BYTES = 256 * 1024
_LARGE_FRAME_BYTES = 1024 * 1024
# Old parser: ~3.6x per-byte from 256 KiB to 1 MiB (quadratic copy + rescan).
# Linear parse stays near 1x. 2.5 is between those, with room for timer noise.
_LINEAR_PER_BYTE_RATIO = 2.5


async def _frames_from(chunks: list[bytes]) -> list[bytes]:
    async def _generate() -> AsyncGenerator[bytes, None]:
        for chunk in chunks:
            yield chunk

    return [frame async for frame in _iter_sse_frames(_generate())]


def test_crlf_pair_split_across_chunks_is_one_frame() -> None:
    """A CRLF cut after the CR must not invent a blank line between event and data."""
    frames = asyncio.run(_frames_from([b"event: x\r", b"\ndata: y\r\n\r\n"]))
    assert frames == [b"event: x\ndata: y\n\n"]


def test_crlf_pair_split_with_empty_chunk_between_is_one_frame() -> None:
    """An empty read must not flush a held CR before its LF arrives."""
    frames = asyncio.run(
        _frames_from([b"event: x\r", b"", b"\ndata: y\r\n\r\n"])
    )
    assert frames == [b"event: x\ndata: y\n\n"]


def test_single_chunk_crlf_frame_stays_one_frame() -> None:
    frames = asyncio.run(
        _frames_from([b"event: x\r\ndata: y\r\n\r\n"])
    )
    assert frames == [b"event: x\ndata: y\n\n"]


def test_adjacent_crlf_frames_stay_separate() -> None:
    frames = asyncio.run(_frames_from([b"data: a\r\n\r\ndata: b\r\n\r\n"]))
    assert frames == [b"data: a\n\n", b"data: b\n\n"]


def test_lone_cr_line_ending_still_one_frame() -> None:
    frames = asyncio.run(_frames_from([b"data: y\r\r"]))
    assert frames == [b"data: y\n\n"]


def test_incomplete_frame_is_flushed_at_eof() -> None:
    frames = asyncio.run(_frames_from([b"data: y"]))
    assert frames == [b"data: y\n\n"]


def test_buffer_without_delimiter_still_rejects_over_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.stream_utils._SSE_MAX_BUFFER_BYTES",
        32,
    )
    with pytest.raises(RuntimeError, match="SSE buffer exceeded 32 bytes"):
        asyncio.run(_frames_from([b"data: " + (b"x" * 64)]))


def _payload(size: int) -> bytes:
    prefix = b"data: "
    suffix = b"\n\n"
    filler = size - len(prefix) - len(suffix)
    assert filler > 0
    return prefix + (b"x" * filler) + suffix


async def _sliced(payload: bytes) -> AsyncGenerator[bytes, None]:
    for offset in range(0, len(payload), _CHUNK_SIZE):
        yield payload[offset : offset + _CHUNK_SIZE]


async def _min_parse_seconds(payload: bytes, rounds: int) -> float:
    samples: list[float] = []
    # First pass warms the allocator; it is not part of the budget.
    for _ in range(rounds + 1):
        started = time.perf_counter()
        frames = [frame async for frame in _iter_sse_frames(_sliced(payload))]
        samples.append(time.perf_counter() - started)
        assert frames == [payload]
    return min(samples[1:])


def test_one_megabyte_frame_in_kilobyte_slices_is_linear() -> None:
    """One 1 MB frame fed in 1 KB slices stays within a linear per-byte budget."""
    small = _payload(_SMALL_FRAME_BYTES)
    large = _payload(_LARGE_FRAME_BYTES)

    async def _measure() -> tuple[float, float]:
        small_s = await _min_parse_seconds(small, rounds=5)
        large_s = await _min_parse_seconds(large, rounds=3)
        return small_s, large_s

    small_s, large_s = asyncio.run(_measure())
    per_byte_ratio = (large_s / len(large)) / (small_s / len(small))
    assert per_byte_ratio < _LINEAR_PER_BYTE_RATIO, (
        f"1 MB frame in 1 KB slices cost {per_byte_ratio:.2f}x more per byte "
        f"than 256 KB ({small_s * 1000:.1f} ms vs {large_s * 1000:.1f} ms); "
        f"a linear parse stays under {_LINEAR_PER_BYTE_RATIO:.1f}x"
    )
