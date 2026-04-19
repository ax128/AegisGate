from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Generic, TypeVar


ContinueT = TypeVar("ContinueT")
ResultT = TypeVar("ResultT")


@dataclass(slots=True)
class Continue(Generic[ContinueT]):
    value: ContinueT


@dataclass(slots=True)
class Finish(Generic[ResultT]):
    value: ResultT


class OnceSyncCall:
    def __init__(self, label: str, func: Callable[[], None]) -> None:
        self._label = label
        self._func = func
        self._called = False

    @property
    def called(self) -> bool:
        return self._called

    def __call__(self) -> None:
        if self._called:
            raise RuntimeError(f"{self._label} called more than once")
        self._called = True
        self._func()


class OnceAsyncCall(Generic[ResultT]):
    def __init__(self, label: str, func: Callable[[], Awaitable[ResultT]]) -> None:
        self._label = label
        self._func = func
        self._called = False

    @property
    def called(self) -> bool:
        return self._called

    async def __call__(self) -> ResultT:
        if self._called:
            raise RuntimeError(f"{self._label} called more than once")
        self._called = True
        return await self._func()


async def run_once_execution(
    *,
    request_stage: Callable[[], Awaitable[Any]],
    forward_stage: Callable[[Any], Awaitable[Any]],
    response_stage: Callable[[Any], Awaitable[Any]],
) -> Any:
    request_result = await request_stage()
    if isinstance(request_result, Finish):
        return request_result.value

    forward_result = await forward_stage(request_result.value)
    if isinstance(forward_result, Finish):
        return forward_result.value

    return await response_stage(forward_result.value)
