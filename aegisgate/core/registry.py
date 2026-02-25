"""Filter registry."""

from __future__ import annotations

from collections.abc import Iterable

from aegisgate.filters.base import BaseFilter
from aegisgate.util.logger import logger


class FilterRegistry:
    def __init__(self) -> None:
        self._request_filters: list[BaseFilter] = []
        self._response_filters: list[BaseFilter] = []

    def register_request_filters(self, filters: Iterable[BaseFilter]) -> None:
        items = list(filters)
        self._request_filters.extend(items)
        logger.info("registered %d request filters", len(items))

    def register_response_filters(self, filters: Iterable[BaseFilter]) -> None:
        items = list(filters)
        self._response_filters.extend(items)
        logger.info("registered %d response filters", len(items))

    @property
    def request_filters(self) -> list[BaseFilter]:
        return self._request_filters

    @property
    def response_filters(self) -> list[BaseFilter]:
        return self._response_filters
