"""Tests for aegisgate.core.registry — filter registration and retrieval."""

from __future__ import annotations

from aegisgate.core.registry import FilterRegistry
from aegisgate.filters.base import BaseFilter


class _DummyFilter(BaseFilter):
    name = "dummy"


class _AnotherFilter(BaseFilter):
    name = "another"


def test_registry_starts_empty():
    reg = FilterRegistry()
    assert reg.request_filters == []
    assert reg.response_filters == []


def test_register_request_filters():
    reg = FilterRegistry()
    f1, f2 = _DummyFilter(), _AnotherFilter()
    reg.register_request_filters([f1, f2])

    assert len(reg.request_filters) == 2
    assert reg.request_filters[0] is f1
    assert reg.request_filters[1] is f2


def test_register_response_filters():
    reg = FilterRegistry()
    f = _DummyFilter()
    reg.register_response_filters([f])
    assert len(reg.response_filters) == 1
    assert reg.response_filters[0] is f


def test_register_multiple_batches():
    reg = FilterRegistry()
    reg.register_request_filters([_DummyFilter()])
    reg.register_request_filters([_AnotherFilter()])
    assert len(reg.request_filters) == 2


def test_register_from_generator():
    reg = FilterRegistry()
    reg.register_request_filters(f for f in [_DummyFilter(), _AnotherFilter()])
    assert len(reg.request_filters) == 2
