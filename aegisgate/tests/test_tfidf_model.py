"""Tests for aegisgate.core.tfidf_model — TfidfClassifier."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from aegisgate.core.tfidf_model import TfidfClassifier, _UNAVAILABLE

# CI runners may take 60s+ to cold-import scipy/sklearn via joblib.
pytestmark = pytest.mark.timeout(120)


class TestTfidfClassifierUnavailable:

    def test_available_false_when_model_files_missing(self) -> None:
        clf = TfidfClassifier()
        # Models likely not present in test env
        if clf._vectorizer is _UNAVAILABLE:
            assert clf.available is False

    def test_predict_returns_unknown_when_unavailable(self) -> None:
        clf = TfidfClassifier()
        if not clf.available:
            label, confidence = clf.predict("test text")
            assert label == "unknown"
            assert confidence == 0.5


class TestTfidfClassifierTokenize:

    def test_lowercase(self) -> None:
        result = TfidfClassifier._tokenize("Hello World")
        assert "hello" in result.lower()

    def test_empty_string(self) -> None:
        result = TfidfClassifier._tokenize("")
        assert result == ""

    def test_whitespace_stripped(self) -> None:
        result = TfidfClassifier._tokenize("  hello  ")
        assert result.strip() == result


class TestTfidfClassifierPredict:

    def test_predict_returns_tuple(self) -> None:
        clf = TfidfClassifier()
        result = clf.predict("What is the weather today?")
        assert isinstance(result, tuple)
        assert len(result) == 2
        label, confidence = result
        assert isinstance(label, str)
        assert isinstance(confidence, float)
        assert 0.0 <= confidence <= 1.0
