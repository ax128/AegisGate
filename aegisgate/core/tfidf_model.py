"""Lightweight TF-IDF prompt injection classifier.

Loads pre-trained vectorizer + classifier from joblib files.
Gracefully degrades if models are missing or dependencies unavailable.
"""

from __future__ import annotations

import hashlib
import re
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any

from aegisgate.util.logger import logger

if TYPE_CHECKING:
    pass

_MODEL_DIR = Path(__file__).resolve().parent.parent / "models" / "tfidf"
_VECTORIZER_PATH = _MODEL_DIR / "vectorizer.joblib"
_CLASSIFIER_PATH = _MODEL_DIR / "classifier.joblib"

_EXPECTED_HASHES: dict[str, str] = {
    "vectorizer.joblib": "bf764795ebdd3604440e1fa99cb57e98bf74036ebe5564039db5dd129f125520",
    "classifier.joblib": "15b446cf5fbb5262be808f98c53e282e20c39e412b829fc010a0a592e90c7b57",
}


def _verify_model_integrity(path: Path) -> bool:
    expected = _EXPECTED_HASHES.get(path.name)
    if not expected:
        return True
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    if sha != expected:
        logger.error(
            "tfidf model integrity check FAILED: %s sha256=%s expected=%s",
            path, sha, expected,
        )
        return False
    return True

# Sentinel for "model not available"
_UNAVAILABLE = "unavailable"


class TfidfClassifier:
    """Thread-safe TF-IDF classifier. Falls back to (\"unknown\", 0.5) if unavailable."""

    def __init__(self) -> None:
        self._vectorizer: Any = _UNAVAILABLE
        self._classifier: Any = _UNAVAILABLE
        self._jieba_loaded = False
        self._load()

    def _load(self) -> None:
        if not _VECTORIZER_PATH.exists() or not _CLASSIFIER_PATH.exists():
            logger.info("tfidf model files not found, semantic tfidf disabled")
            return
        try:
            if not _verify_model_integrity(_VECTORIZER_PATH) or not _verify_model_integrity(_CLASSIFIER_PATH):
                logger.warning("tfidf model integrity check failed, semantic tfidf disabled")
                return

            import joblib

            self._vectorizer = joblib.load(_VECTORIZER_PATH)
            self._classifier = joblib.load(_CLASSIFIER_PATH)
            # Pre-warm jieba dictionary so first predict() doesn't pay loading cost
            self._ensure_jieba()
            logger.info("tfidf model loaded vectorizer=%s classifier=%s", _VECTORIZER_PATH, _CLASSIFIER_PATH)
        except Exception as exc:
            logger.warning("tfidf model load failed: %s", exc)
            self._vectorizer = _UNAVAILABLE
            self._classifier = _UNAVAILABLE

    def _ensure_jieba(self) -> None:
        if self._jieba_loaded:
            return
        try:
            import jieba

            jieba.setLogLevel(20)
            # Trigger lazy dictionary load in a controlled manner
            jieba.lcut("warmup")
            self._jieba_loaded = True
        except ImportError:
            self._jieba_loaded = True  # mark done, will skip jieba in tokenize

    @property
    def available(self) -> bool:
        return self._vectorizer is not _UNAVAILABLE and self._classifier is not _UNAVAILABLE

    @staticmethod
    def _tokenize(text: str) -> str:
        """Segment Chinese with jieba (if available), keep English as-is."""
        text = text.strip().lower()
        try:
            import jieba

            segments: list[str] = []
            for part in re.split(r"([\u4e00-\u9fff\u3400-\u4dbf]+)", text):
                if re.search(r"[\u4e00-\u9fff\u3400-\u4dbf]", part):
                    segments.extend(jieba.lcut(part))
                else:
                    segments.append(part)
            return " ".join(segments)
        except ImportError:
            return text

    def predict(self, text: str) -> tuple[str, float]:
        """Classify text.

        Returns:
            (label, confidence) where label is "injection" or "safe",
            confidence is 0.0-1.0 probability of the predicted class.
            Returns ("unknown", 0.5) if model unavailable.
        """
        if not self.available:
            return "unknown", 0.5

        self._ensure_jieba()

        try:
            tokenized = self._tokenize(text)
            vec = self._vectorizer.transform([tokenized])
            proba = self._classifier.predict_proba(vec)[0]
            # proba[0] = safe, proba[1] = injection
            injection_prob = float(proba[1])
            if injection_prob >= 0.5:
                return "injection", injection_prob
            return "safe", 1.0 - injection_prob
        except Exception as exc:
            logger.warning("tfidf predict error: %s", exc)
            return "unknown", 0.5


# Module-level singleton (lazy init on first import)
_instance: TfidfClassifier | None = None
_instance_lock = threading.Lock()


def get_tfidf_classifier() -> TfidfClassifier:
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = TfidfClassifier()
    return _instance
