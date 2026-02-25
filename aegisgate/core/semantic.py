"""Semantic risk analyzer with gray-zone friendly latency controls."""

from __future__ import annotations

import hashlib
import re
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from dataclasses import dataclass
from threading import Lock

import httpx

from aegisgate.util.logger import logger


@dataclass(slots=True)
class SemanticResult:
    risk_score: float
    tags: list[str]
    reasons: list[str]
    timed_out: bool
    cache_hit: bool
    duration_ms: float


class SemanticAnalyzer:
    """Low-latency semantic-like classifier with timeout and LRU+TTL cache."""

    def __init__(
        self,
        *,
        cache_ttl_seconds: int = 300,
        max_cache_entries: int = 5000,
        artificial_delay_ms: int = 0,
    ) -> None:
        self.cache_ttl_seconds = max(1, int(cache_ttl_seconds))
        self.max_cache_entries = max(100, int(max_cache_entries))
        self.artificial_delay_ms = max(0, int(artificial_delay_ms))
        self._cache: OrderedDict[str, tuple[float, SemanticResult]] = OrderedDict()
        self._cache_lock = Lock()
        self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="semantic-analyzer")

        self._discussion_re = re.compile(
            r"(for\s+research|for\s+analysis|for\s+education|example|quoted|用于研究|用于分析|教学|示例|样例|引用|解释|讨论)",
            re.IGNORECASE,
        )
        self._injection_re = re.compile(
            r"(ignore|bypass|override).*(instruction|policy|rule)|(忽略|绕过|覆盖).*(指令|策略|规则)",
            re.IGNORECASE,
        )
        self._leak_re = re.compile(
            r"(reveal|show|dump|print|leak|disclose).*(system\s+prompt|developer\s+message|developer\s+instruction|hidden\s+instruction|api\s*key|token|cookie|password)"
            r"|((泄露|显示|输出|打印).*(系统提示词|开发者消息|密钥|令牌|token|cookie|密码))",
            re.IGNORECASE,
        )
        self._privilege_re = re.compile(
            r"(read|open|cat|dump).*(local\s+file|system\s+file|config|log|database)"
            r"|((execute|run).*(command|shell|powershell|cmd|bash))"
            r"|((读取|打开|导出).*(本地文件|系统文件|配置|日志|数据库))"
            r"|((执行|运行).*(命令|shell|powershell|cmd|bash))",
            re.IGNORECASE,
        )

    @staticmethod
    def _normalize_text(text: str) -> str:
        collapsed = re.sub(r"\s+", " ", text.strip().lower())
        return collapsed

    @staticmethod
    def _hash_text(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def _cache_get(self, key: str, now: float) -> SemanticResult | None:
        with self._cache_lock:
            item = self._cache.get(key)
            if not item:
                return None
            expires_at, cached = item
            if expires_at <= now:
                self._cache.pop(key, None)
                return None
            self._cache.move_to_end(key)
            return SemanticResult(
                risk_score=cached.risk_score,
                tags=list(cached.tags),
                reasons=list(cached.reasons),
                timed_out=cached.timed_out,
                cache_hit=True,
                duration_ms=cached.duration_ms,
            )

    def _cache_set(self, key: str, result: SemanticResult, now: float) -> None:
        if result.timed_out:
            return
        expires_at = now + float(self.cache_ttl_seconds)
        with self._cache_lock:
            self._cache[key] = (
                expires_at,
                SemanticResult(
                    risk_score=result.risk_score,
                    tags=list(result.tags),
                    reasons=list(result.reasons),
                    timed_out=result.timed_out,
                    cache_hit=False,
                    duration_ms=result.duration_ms,
                ),
            )
            self._cache.move_to_end(key)
            while len(self._cache) > self.max_cache_entries:
                self._cache.popitem(last=False)

    def _classify_sync(self, text: str) -> tuple[float, list[str], list[str]]:
        if self.artificial_delay_ms > 0:
            time.sleep(self.artificial_delay_ms / 1000.0)

        norm = self._normalize_text(text)
        if not norm:
            return 0.0, [], []

        tags: list[str] = []
        reasons: list[str] = []
        risk = 0.0

        if self._injection_re.search(norm):
            tags.append("semantic_injection")
            reasons.append("semantic_injection_intent")
            risk = max(risk, 0.76)
        if self._leak_re.search(norm):
            tags.append("semantic_leak")
            reasons.append("semantic_secret_or_prompt_leak")
            risk = max(risk, 0.9)
        if self._privilege_re.search(norm):
            tags.append("semantic_privilege")
            reasons.append("semantic_privilege_or_command")
            risk = max(risk, 0.86)

        if len(tags) >= 2:
            risk = min(1.0, risk + 0.06)

        if tags and self._discussion_re.search(norm):
            risk = max(0.0, risk * 0.72)
            reasons.append("semantic_discussion_context_reduction")

        return risk, sorted(set(tags)), reasons

    def analyze(self, text: str, timeout_ms: int) -> SemanticResult:
        start = time.perf_counter()
        timeout_s = max(0.001, int(timeout_ms) / 1000.0)
        norm = self._normalize_text(text)
        key = self._hash_text(norm)
        now = time.time()

        cached = self._cache_get(key, now=now)
        if cached:
            return SemanticResult(
                risk_score=cached.risk_score,
                tags=cached.tags,
                reasons=cached.reasons,
                timed_out=False,
                cache_hit=True,
                duration_ms=(time.perf_counter() - start) * 1000.0,
            )

        future = self._executor.submit(self._classify_sync, norm)
        try:
            risk, tags, reasons = future.result(timeout=timeout_s)
            result = SemanticResult(
                risk_score=max(0.0, min(1.0, float(risk))),
                tags=tags,
                reasons=reasons,
                timed_out=False,
                cache_hit=False,
                duration_ms=(time.perf_counter() - start) * 1000.0,
            )
            self._cache_set(key, result, now=now)
            return result
        except TimeoutError:
            return SemanticResult(
                risk_score=0.0,
                tags=[],
                reasons=["semantic_timeout"],
                timed_out=True,
                cache_hit=False,
                duration_ms=(time.perf_counter() - start) * 1000.0,
            )


class SemanticServiceClient:
    """Async semantic service client with cache + timeout + circuit breaker."""

    def __init__(
        self,
        *,
        service_url: str,
        cache_ttl_seconds: int = 300,
        max_cache_entries: int = 5000,
        failure_threshold: int = 3,
        open_seconds: int = 30,
    ) -> None:
        self.service_url = service_url.strip()
        self.cache_ttl_seconds = max(1, int(cache_ttl_seconds))
        self.max_cache_entries = max(100, int(max_cache_entries))
        self.failure_threshold = max(1, int(failure_threshold))
        self.open_seconds = max(1, int(open_seconds))

        self._cache: OrderedDict[str, tuple[float, SemanticResult]] = OrderedDict()
        self._cache_lock = Lock()

        self._failure_count = 0
        self._open_until = 0.0
        self._half_open_probe_inflight = False
        self._breaker_lock = Lock()

        self._client: httpx.AsyncClient | None = None
        self._client_lock = Lock()

    @staticmethod
    def _normalize_text(text: str) -> str:
        return re.sub(r"\s+", " ", text.strip().lower())

    @staticmethod
    def _hash_text(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def _cache_get(self, key: str, now: float) -> SemanticResult | None:
        with self._cache_lock:
            item = self._cache.get(key)
            if not item:
                return None
            expires_at, cached = item
            if expires_at <= now:
                self._cache.pop(key, None)
                return None
            self._cache.move_to_end(key)
            return SemanticResult(
                risk_score=cached.risk_score,
                tags=list(cached.tags),
                reasons=list(cached.reasons),
                timed_out=cached.timed_out,
                cache_hit=True,
                duration_ms=cached.duration_ms,
            )

    def _cache_set(self, key: str, result: SemanticResult, now: float) -> None:
        # Do not cache timeout/error-like results.
        if result.timed_out or any(reason in {"semantic_service_error", "semantic_service_unavailable"} for reason in result.reasons):
            return
        expires_at = now + float(self.cache_ttl_seconds)
        with self._cache_lock:
            self._cache[key] = (
                expires_at,
                SemanticResult(
                    risk_score=result.risk_score,
                    tags=list(result.tags),
                    reasons=list(result.reasons),
                    timed_out=result.timed_out,
                    cache_hit=False,
                    duration_ms=result.duration_ms,
                ),
            )
            self._cache.move_to_end(key)
            while len(self._cache) > self.max_cache_entries:
                self._cache.popitem(last=False)

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is not None:
            return self._client
        with self._client_lock:
            if self._client is None:
                self._client = httpx.AsyncClient(http2=False)
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _acquire_breaker_permission(self, now: float) -> tuple[bool, bool]:
        """
        Returns:
            allowed: whether request can proceed
            half_open_probe: whether this call is the half-open probe
        """
        with self._breaker_lock:
            if now < self._open_until:
                return False, False

            if self._open_until > 0:
                if self._half_open_probe_inflight:
                    return False, False
                self._half_open_probe_inflight = True
                return True, True

            return True, False

    def _mark_success(self) -> None:
        with self._breaker_lock:
            self._failure_count = 0
            self._open_until = 0.0
            self._half_open_probe_inflight = False

    def _mark_failure(self, now: float) -> None:
        with self._breaker_lock:
            self._failure_count += 1
            self._half_open_probe_inflight = False
            if self._failure_count >= self.failure_threshold:
                self._open_until = now + float(self.open_seconds)
                logger.warning(
                    "semantic circuit opened failures=%d open_seconds=%d",
                    self._failure_count,
                    self.open_seconds,
                )

    async def analyze(self, text: str, timeout_ms: int) -> SemanticResult:
        start = time.perf_counter()
        timeout_s = max(0.001, int(timeout_ms) / 1000.0)
        norm = self._normalize_text(text)
        if not norm:
            return SemanticResult(
                risk_score=0.0,
                tags=[],
                reasons=[],
                timed_out=False,
                cache_hit=False,
                duration_ms=(time.perf_counter() - start) * 1000.0,
            )

        if not self.service_url:
            return SemanticResult(
                risk_score=0.0,
                tags=[],
                reasons=["semantic_service_unconfigured"],
                timed_out=False,
                cache_hit=False,
                duration_ms=(time.perf_counter() - start) * 1000.0,
            )

        key = self._hash_text(norm)
        now = time.time()
        cached = self._cache_get(key, now=now)
        if cached:
            logger.debug("semantic cache hit")
            return SemanticResult(
                risk_score=cached.risk_score,
                tags=cached.tags,
                reasons=cached.reasons,
                timed_out=cached.timed_out,
                cache_hit=True,
                duration_ms=(time.perf_counter() - start) * 1000.0,
            )

        allowed, _half_open_probe = self._acquire_breaker_permission(now=now)
        if not allowed:
            logger.debug("semantic circuit open reject")
            return SemanticResult(
                risk_score=0.0,
                tags=[],
                reasons=["semantic_circuit_open"],
                timed_out=False,
                cache_hit=False,
                duration_ms=(time.perf_counter() - start) * 1000.0,
            )

        try:
            client = self._get_client()
            response = await client.post(
                self.service_url,
                json={"text": norm},
                timeout=timeout_s,
            )
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict):
                raise ValueError("semantic_service_invalid_payload")

            risk_score = max(0.0, min(1.0, float(payload.get("risk_score", 0.0))))
            raw_tags = payload.get("tags", [])
            raw_reasons = payload.get("reasons", [])
            tags = sorted({str(item) for item in raw_tags if str(item).strip()})
            reasons = [str(item) for item in raw_reasons if str(item).strip()]

            result = SemanticResult(
                risk_score=risk_score,
                tags=tags,
                reasons=reasons,
                timed_out=False,
                cache_hit=False,
                duration_ms=(time.perf_counter() - start) * 1000.0,
            )
            self._cache_set(key, result, now=now)
            self._mark_success()
            logger.debug("semantic service success risk=%.4f tags=%s", result.risk_score, result.tags)
            return result
        except httpx.TimeoutException:
            self._mark_failure(now=time.time())
            logger.warning("semantic service timeout timeout_ms=%d", timeout_ms)
            return SemanticResult(
                risk_score=0.0,
                tags=[],
                reasons=["semantic_timeout"],
                timed_out=True,
                cache_hit=False,
                duration_ms=(time.perf_counter() - start) * 1000.0,
            )
        except Exception:
            self._mark_failure(now=time.time())
            logger.warning("semantic service unavailable")
            return SemanticResult(
                risk_score=0.0,
                tags=[],
                reasons=["semantic_service_unavailable"],
                timed_out=False,
                cache_hit=False,
                duration_ms=(time.perf_counter() - start) * 1000.0,
            )
