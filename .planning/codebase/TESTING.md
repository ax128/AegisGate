# Testing Patterns

**Analysis Date:** 2026-03-27

## Test Framework

**Runner:**
- `pytest` via the `dev` extra in `pyproject.toml`
- Config: `pyproject.toml`

**Assertion Library:**
- Native `assert` statements with `pytest`

**Run Commands:**
```bash
pytest -q                                              # Run all tests
pytest -q aegisgate/tests/test_gateway_boundary_access.py  # Run a focused suite
pytest --cov=aegisgate --cov-report=xml --cov-report=term-missing -v  # Coverage
```
- `README.md` also documents `pytest -q`.
- `.github/workflows/ci.yml` runs `pytest -v` on Python 3.10 and 3.13, and coverage on Python 3.12.

## Test File Organization

**Location:**
- All detected tests live under `aegisgate/tests`.
- Tests are mostly module-local and self-contained; a shared `conftest.py` is not detected under `aegisgate/tests`.

**Naming:**
- Use `test_*.py` filenames, usually aligned to a subsystem or behavior:
  - `aegisgate/tests/test_gateway_auth.py`
  - `aegisgate/tests/test_hot_reload_unit.py`
  - `aegisgate/tests/test_v2_proxy_router.py`

**Structure:**
```text
aegisgate/tests/
├── test_gateway_*.py
├── test_*_router.py
├── test_*_guard.py
├── test_pipeline*.py
└── test_*.py
```

## Test Structure

**Suite Organization:**
```python
class TestHotReloader:
    def test_start_stop(self) -> None:
        hr = HotReloader(poll_seconds=1.0)

        async def run():
            await hr.start()
            assert hr._task is not None
            await hr.stop()
            assert hr._task is None

        asyncio.run(run())
```
- This class-based grouping pattern appears in `aegisgate/tests/test_hot_reload_unit.py` and `aegisgate/tests/test_gateway_auth.py`.
- Flat function-based tests are also common for single-behavior modules, such as `aegisgate/tests/test_pipeline.py` and `aegisgate/tests/test_openai_pipeline_runtime.py`.

**Patterns:**
- Build lightweight request objects manually instead of spinning up a full app server. See `_build_request()` in `aegisgate/tests/test_gateway_boundary_access.py` and `_make_request()` in `aegisgate/tests/test_v2_proxy_router.py`.
- Keep test helpers in the same file as the tests that use them. Examples: `_response_json()` in `aegisgate/tests/test_gateway_register.py`, `_collect_execute_stream()` in `aegisgate/tests/test_streaming_router.py`.
- Use `@pytest.mark.asyncio` for async tests that await production coroutines directly, especially in gateway and routing tests.
- Use `asyncio.run(...)` inside sync tests when a small async path is easier to exercise inline, as in `aegisgate/tests/test_v2_proxy_router.py` and `aegisgate/tests/test_streaming_router.py`.

## Mocking

**Framework:** `pytest.monkeypatch` plus `unittest.mock`

**Patterns:**
```python
monkeypatch.setattr(
    gateway,
    "observe_request_duration",
    lambda route, seconds: durations.append((route, seconds)),
)
```
from `aegisgate/tests/test_gateway_observability_request.py`

```python
with patch("aegisgate.core.gateway_auth.settings") as mock_settings:
    mock_settings.gateway_key = "test-secret-key"
    assert _verify_admin_gateway_key({"gateway_key": "test-secret-key"}) is True
```
from `aegisgate/tests/test_gateway_auth.py`

```python
class _FakeRequestClient:
    async def request(self, **kwargs):
        if isinstance(self.response, Exception):
            raise self.response
        return self.response
```
from `aegisgate/tests/test_v2_proxy_router.py`

**What to Mock:**
- Runtime settings and global singletons, using `monkeypatch.setattr(...)` on modules like `aegisgate.core.gateway` and `aegisgate.config.settings`.
- External boundaries such as `httpx` clients, DNS resolution, tracing, metrics, audit sinks, and file-backed stores. Representative tests: `aegisgate/tests/test_v2_proxy_router.py`, `aegisgate/tests/test_gateway_observability_startup.py`, `aegisgate/tests/test_passthrough_filter_mode.py`.
- Internal helper functions when isolating a route or middleware branch, for example replacing `_run_request_pipeline` and `_run_response_pipeline` in `aegisgate/tests/test_streaming_router.py`.

**What NOT to Mock:**
- Pure filter logic and internal transport models when the goal is behavior coverage. Examples: `aegisgate/tests/test_pipeline.py`, `aegisgate/tests/test_openai_pipeline_runtime.py`, `aegisgate/tests/test_crypto_extended.py`.
- Validation and error payload shaping when the production function can be called directly with a synthetic request object.

## Fixtures and Factories

**Test Data:**
```python
@pytest.fixture(autouse=True)
def _set_gateway_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gateway.settings, "gateway_key", "agent")
```
from `aegisgate/tests/test_gateway_register.py`

```python
@pytest.fixture()
def fernet_env_key():
    key = Fernet.generate_key().decode()
    with patch.dict(os.environ, {"AEGIS_ENCRYPTION_KEY": key}):
        crypto._fernet_instance = None
        yield key
```
from `aegisgate/tests/test_crypto_extended.py`

**Location:**
- Fixtures are defined inline within the test module that needs them.
- Temporary filesystem setup uses `tmp_path` heavily, especially in `aegisgate/tests/test_config_source_convergence.py`, `aegisgate/tests/test_hot_reload_unit.py`, and crypto tests.
- Simple factories are private helpers prefixed with `_`, for example `_build_request()`, `_make_request()`, `_patch_client()`, and `_patch_resolve()`.

## Coverage

**Requirements:** `50%` minimum configured in `pyproject.toml`

**View Coverage:**
```bash
pytest --cov=aegisgate --cov-report=xml --cov-report=term-missing -v
```
- `pyproject.toml` sets `source = ["aegisgate"]` and omits `aegisgate/tests/*`.
- CI uploads `coverage.xml` from `.github/workflows/ci.yml`.

## Test Types

**Unit Tests:**
- Dominant style.
- Exercise pure helpers, filters, config loading, storage logic, and small orchestration units directly by importing functions/classes.
- Examples: `aegisgate/tests/test_pipeline.py`, `aegisgate/tests/test_logger_module.py`, `aegisgate/tests/test_config_source_convergence.py`.

**Integration Tests:**
- Present as narrow in-process integration tests rather than end-to-end suites.
- Common pattern: build a synthetic `Request`, invoke a FastAPI handler or middleware directly, and assert the `JSONResponse` or `StreamingResponse`.
- Examples: `aegisgate/tests/test_gateway_boundary_access.py`, `aegisgate/tests/test_gateway_register.py`, `aegisgate/tests/test_streaming_router.py`.

**E2E Tests:**
- Not detected.
- No Playwright/Selenium/browser runner is configured.
- No tests using `fastapi.testclient.TestClient` or a live `uvicorn` process are detected in `aegisgate/tests`.

## Common Patterns

**Async Testing:**
```python
@pytest.mark.asyncio
async def test_boundary_blocks_non_token_v1_requests() -> None:
    request = _build_request("/v1/responses", token_authenticated=False, body={"input": "hello"})
    response = await gateway.security_boundary_middleware(request, _allow_next)
    assert response.status_code == 403
```
from `aegisgate/tests/test_gateway_boundary_access.py`

**Error Testing:**
```python
with pytest.raises(InvalidToken):
    crypto.decrypt_mapping(plain_b64)
```
from `aegisgate/tests/test_crypto_extended.py`

```python
assert body["error"]["code"] == "missing_target_url_header"
assert "scheme must be http/https" in body["error"]["message"]
```
from `aegisgate/tests/test_v2_proxy_router.py`

**Streaming Testing:**
```python
async def responses_stream() -> AsyncGenerator[bytes, None]:
    yield b'data: {"type":"response.output_text.delta",'
    yield b'"delta":"hello"}\\n'
    yield b"\\n"
```
- Streaming behavior is covered by collecting `StreamingResponse.body_iterator` and asserting SSE output in `aegisgate/tests/test_streaming_router.py`.

**Observability Testing:**
- Metrics and tracing are usually captured by monkeypatching sink functions into local lists rather than asserting real exporters. See `_capture_observability()` in `aegisgate/tests/test_gateway_observability_request.py`.

## Observed Gaps

- Shared builders and response helpers are duplicated across files such as `aegisgate/tests/test_gateway_boundary_access.py`, `aegisgate/tests/test_gateway_register.py`, and `aegisgate/tests/test_v2_proxy_router.py`; no common fixture layer exists.
- Full-stack HTTP tests are not detected. Current tests validate handlers and middleware directly, but they do not verify router wiring, middleware order, or static asset serving through a live FastAPI client.
- Log-output assertions are minimal. `aegisgate/tests/test_logger_module.py` checks logger utilities, but repository-wide use of structured log keys like `request_id` and `reason` is not systematically asserted.
- CI covers multiple Python versions, but no dedicated lint or type-check job is present in `.github/workflows/ci.yml`.
- Coverage threshold is modest at 50%, so important branches inside large modules like `aegisgate/adapters/openai_compat/router.py` and `aegisgate/core/gateway.py` may still go untested.

---

*Testing analysis: 2026-03-27*
