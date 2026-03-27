# Technology Stack

**Analysis Date:** 2026-03-27

## Languages

**Primary:**
- Python 3.10+ - main application code, adapters, filters, storage backends, and scripts under `aegisgate/` and `scripts/`

**Secondary:**
- YAML - policy and security rule sources under `aegisgate/policies/rules/` and runtime-mounted config under `config/security_filters.yaml`
- JSON - token/model mapping and persisted stats in `config/gw_tokens.json`, `config/model_map.json`, and `config/stats.json`
- HTML/CSS/JS - built-in local admin UI assets under `www/`
- Shell - deployment helpers such as `scripts/caddy-entrypoint.sh` and container startup in `Dockerfile`

## Runtime

**Environment:**
- CPython 3.10+ required by `pyproject.toml`
- Docker image uses Python 3.11 slim in `Dockerfile`
- CI validates Python 3.10, 3.12, and 3.13 in `.github/workflows/ci.yml`

**Package Manager:**
- `pip` + setuptools build backend from `pyproject.toml`
- Editable installs are the primary workflow: `python -m pip install -e .`, `python -m pip install -e .[dev]`, `python -m pip install -e .[dev,semantic]`
- Lockfile: missing; no `uv.lock`, `poetry.lock`, or `requirements.txt` detected at repo root

## Frameworks

**Core:**
- FastAPI - HTTP gateway app and route composition in `aegisgate/core/gateway.py`
- Pydantic v2 + `pydantic-settings` - typed runtime settings and internal models in `aegisgate/config/settings.py` and `aegisgate/core/models.py`
- httpx - async upstream HTTP client for `/v1` and `/v2` forwarding in `aegisgate/adapters/openai_compat/upstream.py` and `aegisgate/adapters/v2_proxy/router.py`

**Testing:**
- `pytest` - test runner configured in `pyproject.toml`
- `pytest-asyncio`, `pytest-timeout`, `pytest-cov` - async tests, timeouts, and coverage from `pyproject.toml`

**Build/Dev:**
- Uvicorn - ASGI server entrypoint used in `Dockerfile`, `README.md`, and `scripts/local_launcher.py`
- Docker Compose - default local/prod-ish deployment path in `docker-compose.yml`
- GitHub Actions - CI test matrix in `.github/workflows/ci.yml`

## Key Dependencies

**Critical:**
- `fastapi>=0.115.0` - public gateway API, admin UI routes, and middleware wiring in `aegisgate/core/gateway.py`
- `httpx>=0.27.0` - upstream request forwarding, SSE streaming, and semantic service calls in `aegisgate/adapters/openai_compat/upstream.py`, `aegisgate/adapters/v2_proxy/router.py`, and `aegisgate/core/semantic.py`
- `pydantic>=2.8.0` and `pydantic-settings>=2.4.0` - typed config and request/response models in `aegisgate/config/settings.py` and `aegisgate/core/models.py`
- `pyyaml>=6.0.0` - policy/rule loading in `aegisgate/config/security_rules.py` and `aegisgate/policies/policy_engine.py`
- `cryptography>=42.0.0` - Fernet-based encrypted mapping storage in `aegisgate/storage/crypto.py`

**Infrastructure:**
- `redis>=5.0.0` optional extra - Redis KV store and nonce replay cache in `aegisgate/storage/redis_store.py` and `aegisgate/core/security_boundary.py`
- `psycopg[binary]>=3.1.0` optional extra - PostgreSQL KV store in `aegisgate/storage/postgres_store.py`
- `scikit-learn>=1.3.0`, `jieba>=0.42.0`, `joblib>=1.3.0` optional `semantic` extra - built-in TF-IDF semantic classifier and training flow in `aegisgate/core/semantic.py`, `aegisgate/core/tfidf_model.py`, and `scripts/train_tfidf.py`
- `prometheus-client>=0.20.0` optional `observability` extra - `/metrics` endpoint in `aegisgate/observability/metrics.py`
- `opentelemetry-*>=1.24.0` optional `observability` extra - tracing bootstrap in `aegisgate/observability/tracing.py`

## Configuration

**Environment:**
- Use `AEGIS_*` env vars defined by `aegisgate/config/settings.py`
- File-based runtime config is `config/.env`; `Settings` reads it directly via `env_file="config/.env"` in `aegisgate/config/settings.py`
- Treat `config/.env` as the only file-based runtime config entrypoint; `config/README.md` explicitly says repo-root `.env` is not used
- Required runtime-writable secret/key files are generated on first boot in `config/aegis_gateway.key`, `config/aegis_proxy_token.key`, and `config/aegis_fernet.key`; these are runtime data, not source-controlled configuration
- Security policies bootstrap from `aegisgate/policies/rules/` and are copied into `config/` by `aegisgate/init_config.py`

**Build:**
- Python package/build metadata lives in `pyproject.toml`
- Container image build and app bootstrap are defined in `Dockerfile`
- Default deployment topology is defined in `docker-compose.yml`
- CI install/test behavior is defined in `.github/workflows/ci.yml`

## Platform Requirements

**Development:**
- Python 3.10+ with `venv` support for `scripts/local_launcher.py`
- Writable `config/` and `logs/` directories; `aegisgate/init_config.py` falls back to `/tmp/aegisgate` for some runtime paths when needed
- For semantic mode, install the `semantic` extra so bundled TF-IDF assets in `aegisgate/models/tfidf/` can be used
- For Redis/Postgres storage, install the matching extras and provide `AEGIS_REDIS_URL` or `AEGIS_POSTGRES_DSN`

**Production:**
- Self-hosted ASGI service served by Uvicorn from `aegisgate.core.gateway:app`
- Default containerized deployment uses `docker-compose.yml`, binds `127.0.0.1:18080`, mounts `./config` and `./logs`, and joins external Docker networks `cliproxy_net` and `sub2api_net`
- Production edge TLS/reverse proxy is expected outside the app; `README.md` recommends Caddy or nginx, and `scripts/caddy-entrypoint.sh` supports a Caddy sidecar using `config/aegis_proxy_token.key`

## Protocol and Adapter Surface

**OpenAI-compatible v1:**
- Main API surface lives in `aegisgate/adapters/openai_compat/router.py`
- Implemented routes include `/v1/chat/completions`, `/v1/responses`, `/v1/messages`, and generic `/v1/{subpath}` via `aegisgate/core/gateway.py`

**Generic HTTP v2 proxy:**
- Independent proxy/filter chain lives in `aegisgate/adapters/v2_proxy/router.py`
- `/v2` and `/v2/{proxy_path}` are mounted when `enable_v2_proxy` is true in `aegisgate/core/gateway.py`

**Relay compatibility:**
- Optional relay adapter in `aegisgate/adapters/relay_compat/router.py`
- `/relay/generate` is mounted only when `AEGIS_ENABLE_RELAY_ENDPOINT=true`

**Protocol bridge:**
- Anthropic Messages to OpenAI Responses conversion is implemented in `aegisgate/adapters/openai_compat/compat_bridge.py`, `aegisgate/adapters/openai_compat/mapper.py`, and token compat data in `config/gw_tokens.json`
- Global model remapping for compat mode comes from `config/model_map.json`

## Runtime Entry Points

**Application:**
- `aegisgate/core/gateway.py` - FastAPI assembly module and main import target
- `python -m aegisgate.init_config` - bootstrap config, writable paths, and policy files from `aegisgate/init_config.py`

**Local development:**
- `scripts/local_launcher.py` - create `.venv`, install extras, run bootstrap, and start Uvicorn in foreground/background

**Container startup:**
- `Dockerfile` command runs `python -m aegisgate.init_config && uvicorn aegisgate.core.gateway:app --host 0.0.0.0 --port 18080`

---

*Stack analysis: 2026-03-27*
