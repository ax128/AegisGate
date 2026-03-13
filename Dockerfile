FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AEGIS_INIT_STRICT=true \
    AEGIS_BOOTSTRAP_RULES_DIR=/app/bootstrap/rules

WORKDIR /app

COPY pyproject.toml README.md /app/
# 快速上手与使用说明文档，供内置 UI 文档页展示
COPY *-QUICKSTART.md OTHER_TERMINAL_CLIENTS_USAGE.md OPENCLAW_INJECT_PROXY_FETCH.md SKILL.md /app/
COPY aegisgate /app/aegisgate
# 首次启动时 init_config 会从本路径复制 .env 与策略 YAML 到挂载目录（若缺失）
COPY config/.env.example /app/config/.env.example
# 镜像内保留一份只读策略模板，避免 rules 目录被 volume 挂载覆盖后无法回填
COPY aegisgate/policies/rules /app/bootstrap/rules

COPY aegisgate/models /app/aegisgate/models
COPY www /app/www

RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir ".[semantic]" \
    && useradd --create-home --uid 10001 appuser \
    && mkdir -p /app/logs \
    && chown -R appuser:appuser /app

USER appuser

EXPOSE 18080

CMD ["sh", "-c", "python -m aegisgate.init_config && uvicorn aegisgate.core.gateway:app --host 0.0.0.0 --port 18080"]
