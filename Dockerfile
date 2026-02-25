FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml README.md /app/
COPY aegisgate /app/aegisgate
# 首次启动时 init_config 会从本路径复制 .env 与策略 YAML 到挂载目录（若缺失）
COPY config/.env.example /app/config/.env.example

RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir . \
    && useradd --create-home --uid 10001 appuser \
    && mkdir -p /app/logs \
    && chown -R appuser:appuser /app

USER appuser

EXPOSE 18080

CMD ["uvicorn", "aegisgate.core.gateway:app", "--host", "0.0.0.0", "--port", "18080"]
