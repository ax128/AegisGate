FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AEGIS_INIT_STRICT=true \
    AEGIS_BOOTSTRAP_RULES_DIR=/app/bootstrap/rules

WORKDIR /app

COPY pyproject.toml README.md /app/
# Every Markdown doc at the repo root, shown on the built-in UI docs page (_EXCLUDED_ROOT_DOCS controls which are hidden)
COPY *.md /app/
COPY aegisgate /app/aegisgate
# On first start, init_config copies .env and the policy YAML from this path into the mounted directory (when missing)
COPY config/.env.example /app/config/.env.example
# Keep a read-only policy template inside the image, so a volume mount over the rules directory can still be refilled
COPY aegisgate/policies/rules /app/bootstrap/rules

COPY aegisgate/models /app/aegisgate/models
COPY www /app/www

RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir ".[semantic]" \
    && useradd --create-home --uid 10001 appuser \
    && mkdir -p /app/logs \
    && chown -R appuser:appuser /app

USER appuser

# Documentation only — it does not publish anything and does not follow AEGIS_PORT.
# Change the compose `ports:`/`expose:` entries when you change AEGIS_PORT.
EXPOSE 18080

# The port follows AEGIS_PORT so a compose override actually moves the listener.
# It used to be hard-coded, which meant setting AEGIS_PORT (as the docs told you
# to) left uvicorn on 18080 while the published mapping pointed at nothing — and
# the console still rendered client Base URLs using the AEGIS_PORT value.
# The bind address stays 0.0.0.0: inside a container the network boundary is the
# published port mapping, not the listener, and AEGIS_HOST defaults to 127.0.0.1
# — honouring it here would make a stock `.env` produce an unreachable container.
CMD ["sh", "-c", "python -m aegisgate.init_config && exec uvicorn aegisgate.core.gateway:app --host 0.0.0.0 --port \"${AEGIS_PORT:-18080}\""]
