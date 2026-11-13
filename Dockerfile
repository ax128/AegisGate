FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AEGIS_INIT_STRICT=true \
    AEGIS_BOOTSTRAP_RULES_DIR=/app/bootstrap/rules

WORKDIR /app

# Dependency layer. Copy only project metadata so a source edit does not
# rebuild wheels. There is no lockfile: base dependencies and the semantic
# extra are read from pyproject.toml. The project itself is installed after
# the source copy below, without reinstalling those dependencies, so the
# process still imports the installed package the way it does today.
COPY pyproject.toml /app/pyproject.toml
RUN python -m pip install --no-cache-dir --upgrade pip \
    && printf '%s\n' \
        'import subprocess' \
        'import sys' \
        'import tomllib' \
        'from pathlib import Path' \
        'project = tomllib.loads(Path("/app/pyproject.toml").read_text(encoding="utf-8"))["project"]' \
        'deps = list(project["dependencies"])' \
        'deps.extend(project["optional-dependencies"]["semantic"])' \
        'subprocess.check_call([sys.executable, "-m", "pip", "install", "--no-cache-dir", *deps])' \
        > /tmp/install-aegisgate-deps.py \
    && python /tmp/install-aegisgate-deps.py \
    && rm -f /tmp/install-aegisgate-deps.py

# Operator guides the console may serve. Allow-list: _UI_DOCS in
# aegisgate/core/gateway_ui_config.py. Root markdown that is not on that
# list stays out of the image.
COPY README.md \
    README_zh.md \
    WEBUI-QUICKSTART.md \
    UPSTREAM-QUICKSTART.md \
    OTHER_TERMINAL_CLIENTS_USAGE.md \
    SKILL.md \
    /app/
COPY aegisgate /app/aegisgate
# On first start, init_config copies .env and the policy YAML from this path into the mounted directory (when missing)
COPY config/.env.example /app/config/.env.example
# Keep a read-only policy template inside the image, so a volume mount over the rules directory can still be refilled
COPY aegisgate/policies/rules /app/bootstrap/rules

COPY aegisgate/models /app/aegisgate/models
COPY www /app/www

RUN python -m pip install --no-cache-dir --no-deps ".[semantic]" \
    && rm -rf /app/build /app/*.egg-info \
    && useradd --create-home --uid 10001 appuser \
    && mkdir -p /app/logs \
    && chown -R appuser:appuser /app

USER appuser

# Documentation only — it does not publish anything and does not follow AEGIS_PORT.
# Change the compose `ports:`/`expose:` entries when you change AEGIS_PORT.
EXPOSE 18080

# Liveness, not readiness: /health answers during startup, /ready does not.
# The port follows AEGIS_PORT, same as the command below. python:3.11-slim has
# no curl, so the probe uses the stdlib client.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["python", "-c", "import os, urllib.request; port = os.environ.get('AEGIS_PORT', '18080'); urllib.request.urlopen('http://127.0.0.1:' + port + '/health', timeout=4)"]

# The port follows AEGIS_PORT so a compose override actually moves the listener.
# It used to be hard-coded, which meant setting AEGIS_PORT (as the docs told you
# to) left uvicorn on 18080 while the published mapping pointed at nothing — and
# the console still rendered client Base URLs using the AEGIS_PORT value.
# The bind address stays 0.0.0.0: inside a container the network boundary is the
# published port mapping, not the listener, and AEGIS_HOST defaults to 127.0.0.1
# — honouring it here would make a stock `.env` produce an unreachable container.
# --no-proxy-headers: the gateway reads the real peer and applies AEGIS_TRUSTED_PROXY_IPS
# itself. uvicorn's own handling would otherwise rewrite the peer and scheme from
# X-Forwarded-For / -Proto for any address in FORWARDED_ALLOW_IPS (127.0.0.1 by default,
# and settable from the compose env_file) before the gateway sees the request.
CMD ["sh", "-c", "python -m aegisgate.init_config && exec uvicorn aegisgate.core.gateway:app --host 0.0.0.0 --port \"${AEGIS_PORT:-18080}\" --no-proxy-headers"]
