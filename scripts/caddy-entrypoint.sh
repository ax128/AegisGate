#!/bin/sh
# Read auto-generated proxy token from shared config volume.
# AegisGate generates this file on first boot; Caddy injects it into
# X-Aegis-Proxy-Token header so the gateway auto-authenticates requests.
TOKEN_FILE="/config/aegis_proxy_token.key"

# Wait for AegisGate to generate the token (depends_on only waits for start).
for i in 1 2 3 4 5; do
    [ -f "$TOKEN_FILE" ] && break
    echo "caddy-entrypoint: waiting for $TOKEN_FILE ..."
    sleep 1
done

if [ -f "$TOKEN_FILE" ]; then
    export AEGIS_PROXY_TOKEN
    AEGIS_PROXY_TOKEN=$(cat "$TOKEN_FILE")
    echo "caddy-entrypoint: proxy token loaded"
else
    export AEGIS_PROXY_TOKEN=""
    echo "caddy-entrypoint: WARNING - $TOKEN_FILE not found, proxy token disabled"
fi

exec caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
