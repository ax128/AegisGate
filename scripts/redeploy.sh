#!/usr/bin/env bash
# Redeploy AegisGate with full cache bust and verification.
set -euo pipefail

echo "=== 1. Git pull ==="
git fetch origin
git pull origin main
echo "Latest commit: $(git log --oneline -1)"

echo ""
echo "=== 2. Verify key code changes ==="
echo "privilege_guard.py (should say logger.debug):"
grep -n "privilege-like response detected" aegisgate/filters/privilege_guard.py

echo ""
echo "injection_detector.py (should say logger.debug):"
grep -n "injection-like response detected" aegisgate/filters/injection_detector.py

echo ""
echo "settings.py (should have require_confirmation_on_block):"
grep -n "require_confirmation_on_block" aegisgate/config/settings.py

echo ""
echo "=== 3. Docker build (no cache) ==="
docker compose down
docker compose -f docker-compose.yml -f docker-compose.cliproxy.yml build --no-cache aegisgate

echo ""
echo "=== 4. Verify inside built image ==="
docker compose -f docker-compose.yml -f docker-compose.cliproxy.yml run --rm --no-deps --entrypoint "" aegisgate \
  grep -n "privilege-like response detected" /app/aegisgate/filters/privilege_guard.py

echo ""
echo "=== 5. Start services ==="
docker compose -f docker-compose.yml -f docker-compose.cliproxy.yml up -d

echo ""
echo "=== Done. Tailing logs... ==="
docker compose logs -f aegisgate
