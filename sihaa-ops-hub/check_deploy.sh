#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Sihha Ops Hub — Post-deploy health check
# Run after Railway finishes deploying to verify the app is live.
#
# Usage:  bash check_deploy.sh [BASE_URL]
# Default BASE_URL: https://sihha-ops-hub-production.up.railway.app
#
# Requires ADMIN_PASSWORD env var to be set for login check.
# ─────────────────────────────────────────────────────────────
set -euo pipefail

BASE_URL="${1:-https://sihha-ops-hub-production.up.railway.app}"
ADMIN_PASS="${ADMIN_PASSWORD:-}"

echo ""
echo "══════════════════════════════════════════════════"
echo "  Sihha Ops Hub — Post-deploy health check"
echo "  Target: $BASE_URL"
echo "══════════════════════════════════════════════════"

PASS=0
FAIL=0

check() {
    local label="$1"
    local cmd="$2"
    printf "  %-40s" "$label..."
    if eval "$cmd" &>/dev/null; then
        echo "✓"
        PASS=$((PASS + 1))
    else
        echo "✗  FAILED"
        FAIL=$((FAIL + 1))
    fi
}

# ── 1. API health ─────────────────────────────────────────────
check "[1/5] GET /api/health → ok" \
    "curl -sf '${BASE_URL}/api/health' | python3 -c \"import sys,json; d=json.load(sys.stdin); sys.exit(0 if d.get('status')=='ok' else 1)\""

# ── 2. Donate-stats ───────────────────────────────────────────
check "[2/5] GET /api/donate-stats" \
    "curl -sf '${BASE_URL}/api/donate-stats'"

# ── 3. Login page ─────────────────────────────────────────────
check "[3/5] GET /login (page loads)" \
    "curl -sf '${BASE_URL}/login'"

# ── 4. Admin portal page ──────────────────────────────────────
check "[4/5] GET / (admin SPA loads)" \
    "curl -sf '${BASE_URL}/'"

# ── 5. Admin login ────────────────────────────────────────────
if [[ -n "$ADMIN_PASS" ]]; then
    check "[5/5] POST /api/auth/login (admin)" \
        "curl -sf -X POST '${BASE_URL}/api/auth/login' \
          -H 'Content-Type: application/json' \
          -d '{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}' \
          | python3 -c \"import sys,json; d=json.load(sys.stdin); sys.exit(0 if 'token' in d else 1)\""
else
    echo "  [5/5] Admin login check skipped (ADMIN_PASSWORD not set)"
fi

echo ""
echo "──────────────────────────────────────────────────"
if [[ $FAIL -eq 0 ]]; then
    echo "  ✓  All health checks passed ($PASS/$PASS)."
else
    echo "  ✗  $FAIL check(s) FAILED. Investigate Railway logs."
    exit 1
fi
echo ""
