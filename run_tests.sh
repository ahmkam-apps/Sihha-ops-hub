#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Sihha Ops Hub — Pre-push test gate
# Run this BEFORE every git push. Push is blocked on failure.
#
# Usage:  bash run_tests.sh
# ─────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo "══════════════════════════════════════════════════"
echo "  Sihha Ops Hub — Pre-push checks"
echo "══════════════════════════════════════════════════"

# ── 1. Python syntax check ────────────────────────────────────
echo ""
echo "[1/3] Syntax check (all .py files)..."
SYNTAX_ERRORS=0
while IFS= read -r -d '' f; do
    python3 -m py_compile "$f" 2>/dev/null || {
        echo "  ✗  Syntax error: $f"
        SYNTAX_ERRORS=$((SYNTAX_ERRORS + 1))
    }
done < <(find . -name "*.py" -not -path "./.git/*" -not -path "./venv/*" -print0)

if [[ $SYNTAX_ERRORS -gt 0 ]]; then
    echo "  FAILED — $SYNTAX_ERRORS file(s) with syntax errors."
    exit 1
fi
echo "  ✓  No syntax errors"

# ── 2. Install test dependencies (if needed) ──────────────────
echo ""
echo "[2/3] Installing test dependencies..."
pip install --quiet pytest werkzeug flask --break-system-packages 2>/dev/null || true

# ── 3. Run pytest ─────────────────────────────────────────────
echo ""
echo "[3/3] Running pytest..."
echo "──────────────────────────────────────────────────"
python -m pytest tests/ -v --tb=short 2>&1
echo "──────────────────────────────────────────────────"

echo ""
echo "  ✓  All checks passed. Safe to push."
echo ""
