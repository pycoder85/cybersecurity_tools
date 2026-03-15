#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN="${PYTHON_BIN:-python3.11}"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "Expected $PYTHON_BIN on PATH." >&2
  exit 1
fi

"$PYTHON_BIN" -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -e ".[dev]"

cat <<'EOF'

Driftwatch bootstrap complete.

Next steps:
  source .venv/bin/activate
  driftwatch serve --demo-data

EOF
