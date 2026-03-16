#!/usr/bin/env sh
set -eu

export DRIFTWATCH_HOST="${DRIFTWATCH_HOST:-0.0.0.0}"
export DRIFTWATCH_PORT="${DRIFTWATCH_PORT:-8484}"
export DRIFTWATCH_HOME="${DRIFTWATCH_HOME:-/data}"

exec driftwatch serve --demo-data
