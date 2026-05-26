#!/usr/bin/env bash
# Source from life-engine-auth repo root: set -a && source scripts/load-env-local.sh && set +a
# Mirrors life-engine/scripts/load-env-local.sh.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENVF="${LIFE_ENGINE_AUTH_ENV_FILE:-$ROOT/.env.local}"
if [[ -f "$ENVF" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENVF"
  set +a
else
  echo "warn: missing $ENVF — copy .env.template to .env.local or export vars manually." >&2
fi
