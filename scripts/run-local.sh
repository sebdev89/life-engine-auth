#!/usr/bin/env bash
# One-shot local runner. Loads .env.local then starts Spring Boot.
# Equivalent to: set -a && source scripts/load-env-local.sh && set +a && mvn spring-boot:run
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
set -a
# shellcheck disable=SC1091
source "$ROOT/scripts/load-env-local.sh"
set +a
cd "$ROOT"
exec mvn spring-boot:run "$@"
