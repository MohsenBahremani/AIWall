#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# shellcheck source=load_dotenv.sh
source "${ROOT}/scripts/load_dotenv.sh"

export AIWALL_CONFIG="${AIWALL_CONFIG:-${ROOT}/aiwall.yaml}"
if [[ ! -f "$AIWALL_CONFIG" ]]; then
  AIWALL_CONFIG="${ROOT}/aiwall.yaml.example"
  echo "Using example config: $AIWALL_CONFIG"
  echo "Copy to aiwall.yaml to customize (cp aiwall.yaml.example aiwall.yaml)"
fi
if [[ ! -f "${ROOT}/prices.yaml" && -f "${ROOT}/prices.yaml.example" ]]; then
  echo "Tip: copy prices.yaml.example to prices.yaml for cost estimation"
fi
export AIWALL_CONFIG
export PYTHONPATH="${ROOT}/backend${PYTHONPATH:+:$PYTHONPATH}"

exec uvicorn app.main:app \
  --host 0.0.0.0 \
  --port "${AIWALL_PORT:-8080}" \
  --reload
