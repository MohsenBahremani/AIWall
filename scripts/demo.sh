#!/usr/bin/env bash
# Demo AIWall proxy + policy enforcement against a running instance (Phase 1.10a).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# shellcheck source=load_dotenv.sh
source "${ROOT}/scripts/load_dotenv.sh"

BASE_URL="${AIWALL_BASE_URL:-http://127.0.0.1:${AIWALL_PORT:-8080}}"
DB_PATH="${AIWALL_DB:-${ROOT}/data/aiwall.db}"
# Fake AWS key that is NOT the AWS docs placeholder (those are ignored when
# scanners.ignore_examples is true).
SECRET_SAMPLE="${AIWALL_DEMO_SECRET:-AKIADEMOAIWALLTEST01}"

# Model ids come from .env / the environment — never hardcode product defaults
# beyond these last-resort fallbacks when no env or upstream is available.
OLLAMA_MODEL="${AIWALL_OLLAMA_MODEL:-llama3.2:1b}"
OPENAI_MODEL="${AIWALL_OPENAI_MODEL:-gpt-4o-mini}"

info() { printf '==> %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }

pick_model() {
  # Explicit override for lab / Cursor / Claude / custom upstreams:
  #   export AIWALL_DEMO_MODEL=llama3.2:1b
  #   export AIWALL_DEMO_MODEL=composer-2.5
  #   export AIWALL_DEMO_MODEL=anthropic/claude-3.5-sonnet
  if [[ -n "${AIWALL_DEMO_MODEL:-}" ]]; then
    echo "${AIWALL_DEMO_MODEL}"
    return
  fi
  if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx 'aiwall-ollama'; then
    echo "${OLLAMA_MODEL}"
    return
  fi
  if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx 'aiwall'; then
    echo "${OPENAI_MODEL}"
    return
  fi
  local ollama_url="${OLLAMA_URL:-http://127.0.0.1:${OLLAMA_PORT:-11434}}"
  if curl -sf "${ollama_url}/api/tags" >/dev/null 2>&1; then
    echo "${OLLAMA_MODEL}"
    return
  fi
  echo "${OPENAI_MODEL}"
}

require_aiwall() {
  if ! curl -sf "${BASE_URL}/healthz" >/dev/null; then
    echo "AIWall is not reachable at ${BASE_URL}" >&2
    echo "Start it with ./scripts/dev.sh or docker compose -f deploy/docker-compose.yml up" >&2
    exit 1
  fi
}

send_allow_request() {
  local model="$1"
  local auth_key="${OPENAI_API_KEY:-${OPENROUTER_API_KEY:-${CURSOR_API_KEY:-${ANTHROPIC_API_KEY:-}}}}"
  info "Sending normal request (model=${model})"
  curl -sS -w "\nHTTP %{http_code}\n" \
    "${BASE_URL}/v1/chat/completions" \
    -H "Content-Type: application/json" \
    ${auth_key:+-H "Authorization: Bearer ${auth_key}"} \
    -d "{\"model\":\"${model}\",\"messages\":[{\"role\":\"user\",\"content\":\"hello from aiwall demo\"}]}"
  echo
}

send_block_request() {
  local model="$1"
  info "Sending secret-leak request (expect policy block; model=${model})"
  curl -sS -w "\nHTTP %{http_code}\n" \
    "${BASE_URL}/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -d "{\"model\":\"${model}\",\"messages\":[{\"role\":\"user\",\"content\":\"my aws key is ${SECRET_SAMPLE}\"}]}"
  echo
}

print_audit_rows() {
  info "Recent audit rows"
  local query="SELECT id, provider, model, decision, reason, total_tokens, estimated_cost, latency_ms FROM audit_events ORDER BY id DESC LIMIT 5;"

  if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx 'aiwall'; then
    docker exec aiwall python -c '
import sqlite3

conn = sqlite3.connect("/app/data/aiwall.db")
rows = conn.execute(
    "SELECT id, provider, model, decision, reason, total_tokens, estimated_cost, latency_ms "
    "FROM audit_events ORDER BY id DESC LIMIT 5"
).fetchall()
if not rows:
    print("(no rows)")
else:
    print("id | provider | model | decision | reason | tokens | cost | latency_ms")
    for row in rows:
        print(" | ".join("" if value is None else str(value) for value in row))
'
    return
  fi

  if command -v sqlite3 >/dev/null 2>&1 && [[ -f "${DB_PATH}" ]]; then
    sqlite3 -header -column "${DB_PATH}" "${query}"
    return
  fi

  warn "Could not read audit DB at ${DB_PATH}"
  echo "Open the dashboard: ${BASE_URL}/"
}

main() {
  require_aiwall
  local model
  model="$(pick_model)"
  info "Using model=${model} (set AIWALL_DEMO_MODEL or AIWALL_OLLAMA_MODEL / AIWALL_OPENAI_MODEL in .env)"
  if [[ "${model}" == "${OPENAI_MODEL}" && -z "${OPENAI_API_KEY:-}" && -z "${CURSOR_API_KEY:-}" && -z "${OPENROUTER_API_KEY:-}" ]]; then
    warn "No Ollama detected and no upstream API key set; allow request may log decision=error"
  fi

  send_allow_request "${model}"
  send_block_request "${model}"
  print_audit_rows

  info "Done. Dashboard: ${BASE_URL}/"
}

main "$@"
