#!/bin/bash
# ---------------------------------------------------------------------------
# Run the HNP flow as SEPARATE A2A services (the doc's multi-service topology):
#   merchant_agent (8001), credentials_provider_agent (8002),
#   merchant_payment_processor_agent (8003), shopping agent (8080), web (5173).
#
# Unlike cards/run.sh (stdio-MCP, single host), each role is its own HTTP A2A
# service here; the agent reaches them over HTTP via a2a_tools. Shared state is
# in Firestore (FIRESTORE_ENABLED=true in .env). The price-drop trigger lives in
# the Firestore "merchant_trigger" collection — see the printed snippet below.
# ---------------------------------------------------------------------------
set -eu

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SAMPLES="$(cd "$SCRIPT_DIR/../../.." && pwd)"   # code/samples/python
readonly SRC="$SAMPLES/src"
readonly WEBCLIENT="$SAMPLES/../../web-client"
readonly AGENT_DIR="$SRC/roles/shopping_agent_v2"
readonly LOG_DIR="$SCRIPT_DIR/.logs"

# Load env (Vertex, model, Firestore, peer URLs).
for env_file in "$SAMPLES/../../.env" "$AGENT_DIR/.env"; do
  if [ -f "$env_file" ]; then set -a; source "$env_file"; set +a; fi
done

export LOGS_DIR="$LOG_DIR"
export TEMP_DB_DIR="$SCRIPT_DIR/.temp-db"   # agent-local mandate SD-JWTs
export FLOW="${FLOW:-card}"

# ── MandateGuard governed mode ─────────────────────────────────────────────
# When MANDATE_GUARD_URL is set (in .env), run the merchant as the registered
# SoundHub clean merchant: it signs checkouts with the registered soundhub key
# and serves the real SoundHub product pages (MandateGuard re-fetches and
# compares them). Defaults use `:-` so the attack demos (MERCHANT_VARIANT /
# MERCHANT_ID overrides on the command line) still win.
if [ -n "${MANDATE_GUARD_URL:-}" ]; then
  export MG_MERCHANT_ID="${MG_MERCHANT_ID:-merchant_clean}"
  export MG_MERCHANT_NAME="${MG_MERCHANT_NAME:-SoundHub}"
  export MG_MERCHANT_WEBSITE="${MG_MERCHANT_WEBSITE:-https://soundhub-55485752139.us-central1.run.app}"
  export MERCHANT_ID="${MERCHANT_ID:-merchant_clean}"
  export MERCHANT_NAME="${MERCHANT_NAME:-SoundHub}"
  export MERCHANT_WEBSITE="${MERCHANT_WEBSITE:-https://soundhub-55485752139.us-central1.run.app}"
  export MERCHANT_KID="${MERCHANT_KID:-soundhub-2026-10}"
  export MERCHANT_SITE_URL="${MERCHANT_SITE_URL:-https://soundhub-55485752139.us-central1.run.app}"
  # MERCHANT_SIGNING_KEY_PEM (the registered soundhub JWK) comes from .env.
  echo "MandateGuard governed mode: merchant=$MERCHANT_ID kid=$MERCHANT_KID site=$MERCHANT_SITE_URL"
fi
rm -rf "$LOG_DIR" "$TEMP_DB_DIR"
mkdir -p "$LOG_DIR" "$TEMP_DB_DIR"
mkdir -p "$SRC/.logs"   # common/watch_log writes .logs/watch.log relative to cwd (SRC)

pids=()
cleanup() { echo; echo "Shutting down..."; [ ${#pids[@]} -gt 0 ] && kill -TERM "${pids[@]}" 2>/dev/null || true; sleep 1; [ ${#pids[@]} -gt 0 ] && kill -KILL "${pids[@]}" 2>/dev/null || true; echo "Done."; }
trap cleanup EXIT

kill_port() { local p; p=$(lsof -ti tcp:"$1" 2>/dev/null || true); [ -n "$p" ] && kill -9 $p 2>/dev/null || true; }

start_role() {  # name module port
  local name="$1" module="$2" port="$3"
  kill_port "$port"
  echo "Starting $name (port $port)..."
  (cd "$SRC" && PYTHONPATH="$SRC" uv run python -m "$module") >"$LOG_DIR/$name.log" 2>&1 &
  pids+=("$!")
}

wait_for_url() {
  local url="$1" timeout="${2:-60}" i
  for (( i=0; i<timeout*2; i++ )); do
    curl -s -o /dev/null "$url" 2>/dev/null && return 0
    sleep 0.5
  done
  echo "WARN: timed out waiting for $url" >&2
}

echo "Syncing workspace..."
(cd "$SAMPLES/../.." && uv sync --all-packages --quiet 2>/dev/null) || true

start_role "merchant-agent"            "roles.merchant_agent"                    8001
start_role "credentials-provider"      "roles.credentials_provider_agent"        8002
start_role "payment-processor"         "roles.merchant_payment_processor_agent"  8003
sleep 2

kill_port 8080
echo "Starting shopping-agent (port 8080)..."
(cd "$AGENT_DIR" && uv run python run_server.py) >"$LOG_DIR/agent.log" 2>&1 &
pids+=("$!")
wait_for_url "http://localhost:8080/a2a/shopping_agent/.well-known/agent-card.json" 120

kill_port 5173
(cd "$WEBCLIENT" && npm install --no-fund --no-audit >/dev/null 2>&1 || true)
echo "Starting web-client (port 5173)..."
(cd "$WEBCLIENT" && VITE_FLOW=card npm run dev -- --port 5173) >"$LOG_DIR/web-client.log" 2>&1 &
pids+=("$!")
wait_for_url "http://localhost:5173" 40

cat <<EOF

A2A separate-services topology is up:
  merchant:8001  credentials:8002  psp:8003  agent:8080  web:5173

Simulate a drop (writes Firestore "merchant_trigger"), using the item_id from the
signed mandate card:
  cd "$SAMPLES/../.." && set -a && source .env && set +a && \\
  PYTHONPATH="$SRC" uv run python -c \\
    "from common.firestore_store import KVStore; KVStore('merchant_trigger').set('<item_id>', {'price':120,'stock':10}); print('drop set')"

Open http://localhost:5173 . Press Ctrl+C to stop.

Attack demos (restart with these env vars on the merchant):
  Impersonator (look-alike, different merchant id -> AllowedMerchants violation
  in create_checkout, purchase blocked):
    MERCHANT_VARIANT=impersonator MERCHANT_ID=impostor_1 MERCHANT_NAME="Demo Merchant" \\
      bash $(basename "$0")
  Injected page (hidden prompt-injection in the product page -> agent treats it as
  quoted data, MandateGuard screens it, and a gift-card SKU would fail the
  line-item constraint):
    MERCHANT_VARIANT=injected bash $(basename "$0")
EOF

command -v open >/dev/null 2>&1 && open "http://localhost:5173" || true
wait
