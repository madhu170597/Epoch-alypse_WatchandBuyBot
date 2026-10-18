#!/bin/bash
# ===========================================================================
# One-command deploy of the whole demo to Cloud Run, wired together:
#   soundhub (governed merchant site) · merchant/credentials/processor A2A roles
#   · shopping agent (ADK) · identity · Telegram bot · web app.
#
# Runs as YOU (your gcloud login). Idempotent — safe to re-run. Stops at the
# first failure and prints the failing step's log. Ends with smoke checks.
#
# PREREQUISITES
#   1. gcloud auth login && gcloud config set project hackathon-proto-mk26
#   2. AP2/.secrets/ holds shopping-agent-sa.json, trusted-surface-sa.json and
#      mandateguard-fixed-keys.json (gitignored).
#   3. Telegram (optional): export BOT_TOKEN=<from BotFather> once; it is stored
#      in Secret Manager and reused on later runs.
#
# Options (env):
#   ONLY="shopping-agent web"   deploy just these services (default: all)
#   SKIP_BUILD=1                reuse the :latest images (deploy/config only)
# ===========================================================================
set -euo pipefail

PROJECT="${PROJECT:-hackathon-proto-mk26}"
REGION="${REGION:-us-central1}"
REPO="${REPO:-ap2}"                         # Artifact Registry docker repo
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
AP2="$REPO_ROOT/AP2"
SECRETS_DIR="${SECRETS_DIR:-$AP2/.secrets}"
CBUILD="$REPO_ROOT/hackathon/deploy/cloudbuild.build.yaml"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
IMG_BASE="${REGION}-docker.pkg.dev/${PROJECT}/${REPO}"

MANDATE_GUARD_URL="${MANDATE_GUARD_URL:-https://mandateguard-55485752139.us-central1.run.app}"
CREDENTIALS_PROVIDER_URL="${CREDENTIALS_PROVIDER_URL:-https://credentials-55485752139.us-central1.run.app}"
AGENT_MODEL="${AGENT_MODEL:-gemini-2.5-flash}"
CHANNEL_SA_KEY="${CHANNEL_SA_KEY:-$HOME/Downloads/hackathon-sa-key 1.json}"
ONLY="${ONLY:-}"

SA_AGENT="shopping-agent-sa@${PROJECT}.iam.gserviceaccount.com"

die()  { echo "ERROR: $*" >&2; exit 1; }
want() { [ -z "$ONLY" ] || [[ " $ONLY " == *" $1 "* ]]; }

# ── 0. Preflight: fail before touching anything ─────────────────────────────
echo "== 0/7  Preflight =="
for c in gcloud python3 openssl curl shasum; do command -v "$c" >/dev/null || die "missing tool: $c"; done
gcloud auth print-access-token >/dev/null 2>&1 || die "gcloud is not logged in. Run: gcloud auth login"
gcloud config set project "$PROJECT" >/dev/null 2>&1
for f in shopping-agent-sa.json trusted-surface-sa.json mandateguard-fixed-keys.json; do
  [ -s "$SECRETS_DIR/$f" ] || die "missing $SECRETS_DIR/$f"
done
python3 - "$SECRETS_DIR/mandateguard-fixed-keys.json" <<'PY' || die "mandateguard-fixed-keys.json is missing a key"
import json, sys
k = json.load(open(sys.argv[1]))
missing = [n for n in ("AGENT_PRIVATE_KEY_PEM", "AGENT_PROVIDER_SIGNING_KEY_PEM", "MERCHANT_SIGNING_KEY_PEM") if not k.get(n)]
sys.exit(1 if missing else 0)
PY
gcloud services enable run.googleapis.com secretmanager.googleapis.com firestore.googleapis.com \
  aiplatform.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com >/dev/null
gcloud firestore databases describe --database='(default)' >/dev/null 2>&1 \
  || die "Firestore (default) database not found in $PROJECT"
gcloud artifacts repositories describe "$REPO" --location "$REGION" >/dev/null 2>&1 || \
  gcloud artifacts repositories create "$REPO" --repository-format=docker --location "$REGION" >/dev/null
PN="$(gcloud projects describe "$PROJECT" --format='value(projectNumber)')"
pub() { echo "https://$1-${PN}.${REGION}.run.app"; }   # deterministic Cloud Run URL
echo "  ok ($PROJECT / $PN / $(gcloud config get-value account 2>/dev/null))"

# ── 1. Secrets (a new version only when the content changed) ────────────────
put_secret() {  # name file
  local name="$1" file="$2"
  if gcloud secrets describe "$name" >/dev/null 2>&1; then
    if [ "$(gcloud secrets versions access latest --secret "$name" 2>/dev/null | shasum -a 256)" = "$(shasum -a 256 < "$file")" ]; then
      echo "  secret $name (unchanged)"; return 0
    fi
  else
    gcloud secrets create "$name" --replication-policy=automatic >/dev/null
  fi
  gcloud secrets versions add "$name" --data-file="$file" >/dev/null
  echo "  secret $name (updated)"
}
has_secret() { gcloud secrets versions access latest --secret "$1" >/dev/null 2>&1; }
random_secret() {  # name — create once, keep forever (services must agree on it)
  has_secret "$1" && return 0
  openssl rand -hex 16 | tr -d '\n' > "$TMP/$1"
  put_secret "$1" "$TMP/$1"
}

echo "== 1/7  Secrets =="
put_secret mg-agent-sa   "$SECRETS_DIR/shopping-agent-sa.json"
put_secret mg-trusted-sa "$SECRETS_DIR/trusted-surface-sa.json"
python3 - "$SECRETS_DIR/mandateguard-fixed-keys.json" "$TMP" <<'PY'
import json, sys
keys = json.load(open(sys.argv[1]))
for k in ("AGENT_PRIVATE_KEY_PEM", "AGENT_PROVIDER_SIGNING_KEY_PEM", "MERCHANT_SIGNING_KEY_PEM"):
    open(f"{sys.argv[2]}/{k}", "w").write(keys[k])
PY
put_secret agent-priv     "$TMP/AGENT_PRIVATE_KEY_PEM"
put_secret agent-provider "$TMP/AGENT_PROVIDER_SIGNING_KEY_PEM"
put_secret merchant-key   "$TMP/MERCHANT_SIGNING_KEY_PEM"
random_secret svc-secret
random_secret tg-bot-secret
random_secret tg-webhook-secret
if [ -n "${BOT_TOKEN:-}" ]; then
  printf '%s' "$BOT_TOKEN" > "$TMP/bot-token"; put_secret tg-bot-token "$TMP/bot-token"
fi
HAVE_CHANNEL=0
if [ -s "$CHANNEL_SA_KEY" ]; then put_secret mg-channel-sa "$CHANNEL_SA_KEY"; HAVE_CHANNEL=1
elif has_secret mg-channel-sa; then HAVE_CHANNEL=1; fi

# ── 2. Images (Cloud Build, in parallel) ────────────────────────────────────
IMG_SOUNDHUB="$IMG_BASE/soundhub:latest"
IMG_MERCHANT="$IMG_BASE/merchant-agent:latest"
IMG_CREDS="$IMG_BASE/credentials-provider-agent:latest"
IMG_PSP="$IMG_BASE/merchant-payment-processor-agent:latest"
IMG_AGENT="$IMG_BASE/shopping-agent:latest"
IMG_IDENTITY="$IMG_BASE/identity-service:latest"
IMG_BOT="$IMG_BASE/telegram-bot:latest"
IMG_WEB="$IMG_BASE/web:latest"

PIDS=(); LOGS=()
build() {  # service context dockerfile image [role] [extra build-arg]
  want "$1" || return 0
  local log="$TMP/build-$1.log"
  gcloud builds submit "$2" --config "$CBUILD" \
    --substitutions="_DOCKERFILE=$3,_IMAGE=$4,_ROLE=${5:-none},_EXTRA_ARG=${6:-UNUSED=1}" >"$log" 2>&1 &
  PIDS+=($!); LOGS+=("$log")
  echo "  building $1"
}

echo "== 2/7  Build images =="
if [ -z "${SKIP_BUILD:-}" ]; then
  build soundhub                         "$REPO_ROOT/hackathon/merchant_site" Dockerfile "$IMG_SOUNDHUB"
  build merchant-agent                   "$AP2" Dockerfile.role  "$IMG_MERCHANT" merchant_agent
  build credentials-provider-agent       "$AP2" Dockerfile.role  "$IMG_CREDS"    credentials_provider_agent
  build merchant-payment-processor-agent "$AP2" Dockerfile.role  "$IMG_PSP"      merchant_payment_processor_agent
  build shopping-agent                   "$AP2" Dockerfile.agent "$IMG_AGENT"
  build identity-service                 "$REPO_ROOT/identity-service" Dockerfile "$IMG_IDENTITY"
  build telegram-bot                     "$REPO_ROOT/telegram-bot"     Dockerfile "$IMG_BOT"
  build web "$AP2/code/web-client" Dockerfile "$IMG_WEB" none "VITE_AGENT_URL=$(pub shopping-agent)/a2a/shopping_agent"
  FAILED=0; i=0
  while [ "$i" -lt "${#PIDS[@]}" ]; do   # bash 3.2-safe (macOS) with set -u
    if ! wait "${PIDS[$i]}"; then
      FAILED=1; echo "---- build failed: ${LOGS[$i]##*/build-} ----"; tail -25 "${LOGS[$i]}"
    fi
    i=$((i + 1))
  done
  [ "$FAILED" = 0 ] || die "image build failed (see above)"
  echo "  all images built"
else
  echo "  SKIP_BUILD=1 — reusing :latest images"
fi

# ── 3. Deploy ────────────────────────────────────────────────────────────────
deploy() {  # service image [gcloud run deploy flags...]
  local svc="$1" img="$2"; shift 2
  want "$svc" || return 0
  local log="$TMP/deploy-$svc.log"
  if gcloud run deploy "$svc" --image "$img" --region "$REGION" --quiet \
       --allow-unauthenticated --service-account "$SA_AGENT" "$@" >"$log" 2>&1; then
    echo "  $svc up"
  else
    tail -25 "$log"; die "deploy $svc failed"
  fi
}

# Every A2A role builds a genai client at startup (Vertex via the runtime SA).
# FIRESTORE_ENABLED shares state across services (carts, trust key, listings).
VERTEX="GOOGLE_GENAI_USE_VERTEXAI=true,GOOGLE_CLOUD_PROJECT=$PROJECT,GOOGLE_CLOUD_LOCATION=$REGION,FIRESTORE_ENABLED=true"
SOUNDHUB_SITE="$(pub soundhub)"

echo "== 3/7  SoundHub site + A2A roles =="
# SoundHub is the merchant site registered with MandateGuard; same service name
# keeps the registered URL. Static pages are unchanged; it now also serves
# on-demand listings and timed demo price drops from Firestore.
deploy soundhub "$IMG_SOUNDHUB" --port 8080 --min-instances 1 --set-env-vars "FIRESTORE_ENABLED=true"
deploy merchant-agent "$IMG_MERCHANT" --timeout 300 --min-instances 1 \
  --set-env-vars "A2A_HOST=0.0.0.0,A2A_PUBLIC_URL=$(pub merchant-agent),$VERTEX,MERCHANT_ID=merchant_clean,MERCHANT_NAME=SoundHub,MERCHANT_WEBSITE=$SOUNDHUB_SITE,MERCHANT_KID=soundhub-2026-10,MERCHANT_SITE_URL=$SOUNDHUB_SITE,MG_MERCHANT_ID=merchant_clean,MG_HNP_SPEND_CAP=480" \
  --set-secrets "MERCHANT_SIGNING_KEY_PEM=merchant-key:latest"
for role in credentials-provider-agent merchant-payment-processor-agent; do
  img="$IMG_CREDS"; [ "$role" = merchant-payment-processor-agent ] && img="$IMG_PSP"
  deploy "$role" "$img" --timeout 300 \
    --set-env-vars "A2A_HOST=0.0.0.0,A2A_PUBLIC_URL=$(pub "$role"),$VERTEX"
done

echo "== 4/7  Shopping agent (ADK) =="
# One instance, always on: ADK sessions and signed-mandate files live in memory
# / on local disk. Long timeout: a purchase turn streams for minutes.
deploy shopping-agent "$IMG_AGENT" --min-instances 1 --max-instances 1 --timeout 3600 --memory 1Gi \
  --set-env-vars "A2A_HOST=0.0.0.0,$VERTEX,AGENT_MODEL=$AGENT_MODEL,MANDATE_GUARD_URL=$MANDATE_GUARD_URL,CREDENTIALS_PROVIDER_URL=$CREDENTIALS_PROVIDER_URL,PAYMENT_PROCESSOR_URL=$CREDENTIALS_PROVIDER_URL,MERCHANT_AGENT_URL=$(pub merchant-agent)/a2a/merchant_agent,MG_MERCHANT_ID=merchant_clean,MG_MERCHANT_NAME=SoundHub,MG_MERCHANT_WEBSITE=$SOUNDHUB_SITE,MANDATE_GUARD_TIMEOUT=45,MG_AGENT_SA_KEY=/secrets/agent/sa.json,MG_TRUSTED_SURFACE_SA_KEY=/secrets/trusted/sa.json" \
  --set-secrets "/secrets/agent/sa.json=mg-agent-sa:latest,/secrets/trusted/sa.json=mg-trusted-sa:latest,AGENT_PRIVATE_KEY_PEM=agent-priv:latest,AGENT_PROVIDER_SIGNING_KEY_PEM=agent-provider:latest,MERCHANT_SIGNING_KEY_PEM=merchant-key:latest"

echo "== 5/7  Identity service =="
deploy identity-service "$IMG_IDENTITY" --port 8080 \
  --set-env-vars "FIREBASE_PROJECT_ID=$PROJECT,RP_ID=$(pub web | sed 's|https://||'),EXPECTED_ORIGIN=$(pub web),REQUIRE_MFA=false" \
  --set-secrets "SERVICE_SECRET=svc-secret:latest,TELEGRAM_BOT_SECRET=tg-bot-secret:latest"

echo "== 6/7  Telegram bot + web app =="
BOT_DEPLOYED=0
if want telegram-bot && has_secret tg-bot-token; then
  BOT_SECRETS="BOT_TOKEN=tg-bot-token:latest,WEBHOOK_SECRET=tg-webhook-secret:latest,SERVICE_SECRET=svc-secret:latest,TELEGRAM_BOT_SECRET=tg-bot-secret:latest"
  BOT_ENV="AGENT_URL=$(pub shopping-agent)/a2a/shopping_agent,IDENTITY_URL=$(pub identity-service),WEB_APP_URL=$(pub web),PUBLIC_BASE_URL=$(pub telegram-bot),ENFORCE_LINK=false,MANDATE_GUARD_URL=$MANDATE_GUARD_URL,MONITOR_POLL_SECONDS=8"
  if [ "$HAVE_CHANNEL" = 1 ]; then
    BOT_SECRETS="$BOT_SECRETS,/secrets/channel/sa.json=mg-channel-sa:latest"
    BOT_ENV="$BOT_ENV,MG_CHANNEL_SA_KEY=/secrets/channel/sa.json"
  fi
  # One instance with CPU always allocated: chat state and the price-watch loops
  # run in-process after the webhook has been acknowledged.
  deploy telegram-bot "$IMG_BOT" --port 8080 --min-instances 1 --max-instances 1 --no-cpu-throttling \
    --set-env-vars "$BOT_ENV" --set-secrets "$BOT_SECRETS"
  TOKEN="$(gcloud secrets versions access latest --secret tg-bot-token)"
  HOOK="$(gcloud secrets versions access latest --secret tg-webhook-secret)"
  curl -fsS "https://api.telegram.org/bot${TOKEN}/setWebhook" \
    --data-urlencode "url=$(pub telegram-bot)/webhook/${HOOK}" --data "drop_pending_updates=true" \
    | grep -q '"ok":true' || die "Telegram setWebhook failed (check BOT_TOKEN)"
  unset TOKEN HOOK
  echo "  webhook set"; BOT_DEPLOYED=1
elif want telegram-bot; then
  echo "  no BOT_TOKEN in env or Secret Manager — skipping the bot (export BOT_TOKEN=... and re-run with ONLY=telegram-bot)"
fi
deploy web "$IMG_WEB" --port 8080

# ── 7. Smoke checks ──────────────────────────────────────────────────────────
check() {  # name url expected-substring
  want "$1" || return 0
  local body=""
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    body="$(curl -fsS --max-time 20 "$2" 2>/dev/null || true)"
    [[ -n "$body" && "$body" == *"$3"* ]] && { echo "  ok  $1"; return 0; }
    sleep 3
  done
  die "smoke check $1 failed: $2 (expected '$3', got: ${body:0:200})"
}
echo "== 7/7  Smoke checks =="
check soundhub       "$SOUNDHUB_SITE/health" '"firestore":true'
check soundhub       "$SOUNDHUB_SITE/p/sony-wh-1000xm5-black" 'Sony WH-1000XM5'
check merchant-agent "$(pub merchant-agent)/a2a/merchant_agent/.well-known/agent-card.json" "$(pub merchant-agent)"
check credentials-provider-agent "$(pub credentials-provider-agent)/a2a/credentials_provider/.well-known/agent-card.json" "$(pub credentials-provider-agent)"
check shopping-agent "$(pub shopping-agent)/a2a/shopping_agent/.well-known/agent-card.json" '"name"'
check identity-service "$(pub identity-service)/openapi.json" '"openapi"'   # /healthz is reserved by Cloud Run
check web            "$(pub web)/" '<div id="root"'
[ "$BOT_DEPLOYED" = 1 ] && check telegram-bot "$(pub telegram-bot)/openapi.json" '"openapi"'

cat <<SUMMARY

  Web app:        $(pub web)
  Shopping agent: $(pub shopping-agent)
  SoundHub:       $SOUNDHUB_SITE
  Identity:       $(pub identity-service)
  Bot:            $([ "$BOT_DEPLOYED" = 1 ] && pub telegram-bot || echo "<not deployed>")

  Try: "Buy Sony WH-1000XM5 black from SoundHub if it drops to \$250 this week"
  -> approve -> price drops under budget within ~30s -> order placed.
  Secrets live in Secret Manager (svc-secret, tg-*); none are printed here.
SUMMARY
