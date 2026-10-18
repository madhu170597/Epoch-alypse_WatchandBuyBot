#!/bin/bash
# ---------------------------------------------------------------------------
# OPERATOR ACTION (run by Manish, who holds MandateGuard operator access).
#
# Registers the Telegram bot's service account as a MandateGuard `channel`
# client so it can receive approval events (push) and/or pull + redeem held
# approvals. This is the ONLY MandateGuard-side step needed for the Telegram
# ESCALATE-approval path; the autonomous ALLOW purchase needs nothing here.
#
# Nothing is redeployed — access applies to the next call (contract section 1).
#
# Usage:
#   WEBHOOK_URL="https://<bot-public-url>/mg/events" bash register-telegram-channel.sh
#   # omit WEBHOOK_URL to register for PULL-only (no push events).
# ---------------------------------------------------------------------------
set -euo pipefail

MANDATE_GUARD_URL="${MANDATE_GUARD_URL:-https://mandateguard-55485752139.us-central1.run.app}"
CHANNEL_SA="${CHANNEL_SA:-hackathon-sa@hackathon-proto-mk26.iam.gserviceaccount.com}"
WEBHOOK_URL="${WEBHOOK_URL:-}"     # https .../mg/events ; empty = pull-only

# Operator ID token (audience = MandateGuard base URL), from your own gcloud auth.
TOKEN="$(gcloud auth print-identity-token --audiences="$MANDATE_GUARD_URL")"

# Build the request body. The bot authenticates as $CHANNEL_SA (email claim).
read -r -d '' BODY <<JSON || true
{
  "client_id": "telegram-bot",
  "role": "channel",
  "service_account": "$CHANNEL_SA"${WEBHOOK_URL:+,
  "webhook_url": "$WEBHOOK_URL"}
}
JSON

echo "Registering channel client:"
echo "  service_account: $CHANNEL_SA"
echo "  webhook_url:     ${WEBHOOK_URL:-<pull-only>}"
echo

curl -sS -X POST "$MANDATE_GUARD_URL/v1/admin/clients" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "$BODY"
echo

# If MandateGuard should post the approval message itself instead (option 3 in
# section 8), also set MG_TELEGRAM_BOT_TOKEN on the MandateGuard deployment and
# register linked_channels.telegram on each mandate.
#
# Field names above follow the integration contract; if the admin API at
# $MANDATE_GUARD_URL/api/docs names them differently, adjust client_id/
# service_account/webhook_url to match (role must be "channel").
