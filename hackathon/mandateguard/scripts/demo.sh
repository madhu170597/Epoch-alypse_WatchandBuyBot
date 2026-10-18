#!/usr/bin/env bash
# Run the demo story against the deployed services. Each role calls as its own service account, through
# impersonation of your gcloud account, so no personal identity reaches the public audit log.
#
#   bash scripts/demo.sh --enroll       one-time link and QR code to create the demo user's passkey
#   bash scripts/demo.sh                six purchases; the allowed ones are charged, shipped and delivered
#   bash scripts/demo.sh --consent      the user first signs the mandates for purchases 1 and 6 with the passkey
#   bash scripts/demo.sh --refund       also refunds the first purchase at the end
#   bash scripts/demo.sh --misdeliver   SoundHub reports purchase 1 delivered to a different address
set -euo pipefail
# The project's own gcloud folder, when there is one, so another account's default login stays untouched.
if [ -z "${CLOUDSDK_CONFIG:-}" ] && [ -d "$HOME/.gcloud-hackathon" ]; then export CLOUDSDK_CONFIG="$HOME/.gcloud-hackathon"; fi
PROJECT=${PROJECT:-hackathon-proto-mk26}
ACCOUNT=${ACCOUNT:-$(gcloud config get-value account 2>/dev/null)}
MG=${MG:-https://mandateguard-55485752139.us-central1.run.app}
CS=${CS:-https://credentials-55485752139.us-central1.run.app}
STORE=${STORE:-https://soundhub-55485752139.us-central1.run.app}

sa() { echo "$1@${PROJECT}.iam.gserviceaccount.com"; }
tok() {  # tok <service account> <audience>: a Google-signed ID token for that audience, with the email claim
  gcloud auth print-identity-token --account="$ACCOUNT" --impersonate-service-account="$(sa "$1")" \
    --audiences="$2" --include-email --verbosity=error
}

AGENT=$(tok shopping-agent-sa "$MG")
SURFACE=$(tok trusted-surface-sa "$MG")
OPS=$(tok mandateguard-ops-sa "$MG")
REFUND=$(tok mandateguard-ops-sa "$CS")

cd "$(dirname "$0")/.."
exec .venv/bin/python -u scripts/demo_story.py --mg "$MG" --cs "$CS" --store "$STORE" --agent-principal "$(sa shopping-agent-sa)" \
  --agent-token "$AGENT" --surface-token "$SURFACE" --ops-token "$OPS" --refund-token "$REFUND" "$@"
