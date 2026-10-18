#!/usr/bin/env bash
# Register our pieces with the live MandateGuard, as operator.
# hackathon-sa impersonates mandateguard-ops-sa to mint the operator ID token,
# then registers: our agent SA + fixed cnf key on shopper-agent, and our SA as
# a trusted_surface client. Finally verifies our SA now passes (403 -> 200).
set -euo pipefail

OPS_KEY="/Users/mm519918/Downloads/mandateguard-sa-key.json"
MG="https://mandateguard-55485752139.us-central1.run.app"
OUR_SA="teammate-vertex-sa@hackathon-proto-mk26.iam.gserviceaccount.com"
OPS_SA="mandateguard-ops-sa@hackathon-proto-mk26.iam.gserviceaccount.com"
AGENT_THUMB="H4pgUnKBSop2ugynqnPX2hx2xTzQ1Wr4wYh3jB361zk"

# 1) operator ID token via impersonation (source = hackathon-sa)
OPS=$(GOOGLE_APPLICATION_CREDENTIALS="$OPS_KEY" python3 - "$MG" "$OPS_SA" <<'PY'
import sys
from google.auth import default, impersonated_credentials
from google.auth.transport.requests import Request
mg, ops_sa = sys.argv[1], sys.argv[2]
src, _ = default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
tc = impersonated_credentials.IDTokenCredentials(
    impersonated_credentials.Credentials(
        source_credentials=src, target_principal=ops_sa,
        target_scopes=["https://www.googleapis.com/auth/cloud-platform"]),
    target_audience=mg, include_email=True)
tc.refresh(Request())
print(tc.token)
PY
)
echo "ops token minted (len ${#OPS})"

# 2) register our agent SA + delegated cnf key on shopper-agent
echo "== register agent =="
curl -s -X POST "$MG/v1/admin/agents" -H "Authorization: Bearer $OPS" \
  -H "Content-Type: application/json" \
  -d "{\"agent_id\":\"shopper-agent\",\"principals\":[\"$OUR_SA\"],\"key_thumbprints\":[\"$AGENT_THUMB\"],\"description\":\"madhu agent SA + fixed cnf key\"}"
echo

# 3) register our web/identity SA as trusted_surface
echo "== register trusted_surface =="
curl -s -X POST "$MG/v1/admin/clients" -H "Authorization: Bearer $OPS" \
  -H "Content-Type: application/json" \
  -d "{\"client_id\":\"madhu-web\",\"role\":\"trusted_surface\",\"principals\":[\"$OUR_SA\"],\"description\":\"web/identity trusted surface\"}"
echo

# 4) verify our SA now allowed (expect 200)
echo "== verify our SA =="
OUR_TOK=$(GOOGLE_APPLICATION_CREDENTIALS="$HOME/keys/vertex-key.json" python3 -c \
  "import google.auth.transport.requests as r,google.oauth2.id_token as i;print(i.fetch_id_token(r.Request(),'$MG'))")
curl -s -o /dev/null -w "approvals/pending -> HTTP %{http_code} (expect 200)\n" \
  "$MG/v1/approvals/pending" -H "Authorization: Bearer $OUR_TOK"
