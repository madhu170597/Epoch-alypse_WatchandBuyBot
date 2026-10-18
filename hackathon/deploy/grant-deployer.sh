#!/bin/bash
# ===========================================================================
# OPERATOR / PROJECT-OWNER step (run by Manish on hackathon-proto-mk26).
#
# Lets the deployer run deploy-all.sh: permission to deploy Cloud Run and to
# run services AS the registered service accounts, plus the runtime roles those
# service accounts need (Vertex, Firestore, Secret Manager).
#
# Usage:
#   DEPLOYER=madhu170597@gmail.com bash grant-deployer.sh
# ===========================================================================
set -euo pipefail

PROJECT="${PROJECT:-hackathon-proto-mk26}"
DEPLOYER="${DEPLOYER:?set DEPLOYER=<the google account running deploy-all.sh>}"

SA_AGENT="shopping-agent-sa@${PROJECT}.iam.gserviceaccount.com"
SA_TRUSTED="trusted-surface-sa@${PROJECT}.iam.gserviceaccount.com"
SA_CHANNEL="hackathon-sa@${PROJECT}.iam.gserviceaccount.com"

gcloud config set project "$PROJECT" >/dev/null

echo "== Let $DEPLOYER deploy + act-as the service accounts =="
gcloud projects add-iam-policy-binding "$PROJECT" \
  --member "user:$DEPLOYER" --role roles/run.admin >/dev/null
gcloud projects add-iam-policy-binding "$PROJECT" \
  --member "user:$DEPLOYER" --role roles/iam.serviceAccountUser >/dev/null   # actAs any SA
gcloud projects add-iam-policy-binding "$PROJECT" \
  --member "user:$DEPLOYER" --role roles/cloudbuild.builds.editor >/dev/null
gcloud projects add-iam-policy-binding "$PROJECT" \
  --member "user:$DEPLOYER" --role roles/artifactregistry.writer >/dev/null

echo "== Runtime roles for the service accounts =="
gcloud projects add-iam-policy-binding "$PROJECT" \
  --member "serviceAccount:$SA_AGENT" --role roles/aiplatform.user >/dev/null
gcloud projects add-iam-policy-binding "$PROJECT" \
  --member "serviceAccount:$SA_AGENT" --role roles/datastore.user >/dev/null
gcloud projects add-iam-policy-binding "$PROJECT" \
  --member "serviceAccount:$SA_AGENT" --role roles/secretmanager.secretAccessor >/dev/null
gcloud projects add-iam-policy-binding "$PROJECT" \
  --member "serviceAccount:$SA_TRUSTED" --role roles/datastore.user >/dev/null
gcloud projects add-iam-policy-binding "$PROJECT" \
  --member "serviceAccount:$SA_TRUSTED" --role roles/secretmanager.secretAccessor >/dev/null
gcloud projects add-iam-policy-binding "$PROJECT" \
  --member "serviceAccount:$SA_CHANNEL" --role roles/secretmanager.secretAccessor >/dev/null

echo "Done. $DEPLOYER can now run hackathon/deploy/deploy-all.sh."
