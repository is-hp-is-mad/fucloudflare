#!/usr/bin/env bash
# Starts a throwaway fucf for one job of .github/workflows/compat.yml, makes
# its first administrator and one API token, and hands the job what it needs
# through $GITHUB_ENV:
#
#   FUCF_API      http://127.0.0.1:8787/client/v4 (what the tool is pointed at)
#   FUCF_EDGE     http://127.0.0.1:18080 (the edge's plain HTTP listener)
#   FUCF_ACCOUNT  the one account id (GET /accounts)
#   FUCF_SESSION  the administrator's panel session, for checking results
#   FUCF_TOKEN    an API token holding exactly the permission groups given
#   FUCF_LOG      where fucf writes its log
#
# Usage: e2e/compat/start-fucf.sh "<permission group>" ["<permission group>" ...]
#
# The binary comes from the build job (dist/fucf-linux-x86_64, or $FUCF_BIN).
# Every value here is example data, and the bootstrap token, the password and
# the token made below die with the job's runner. FUCF_HTTPS_LISTEN,
# FUCF_PANEL_HOST, FUCF_TLS_CERT_DIR and the other FUCF_* variables the job
# sets reach fucf as they are.
set -euo pipefail

BIN=${FUCF_BIN:-dist/fucf-linux-x86_64}
DATA=${RUNNER_TEMP:-/tmp}/fucf-data
LOG=${RUNNER_TEMP:-/tmp}/fucf.log
API=http://127.0.0.1:8787/client/v4
BOOTSTRAP=compat-bootstrap-token

[ "$#" -ge 1 ] || { echo "name at least one permission group" >&2; exit 2; }
chmod +x "$BIN"
mkdir -p "$DATA"

# Loopback only; no ACME (nothing may reach a real CA) and no block-list
# downloads, so a run depends on nothing but the tool under test.
FUCF_DATA_DIR="$DATA" FUCF_API_TOKEN="$BOOTSTRAP" FUCF_API_LISTEN=127.0.0.1:8787 \
FUCF_HTTP_LISTEN=127.0.0.1:18080 FUCF_HTTPS_LISTEN="${FUCF_HTTPS_LISTEN:-off}" FUCF_HTTP3_LISTEN=off \
FUCF_DNS_LISTEN=127.0.0.1:15353 FUCF_EDGE_IPS=127.0.0.1 FUCF_ACME_DIRECTORY=off FUCF_IP_REPUTATION=false \
  nohup "$BIN" > "$LOG" 2>&1 &

# Expect: the API answers within 10 seconds.
for _ in $(seq 1 50); do
  curl -fsS -o /dev/null http://127.0.0.1:8787/ 2>/dev/null && break
  sleep 0.2
done
if ! curl -fsS -o /dev/null http://127.0.0.1:8787/; then
  echo "::error::fucf did not start"; tail -50 "$LOG"; exit 1
fi
tail -5 "$LOG"

# Expect: /auth/setup takes the bootstrap token once and answers a session.
SESSION=$(curl -sS --fail-with-body -X POST -H "Content-Type: application/json" "$API/auth/setup" \
  -d "$(jq -n --arg t "$BOOTSTRAP" '{token: $t, email: "owner@example.com", password: "a long compat check password"}')" \
  | jq -er .result.token)
echo "::add-mask::$SESSION"

# Expect: exactly one account, whose id tokens and tools use.
ACCOUNT=$(curl -sS --fail-with-body -H "Authorization: Bearer $SESSION" "$API/accounts" | jq -er '.result[0].id')

# One token for the whole account with only the groups this job's tool needs,
# named the way Cloudflare's dashboard names them.
BODY=$(jq -n --arg acc "$ACCOUNT" '{
  name: "compat",
  policies: [{
    effect: "allow",
    resources: { ("com.cloudflare.api.account." + $acc): "*" },
    permission_groups: [$ARGS.positional[] | { name: . }]
  }]
}' --args "$@")
TOKEN=$(curl -sS --fail-with-body -X POST -H "Authorization: Bearer $SESSION" -H "Content-Type: application/json" \
  "$API/user/tokens" -d "$BODY" | jq -er .result.value)
echo "::add-mask::$TOKEN"

# Expect: the new token verifies as active, the first call every tool makes.
curl -sS --fail-with-body -H "Authorization: Bearer $TOKEN" "$API/user/tokens/verify" | jq -e '.success and .result.status == "active"' >/dev/null

{
  echo "FUCF_API=$API"
  echo "FUCF_EDGE=http://127.0.0.1:18080"
  echo "FUCF_ACCOUNT=$ACCOUNT"
  echo "FUCF_SESSION=$SESSION"
  echo "FUCF_TOKEN=$TOKEN"
  echo "FUCF_LOG=$LOG"
} >> "${GITHUB_ENV:-/dev/null}"
echo "fucf is up: account $ACCOUNT, token with: $*"
