# Helpers for the steps of .github/workflows/compat.yml, sourced after
# e2e/compat/start-fucf.sh has put FUCF_API and FUCF_SESSION in the environment.

# admin METHOD PATH [JSON]: the fucf API as its first administrator. Results
# are checked with the panel session, not with the tool's token, so that a
# check sees what the tool did whatever the token may read.
admin() {
  curl -sS --fail-with-body -X "$1" -H "Authorization: Bearer $FUCF_SESSION" -H "Content-Type: application/json" \
    "$FUCF_API$2" ${3:+--data-binary "$3"}
}

# must WHAT JQ_FILTER JSON: passes when the filter is true for the JSON;
# otherwise fails the step, saying what was expected and printing what came.
must() {
  if jq -e "$2" >/dev/null 2>&1 <<<"$3"; then
    echo "ok: $1"
  else
    echo "::error::expected $1 ($2)"
    jq . <<<"$3" 2>/dev/null || printf '%s\n' "$3"
    exit 1
  fi
}
