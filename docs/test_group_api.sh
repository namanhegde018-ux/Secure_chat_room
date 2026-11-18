#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"
SESSION_ID="${SESSION_ID:-group-demo-001}"

printf '\n== Health ==\n'
curl -fsS "$BASE_URL/health"

printf '\n\n== Start 3-person group ==\n'
curl -fsS -X POST "$BASE_URL/session/start" \
  -H 'Content-Type: application/json' \
  -d "{\"session_id\":\"$SESSION_ID\",\"participants\":[{\"name\":\"Alice\",\"ip\":\"10.0.0.1\"},{\"name\":\"Bob\",\"ip\":\"10.0.0.2\"},{\"name\":\"Charlie\",\"ip\":\"10.0.0.5\"}]}"

printf '\n\n== Active sessions ==\n'
curl -fsS "$BASE_URL/sessions"

printf '\n\nNow test in the Mininet prompt: alice/bob/charlie -> 10.0.0.3 should work; mallory -> 10.0.0.3 should fail.\n'
printf 'Then end the session with:\n'
printf 'curl -fsS -X POST %s/session/end -H "Content-Type: application/json" -d '\''{"session_id":"%s"}'\''\n' "$BASE_URL" "$SESSION_ID"
