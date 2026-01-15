#!/usr/bin/env sh
set -eu

BASE="${LAP_BASE_URL:-http://gateway:8000}"
API_KEY="${LAP_API_KEY:-dev-key-1}"
SKIP_TLS="${LAP_SKIP_TLS_VERIFY:-0}"

CURL="curl -s"
if [ "$SKIP_TLS" = "1" ]; then
  CURL="curl -sk"
fi

echo "[agent] BASE=$BASE"

echo "[0/3] Boundary check: tool should NOT be reachable directly"
if $CURL --max-time 2 "http://tool:9000/" >/dev/null 2>&1; then
  echo "ERROR: tool is reachable from agent (boundary broken)" >&2
  exit 2
else
  echo "OK: tool not reachable directly."
fi

echo "[1/3] Create session"
SESSION_JSON=$($CURL -X POST "$BASE/v1/session/new" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $API_KEY" \
  -d '{"ttl_seconds": 3600}')

SESSION_ID=$(echo "$SESSION_JSON" | sed -n 's/.*"session_id"[ ]*:[ ]*"\([^"]*\)".*/\1/p')
if [ -z "$SESSION_ID" ]; then
  echo "Failed to parse session_id: $SESSION_JSON" >&2
  exit 1
fi

echo "session_id=$SESSION_ID"

echo "[2/3] Evaluate"
EVAL=$($CURL -X POST "$BASE/v1/evaluate" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $API_KEY" \
  -H "X-Agent-Id: agent_001" \
  -H "X-Session-Id: $SESSION_ID" \
  -d '{
    "action_id":"demo-001",
    "description":"Call the internal HTTP tool through the gateway.",
    "irreversibility": {"score": 0.2},
    "outcome_delta": {},
    "necessity_confidence": 0.7,
    "provenance": {},
    "alternatives": []
  }')

echo "$EVAL"
TOKEN=$(echo "$EVAL" | sed -n 's/.*"capability_token"[ ]*:[ ]*"\([^"]*\)".*/\1/p')

if [ -z "$TOKEN" ]; then
  echo "No token returned (this is expected if the evaluator denied or required minting)." >&2
  exit 0
fi

echo "[3/3] Invoke internal tool through gateway"
INVOKE=$($CURL -X POST "$BASE/v1/tools/http/invoke" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $API_KEY" \
  -H "X-Agent-Id: agent_001" \
  -H "X-Session-Id: $SESSION_ID" \
  -d "{\"tool_name\":\"http\",\"operation\":\"invoke\",\"params\":{\"hello\":\"world\"},\"capability_token\":\"$TOKEN\",\"nonce\":\"n-001\",\"counter\":1}")

echo "$INVOKE"
