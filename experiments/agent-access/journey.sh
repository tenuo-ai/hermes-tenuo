#!/usr/bin/env bash
# Runs the whole owner/guest journey on one machine and checks each outcome.
# Usage: ./journey.sh            (uses uv, which installs each script's dependencies)
#        ./journey.sh python     (a Python with tenuo[mcp,fastmcp]==0.3.8 and httpx installed)
set -euo pipefail
cd "$(dirname "$0")"
P=${1:-uv run --quiet}
W=$(mktemp -d); trap 'kill $SERVER 2>/dev/null || true; rm -rf "$W"' EXIT
O=$W/owner; G=$W/guest; PORT=${PORT:-8765}; URL=http://127.0.0.1:$PORT
fail() { echo "FAIL: $*"; exit 1; }
expect() { local want=$1; shift; local out; out=$("$@" 2>&1 || true); echo "$out" | sed 's/^/    /'; echo "$out" | grep -q "$want" || fail "expected '$want'"; }

echo "1. Owner shares calendar read access with Alex"
LINK=$($P owner.py --home "$O" share Alex calendar.read --hours 2 --server "$URL" | grep -o "http[^' ]*#HG-[A-Z0-9-]*")
$P server.py --home "$O" --port "$PORT" >"$W/server.log" 2>&1 & SERVER=$!
for _ in $(seq 240); do curl -s -o /dev/null "$URL/tenuo/warrant" && break; sleep 0.25; done

echo "2. Alex runs the one command; the owner approves one card"
$P accept.py "$LINK" --as Alex --agent "Claude Code" --home "$G" --wait 20 >"$W/accept.log" 2>&1 & ACCEPT=$!
$P owner.py --home "$O" approve --yes --wait 120 | sed 's/^/    /'
wait $ACCEPT; sed 's/^/    /' "$W/accept.log"
expect "isn't valid" $P accept.py "$LINK" --home "$W/other" --wait 1

echo "3. Read works; write is refused by Alex's client and by the server"
expect "Standup" $P accept.py --home "$G" --call list_events day=2026-11-27
expect "doesn.t include" $P accept.py --home "$G" --call add_event day=2026-11-27 title=Hack
expect "SERVER REFUSED" $P bypass.py "$G" add_event '{"day":"2026-11-27","title":"Hack"}' signed
expect "SERVER REFUSED" $P bypass.py "$G" list_events '{"day":"2026-11-27"}' none
$P accept.py --home "$G" --call list_events day=2026-11-27 | grep -q Hack && fail "refused write had an effect"

echo "4. Owner widens and extends; Alex does nothing"
FP=$($P owner.py --home "$O" list | awk '{print $1}')
python3 - "$O" "$G" >"$W/old.w" <<'PY'
import json, sys
print(json.load(open(sys.argv[1] + "/public/pairings.json"))[json.load(open(sys.argv[2] + "/server.json"))["holder"]]["warrant"])
PY
$P owner.py --home "$O" change "$FP" --scope calendar.write --hours 4 | sed 's/^/    /'
expect "Added" $P accept.py --home "$G" --call add_event day=2026-11-27 title=Lunch
expect "revoked" $P bypass.py "$G" list_events '{"day":"2026-11-27"}' signed "$W/old.w"

echo "5. Owner ends access"
$P owner.py --home "$O" end "$FP" | sed 's/^/    /'
expect "ended this access" $P accept.py --home "$G" --call list_events day=2026-11-27
python3 - "$O" "$G" >"$W/last.w" <<'PY'
import json, sys
print(json.load(open(sys.argv[1] + "/public/pairings.json"))[json.load(open(sys.argv[2] + "/server.json"))["holder"]]["warrant"])
PY
expect "revoked" $P bypass.py "$G" list_events '{"day":"2026-11-27"}' signed "$W/last.w"
echo "All checks passed."
