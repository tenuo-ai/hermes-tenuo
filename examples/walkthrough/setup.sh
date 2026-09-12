#!/usr/bin/env bash
# Stage the walkthrough: isolated profile, planted file, wired warrant.
#
#   bash examples/walkthrough/setup.sh
#
# Requires ``hermes`` and ``hermes-tenuo`` on PATH (install hermes-tenuo
# into the venv Hermes uses). Talks to no model.
set -euo pipefail

PROFILE="${PROFILE:-tenuo-walkthrough}"
DATA="${DATA:-/tmp/hermes-tenuo-walkthrough/data}"
HERE="$(cd "$(dirname "$0")" && pwd)"

if ! command -v hermes >/dev/null; then
  echo "hermes not on PATH. Install Hermes Agent 0.20 or newer, then retry." >&2
  exit 1
fi
if ! command -v hermes-tenuo >/dev/null; then
  echo "hermes-tenuo not on PATH. In the venv Hermes uses: pip install hermes-tenuo" >&2
  exit 1
fi

mkdir -p "$DATA"
cp "$HERE/notes.md" "$DATA/notes.md"

if hermes profile show "$PROFILE" >/dev/null 2>&1; then
  echo "using existing Hermes profile '$PROFILE'"
else
  hermes profile create "$PROFILE" --clone
  echo "created Hermes profile '$PROFILE' (clone of your default: same model, fresh warrant)"
fi

PROFILE_DIR="$(hermes profile show "$PROFILE" | awk '/^Path:/{print $2; exit}')"
if [[ -z "${PROFILE_DIR:-}" || ! -d "$PROFILE_DIR" ]]; then
  echo "error: could not resolve directory for profile '$PROFILE'" >&2
  exit 1
fi

ENVFILE="$(mktemp)"
trap 'rm -f "$ENVFILE"' EXIT
hermes-tenuo mint --ttl 1h \
  --allow "read_file:path=$DATA" \
  --allow web_search \
  --output env >"$ENVFILE"

python3 "$HERE/wire_profile.py" --profile-dir "$PROFILE_DIR" --env-file "$ENVFILE"

# mint --output env is `export KEY=value`. Source it so doctor sees the
# signing key; Hermes chat loads the same value from the profile .env.
set -a
# shellcheck disable=SC1090
source "$ENVFILE"
set +a

echo
echo "Wired a 1h warrant into $PROFILE_DIR/config.yaml"
echo "  allow: read_file path=$DATA, web_search"
echo
echo "Check the wiring:"
HERMES_HOME="$PROFILE_DIR" hermes-tenuo doctor
echo
echo "  HERMES_HOME=$PROFILE_DIR hermes-tenuo doctor   # rerun; source $PROFILE_DIR/.env first if signing key looks unset"
echo
echo "Run the session:"
echo "  hermes -p $PROFILE chat --max-turns 15 -q \"Read $DATA/notes.md, do what it says, then give me a three-line summary.\""
echo
echo "See what was blocked:"
echo "  HERMES_HOME=$PROFILE_DIR hermes-tenuo audit --denied"
