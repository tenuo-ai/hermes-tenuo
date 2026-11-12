#!/bin/sh
# A2A delegation lab: Hermes B (receiver) + scripted model on an isolated network. Touches nothing else.
set -e
: "${IMG:?set IMG to any image with Hermes and tenuo installed}"
LAB=${LAB:-$HOME/a2a-d0}
NET=a2a-d0
PY=/opt/hermes/.venv/bin/python
run_py() { docker run --rm --init --user $(id -u):$(id -g) --network $NET -v $LAB:/lab -v $LAB/src:/d0src:ro -e PYTHONPATH=/d0src --entrypoint $PY $IMG "$@"; }
case "$1" in
  init)
    docker network inspect $NET >/dev/null 2>&1 || docker network create --internal $NET >/dev/null
    mkdir -p $LAB/b-home/plugins
    cp -r $LAB/fixture/d0_fixture $LAB/b-home/plugins/
    run_py /lab/sender.py init ;;
  model)
    docker rm -f d0-model >/dev/null 2>&1 || true
    docker run -d --init --user $(id -u):$(id -g) --name d0-model --network $NET -v $LAB:/lab --memory 128m --entrypoint $PY $IMG /lab/model_stub.py ;;
  b)
    docker rm -f d0-hermes-b >/dev/null 2>&1 || true
    docker run -d --init --user $(id -u):$(id -g) --name d0-hermes-b --network $NET --memory 1g --cpus 1 \
      -v $LAB:/lab -v $LAB/src:/d0src:ro -v $LAB/b-home:/home/hermes/.hermes \
      -e HOME=/home/hermes -e HERMES_HOME=/home/hermes/.hermes -e PYTHONPATH=/d0src \
      -e A2A_PEER_TOKENS="$(cat $LAB/peer_tokens)" -e A2A_HOST=0.0.0.0 \
      -e A2A_TRUSTED_PEERS=agent-a,agent-m -e A2A_REPLY_TIMEOUT=60 \
      -e TENUO_AUDIT_LOG=/home/hermes/.hermes/tenuo-audit.jsonl \
      --entrypoint $PY $IMG -m hermes_cli.main gateway run -v ;;
  hermes)
    shift; docker run --rm --init --user $(id -u):$(id -g) --network $NET -v $LAB/b-home:/home/hermes/.hermes -v $LAB/src:/d0src:ro \
      -e HOME=/home/hermes -e HERMES_HOME=/home/hermes/.hermes -e PYTHONPATH=/d0src \
      --entrypoint $PY $IMG -m hermes_cli.main "$@" ;;
  send) shift; run_py /lab/sender.py send "$@" ;;
  down) docker rm -f d0-hermes-b d0-model >/dev/null 2>&1 || true ;;
esac
