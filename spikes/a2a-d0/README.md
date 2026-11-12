# A2A delegation lab

Reproduces the live evidence in [docs/a2a-delegation-design.md](../../docs/a2a-delegation-design.md):
one Hermes (B) receiving native A2A `SendMessage` tasks, a scripted model, and a sender that plays
agent A (and a second peer, M). Synthetic devices only; nothing real is touched. Keys, peer tokens
and the operator root are generated at `init` into the lab directory, never committed.

```sh
mkdir -p ~/a2a-d0/src && cp -r spikes/a2a-d0/* ~/a2a-d0/ && cp -r hermes_tenuo ~/a2a-d0/src/
cd ~/a2a-d0
export IMG="<image with Hermes and tenuo installed>"
umask 077
./run.sh init > init.json      # operator root, A and M keys and warrants, peer tokens
# write b-home/config.yaml (see the design report), store the peer tokens in ./peer_tokens, then:
./run.sh hermes tools enable d0_home --platform a2a
./run.sh model && ./run.sh b
# derive B's public key inside B as shown in the design report; write only that to ./b_key.pub
python3 matrix.py              # 12 checks; prints PASS/FAIL per scenario
./run.sh down
```

Set `IMG` to an image with Hermes and `tenuo` installed; the lab mounts this
checkout's `hermes_tenuo` ahead of the installed one.
