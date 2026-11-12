# A2A delegation spike (D0) — live lab

Reproduces the live evidence in [docs/remote-delegation-spike.md](../../docs/remote-delegation-spike.md):
one Hermes (B) receiving native A2A `SendMessage` tasks, a scripted model, and a sender that plays
agent A (and a second peer, M). Synthetic devices only; nothing real is touched. Keys, peer tokens
and the operator root are generated at `init` into the lab directory, never committed.

```sh
mkdir -p ~/a2a-d0/src && cp -r spikes/a2a-d0/* ~/a2a-d0/ && cp -r hermes_tenuo ~/a2a-d0/src/
cd ~/a2a-d0
./run.sh init > init.json      # operator root, A and M keys and warrants, peer tokens
# write b-home/config.yaml (see the spike doc), store the peer tokens in ./peer_tokens, then:
./run.sh hermes tools enable d0_home --platform a2a
./run.sh model && ./run.sh b
# write B's public key (from its log line or b-home/tenuo/a2a.key) to ./b_key.pub
python3 matrix.py              # 12 checks; prints PASS/FAIL per scenario
./run.sh down
```

`IMG` selects the image (any image with Hermes and `tenuo` installed); the lab mounts this
checkout's `hermes_tenuo` ahead of the installed one.
