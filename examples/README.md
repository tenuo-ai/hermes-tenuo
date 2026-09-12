# Examples

No Hermes process and no API key. Start here:

```bash
pip install hermes-tenuo
hermes-tenuo demo
# or, from this directory: python demo.py
```

That is one story: a nightly job leaves its slip, then the same check on a
child grant and on two gateway users. The longer scripts below are the
same `HermesGuard.pre_tool_call` path, one file per scene.
`subagent_scope.py` is the grant; `gateway_multiuser.py` is one
independently minted warrant per session.

```bash
python cron_warrant.py
python subagent_scope.py
python gateway_multiuser.py
```

A recorded Hermes session with a planted prompt injection is
[`docs/walkthrough.md`](../docs/walkthrough.md) (`examples/walkthrough/setup.sh`).

Requires `tenuo>=0.3.0`.
