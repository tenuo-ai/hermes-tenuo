# Examples

No Hermes process and no API key. Start here:

```bash
pip install "git+https://github.com/tenuo-ai/hermes-tenuo.git"
hermes-tenuo demo
# or, from this directory: python demo.py
```

That prints the cron, `delegate_task` (a `grant_builder` hop), and gateway
scenes. The longer scripts below are the same `HermesGuard.pre_tool_call`
path, one file per scene. `subagent_scope.py` is the grant; `gateway_multiuser.py`
is one independently minted warrant per session.

```bash
python cron_warrant.py
python subagent_scope.py
python gateway_multiuser.py
```

Requires `tenuo>=0.3.0`.
