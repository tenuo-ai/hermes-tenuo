# Examples

No Hermes process and no API key. Start here:

```bash
pip install -e ..
hermes-tenuo demo
# or: python demo.py
```

That prints the cron, `delegate_task`, and gateway scenes. The longer scripts below are the same `HermesGuard.pre_tool_call` path, one file per scene.

```bash
python cron_warrant.py
python subagent_scope.py
python gateway_multiuser.py
```

Requires `tenuo>=0.3.0`.
