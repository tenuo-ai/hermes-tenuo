# Examples

These examples require `tenuo>=0.1.0b24` (the version that includes `tenuo.hermes`).

```bash
pip install "tenuo>=0.1.0b24" hermes-tenuo
python cron_warrant.py
python subagent_scope.py
python gateway_multiuser.py
```

Until that version is published, install from source:

```bash
git clone https://github.com/tenuo-ai/tenuo
cd tenuo/tenuo-python && pip install -e .
cd /path/to/hermes-tenuo && pip install -e .
python examples/cron_warrant.py
```
