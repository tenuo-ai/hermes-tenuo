# Examples

```bash
pip install "git+https://github.com/tenuo-ai/hermes-tenuo.git"
# or, from a clone:
pip install -e ..

hermes-tenuo mint --allow read_file --allow web_search --ttl 1h --output full
hermes-tenuo doctor

python cron_warrant.py
python subagent_scope.py
python gateway_multiuser.py
```

Requires `tenuo>=0.3.0` and Hermes Agent 0.20.x.
