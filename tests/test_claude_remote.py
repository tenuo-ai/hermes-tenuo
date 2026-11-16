"""claude_code with approval and another machine: request, card, /claude, hub."""

import base64
import json
import threading
import time
import urllib.error
import urllib.request

import pytest

from hermes_tenuo import claude_code as cc
from hermes_tenuo import claude_remote as cr


def _key_b64():
    from tenuo import SigningKey
    key = SigningKey.generate()
    return key, base64.b64encode(key.public_key.to_bytes()).decode()


def _config(tmp_path, monkeypatch, **over):
    _, pub = _key_b64()
    monkeypatch.setenv("TEST_WORKER_TOKEN", "s3cret")
    block = {"machines": {"laptop": {"public_key": pub, "token_env": "TEST_WORKER_TOKEN"}},
             "listen": "127.0.0.1:0", **over}
    return cc.load_config({"claude_code": block})


def test_machines_need_listen_and_valid_keys(tmp_path):
    with pytest.raises(ValueError, match="listen"):
        cc.load_config({"claude_code": {"machines": {"m": {"public_key": _key_b64()[1], "token_env": "X"}}}})
    with pytest.raises(Exception):
        cc.load_config({"claude_code": {"listen": "x:1", "machines": {"m": {"public_key": "bad", "token_env": "X"}}}})


def test_build_request_for_a_machine(tmp_path, monkeypatch):
    config = _config(tmp_path, monkeypatch)
    r = cc.build_request(config, {"task": "fix it", "workspace": "calc-demo", "commands": ["git diff"],
                                  "minutes": 999}, "sk")
    assert (r.machine, r.workspace, r.commands, r.minutes, r.session_key) == \
        ("laptop", "calc-demo", ["git diff"], config["max_minutes"], "sk")
    for bad in ("../x", "/etc", "a/../b", "a b"):
        with pytest.raises(cc.ClaudeCodeError):
            cc.build_request(config, {"task": "x", "workspace": bad})
    with pytest.raises(cc.ClaudeCodeError):
        cc.build_request(config, {"task": "x", "workspace": "a", "machine": "other"})


def test_card_says_what_is_granted(tmp_path, monkeypatch):
    config = _config(tmp_path, monkeypatch)
    r = cc.build_request(config, {"task": "review", "workspace": "calc-demo", "commands": ["git diff"],
                                  "read_only": True, "minutes": 10})
    card = cc.describe(r)
    assert "laptop" in card and "calc-demo" in card and "git diff" in card and "10 min" in card
    assert "read files" in card and "edit" not in card.split("May:")[1].split("\n")[0]
    assert "/claude" in card


def test_requests_are_approved_once_and_only_in_their_conversation():
    store = cc.Requests()
    r = cc.Request(id="ab12", task="t", machine="laptop", workspace="w", commands=[], read_only=False,
                   minutes=5, session_key="owner-chat")
    store.add(r)
    assert store.waiting("other-chat") == []
    assert store.take("ab12", "other-chat") is None
    assert store.take("ab12", "owner-chat") is r
    assert store.take("ab12", "owner-chat") is None
    assert store.deny("ab12", "owner-chat") is False


def _hub(monkeypatch):
    key, pub = _key_b64()
    monkeypatch.setenv("TEST_WORKER_TOKEN", "s3cret")
    hub = cr.Hub(cr.parse_machines({"laptop": {"public_key": pub, "token_env": "TEST_WORKER_TOKEN"}}))
    from http.server import ThreadingHTTPServer
    hub.server = ThreadingHTTPServer(("127.0.0.1", 0), cr._handler(hub))
    threading.Thread(target=hub.server.serve_forever, daemon=True).start()
    monkeypatch.setattr(cr, "POLL_SECONDS", 1)
    return hub, pub, f"http://127.0.0.1:{hub.server.server_address[1]}"


def _call(url, method="GET", body=None, token="s3cret", machine="laptop", pub=""):
    req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body else None,
                                 headers={"Authorization": f"Bearer {token}", "X-Tenuo-Machine": machine,
                                          "X-Tenuo-Root": "/Users/me/code", "X-Tenuo-Public-Key": pub})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        return exc.code, None


def test_hub_rejects_unknown_machines_tokens_and_keys(monkeypatch):
    hub, pub, base = _hub(monkeypatch)
    assert _call(base + "/claude/next", token="wrong", pub=pub)[0] == 401
    assert _call(base + "/claude/next", machine="intruder", pub=pub)[0] == 401
    assert _call(base + "/claude/next", pub=_key_b64()[1])[0] == 403
    assert _call(base + "/claude/next", pub=pub)[0] == 204
    assert hub.machines["laptop"].online and hub.machines["laptop"].root == "/Users/me/code"


def test_hub_delivers_a_job_and_its_result(monkeypatch):
    hub, pub, base = _hub(monkeypatch)
    lines = []
    job = cr.Job(id="run1", machine="laptop", payload={"id": "run1", "task": "t"}, on_progress=lines.extend)
    hub.submit(job)
    status, body = _call(base + "/claude/next", pub=pub)
    assert status == 200 and body["id"] == "run1"
    assert _call(base + "/claude/jobs/run1/progress", "POST", {"line": "✅ Read calc.py"}, pub=pub)[0] == 200
    assert _call(base + "/claude/jobs/nope/result", "POST", {"ok": True}, pub=pub)[0] == 404
    assert _call(base + "/claude/jobs/run1/result", "POST", {"ok": True, "result": "done"}, pub=pub)[0] == 200
    assert hub.wait(job, 1) == {"ok": True, "result": "done"}
    assert lines == ["✅ Read calc.py"]


class _Ctx:
    def __init__(self, choice="approve"):
        self.tools, self.commands, self.posts, self.injected = {}, {}, [], []
        self.choice = choice

    def register_tool(self, name, toolset, schema, handler, **kw):
        self.tools[name] = handler

    def register_command(self, name, handler, **kw):
        self.commands[name] = handler

    def post_message(self, text):
        ctx = self

        class Handle:
            ok = True
            def edit(self, t):
                ctx.posts.append(t)
        self.posts.append(text)
        return Handle()

    def ask_choice(self, question, choices):
        self.asked = (question, choices)
        return self.choice

    def inject_message(self, content, session_key=None, **kw):
        self.injected.append((content, session_key))
        return True


def test_tool_waits_for_owner_approval_then_runs(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    ws.mkdir()
    monkeypatch.setattr("hermes_tenuo._config._get_plugin_entry",
                        lambda ctx: {"claude_code": {"workspaces": [str(ws)], "tenuo_claude": "/bin/true"}})
    monkeypatch.setattr("hermes_tenuo._home.hermes_home", lambda: tmp_path / "home")
    monkeypatch.setattr(cc, "_bound_session_key", lambda: "owner-chat")
    ran = []

    def fake_run(config, home, hub, request, on_progress=None, runner=None):
        ran.append(request)
        return {"ok": True, "result": "fixed", "allowed_count": 3, "denied_count": 1,
                "denied": [{"tool": "Bash", "args": {"command": "git push"}}],
                "receipts": {"count": 4, "chain_ok": True}}
    monkeypatch.setattr(cc, "run_request", fake_run)
    ctx = _Ctx()
    assert cc.register(ctx)
    out = json.loads(ctx.tools["claude_code"]({"task": "fix", "workspace": str(ws), "minutes": 5}))
    assert out["status"] == "waiting_for_approval" and not ran
    assert "Claude Code request" in ctx.posts[0]
    # Someone in another conversation can't approve it.
    assert "No Claude Code request" in ctx.commands["claude"]("", session_key="other-chat")
    ctx.commands["claude"]("", session_key="owner-chat")
    for _ in range(50):
        if ctx.injected:
            break
        time.sleep(0.05)
    assert len(ran) == 1
    assert any("Denied: Bash git push" in p for p in ctx.posts)
    assert ctx.injected and ctx.injected[0][1] == "owner-chat"


def test_denied_request_never_runs(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    ws.mkdir()
    monkeypatch.setattr("hermes_tenuo._config._get_plugin_entry",
                        lambda ctx: {"claude_code": {"workspaces": [str(ws)], "tenuo_claude": "/bin/true"}})
    monkeypatch.setattr(cc, "_bound_session_key", lambda: "owner-chat")
    monkeypatch.setattr(cc, "run_request", lambda *a, **k: pytest.fail("must not run"))
    ctx = _Ctx(choice="deny")
    cc.register(ctx)
    ctx.tools["claude_code"]({"task": "fix", "workspace": str(ws)})
    assert "Denied" in ctx.commands["claude"]("", session_key="owner-chat")
