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


GRANT_COMMANDS = ["git status", "git diff", "git add", "git commit", "python3 -m pytest"]


def _standing_grant(machine_key, hermes_pub, *, share="/Users/me/code", push="claude/*", days=1,
                    commands=GRANT_COMMANDS, report="summary"):
    """What `tenuo-claude worker grant` signs on the machine."""
    from tenuo import Exact, Pattern, Subpath, Warrant
    b = Warrant.mint_builder()
    for cap in cc.FILE_CAPS:
        b = b.capability(cap, {"path": Subpath(share)})
    b = b.capability(cc.COMMAND_CAP, {"command": cc.command_constraint(commands)})
    if push:
        b = b.capability("git_push", {"remote": Exact("origin"), "branch": Pattern(push)})
    w = b.holder(hermes_pub).ttl(int(days * 86400)).mint(machine_key)
    info = {"id": w.id, "share": share, "commands": commands, "push": push, "remote": "origin",
            "report": report, "expires_at": str(w.expires_at())}
    return w.to_base64(), info


def _machine(tmp_path, monkeypatch, **grant_kw):
    """A config with one connected machine that granted this Hermes; returns (config, machine key, home)."""
    from tenuo import SigningKey
    key = SigningKey.generate()
    pub = base64.b64encode(key.public_key.to_bytes()).decode()
    monkeypatch.setenv("TEST_WORKER_TOKEN", "s3cret")
    config = cc.load_config({"claude_code": {"listen": "127.0.0.1:0", "machines": {
        "laptop": {"public_key": pub, "token_env": "TEST_WORKER_TOKEN"}}}})
    home = tmp_path / "home"
    hermes = cc.issuer_key(home)
    m = config["machines"]["laptop"]
    m.grant, m.grant_info = _standing_grant(key, grant_kw.pop("to", hermes.public_key), **grant_kw)
    m.root, m.last_seen = "/Users/me/code", time.time()
    return config, key, home


def test_machines_need_listen_and_valid_keys(tmp_path):
    with pytest.raises(ValueError, match="listen"):
        cc.load_config({"claude_code": {"machines": {"m": {"public_key": _key_b64()[1], "token_env": "X"}}}})
    with pytest.raises(Exception):
        cc.load_config({"claude_code": {"listen": "x:1", "machines": {"m": {"public_key": "bad", "token_env": "X"}}}})


def test_a_machine_without_a_grant_is_refused(tmp_path, monkeypatch):
    config = _config(tmp_path, monkeypatch)
    with pytest.raises(cc.ClaudeCodeError, match="hasn't given Hermes a grant"):
        cc.build_request(config, {"task": "fix it", "workspace": "calc-demo"}, "sk", config["machines"])


def test_build_request_for_a_machine(tmp_path, monkeypatch):
    config, _, _ = _machine(tmp_path, monkeypatch)
    machines = config["machines"]
    r = cc.build_request(config, {"task": "fix it", "workspace": "calc-demo", "commands": ["git diff"],
                                  "minutes": 999, "branch": "issue 78"}, "sk", machines)
    assert (r.machine, r.workspace, r.commands, r.minutes, r.session_key, r.branch) == \
        ("laptop", "calc-demo", ["git diff", "git add", "git commit"], config["max_minutes"], "sk",
         "claude/issue-78")
    # Without a push, the owner's commands stand as chosen.
    assert cc.build_request(config, {"task": "x", "workspace": "a", "commands": ["git diff"], "push": False},
                            "", machines).commands == ["git diff"]
    assert cc.build_request(config, {"task": "x", "workspace": "a", "branch": "claude/x"}, "", machines).branch \
        == "claude/x"
    assert cc.build_request(config, {"task": "x", "workspace": "a", "read_only": True}, "", machines).branch == ""
    assert cc.build_request(config, {"task": "x", "workspace": "a", "push": False}, "", machines).branch == ""
    # The machine's grant decides the commands, not Hermes's config.
    with pytest.raises(cc.ClaudeCodeError, match="not allowed"):
        cc.build_request(config, {"task": "x", "workspace": "a", "commands": ["npm test"]}, "", machines)
    for bad in ("../x", "/etc", "a/../b", "a b"):
        with pytest.raises(cc.ClaudeCodeError):
            cc.build_request(config, {"task": "x", "workspace": bad}, "", machines)
    with pytest.raises(cc.ClaudeCodeError):
        cc.build_request(config, {"task": "x", "workspace": "a", "machine": "other"}, "", machines)


def test_card_says_what_is_granted(tmp_path, monkeypatch):
    config, _, _ = _machine(tmp_path, monkeypatch)
    r = cc.build_request(config, {"task": "review", "workspace": "calc-demo", "commands": ["git diff"],
                                  "read_only": True, "minutes": 10}, "", config["machines"])
    card = cc.describe(r)
    assert "laptop" in card and "calc-demo" in card and "git diff" in card and "10 min" in card
    assert "read files" in card and "edit" not in card.split("May:")[1].split("\n")[0]
    assert "Never: git push" in card and "/claude" in card
    r = cc.build_request(config, {"task": "fix", "workspace": "calc-demo", "branch": "issue-78"}, "",
                         config["machines"])
    card = cc.describe(r)
    assert "Push: only branch claude/issue-78 to origin" in card and "Claude can't push" in card
    assert "status, branch, commit ids" in card


def test_precheck_refuses_what_the_grant_does_not_cover(tmp_path, monkeypatch):
    config, _, home = _machine(tmp_path, monkeypatch)
    hub = cr.Hub(config["machines"])
    ok = cc.build_request(config, {"task": "fix", "workspace": "calc-demo"}, "", hub.machines)
    cc.precheck(home, hub, ok)
    ok.branch = "main"  # a branch outside claude/*
    with pytest.raises(cc.ClaudeCodeError, match="outside laptop's grant"):
        cc.precheck(home, hub, ok)
    ok.branch, ok.commands = "claude/x", ["git push"]
    with pytest.raises(cc.ClaudeCodeError, match="outside laptop's grant"):
        cc.precheck(home, hub, ok)


def test_precheck_refuses_a_grant_to_another_hermes_or_signed_by_someone_else(tmp_path, monkeypatch):
    from tenuo import SigningKey
    config, _, home = _machine(tmp_path, monkeypatch, to=SigningKey.generate().public_key)
    hub = cr.Hub(config["machines"])
    r = cc.build_request(config, {"task": "fix", "workspace": "calc-demo"}, "", hub.machines)
    with pytest.raises(cc.ClaudeCodeError, match="different Hermes key"):
        cc.precheck(home, hub, r)
    # A grant Hermes signed itself (not the machine) doesn't check out.
    hermes = cc.issuer_key(home)
    hub.machines["laptop"].grant, _ = _standing_grant(hermes, hermes.public_key)
    with pytest.raises(cc.ClaudeCodeError, match="doesn't check out"):
        cc.precheck(home, hub, r)


def _fake_worker(hub, machine_key, base_url, pub, report_extra=None):
    """Stands in for `tenuo-claude worker`: checks the job against its own key, reports signed."""
    import tenuo_core
    from tenuo import Authorizer
    from tenuo.meta import argument_json
    seen = {}

    def loop():
        job = None
        for _ in range(20):
            status, job = _call(base_url + "/claude/next", pub=pub)
            if job:
                break
        chain = list(tenuo_core.decode_warrant_stack_base64(job["warrant"]))
        Authorizer(trusted_roots=[machine_key.public_key]).verify_chain(chain)
        seen["job"], seen["chain"] = job, chain
        report = {"ok": True, "branch": job["branch"], "pushed": True, "commits": ["a1b2c3d"],
                  "allowed": 7, "denied_count": 2, "receipts": {"count": 10, "head": "h", "chain_ok": True,
                                                               "signed_by": pub},
                  "grant": chain[0].id, "warrant": chain[-1].id, "report": "summary", **(report_extra or {})}
        ts = int(time.time())
        env = tenuo_core.sign_meta(chain, machine_key, cc.REPORT_TOOL, argument_json(report), ts)
        report["proof"] = {"warrant": env["warrant"], "signature": env["signature"], "ts": ts}
        _call(base_url + f"/claude/jobs/{job['id']}/result", "POST", report, pub=pub)
    t = threading.Thread(target=loop, daemon=True)
    t.start()
    return seen, t


def test_run_on_machine_narrows_the_grant_and_checks_the_signed_report(tmp_path, monkeypatch):
    config, key, home = _machine(tmp_path, monkeypatch)
    from http.server import ThreadingHTTPServer
    hub = cr.Hub(config["machines"])
    hub.server = ThreadingHTTPServer(("127.0.0.1", 0), cr._handler(hub))
    threading.Thread(target=hub.server.serve_forever, daemon=True).start()
    monkeypatch.setattr(cr, "POLL_SECONDS", 5)
    base = f"http://127.0.0.1:{hub.server.server_address[1]}"
    pub = config["machines"]["laptop"].public_key
    m = hub.machines["laptop"]
    grant_b64, info = m.grant, m.grant_info

    seen, t = _fake_worker(hub, key, base, pub)
    # The worker's poll refreshes the grant from its headers; keep it.
    monkeypatch.setattr(hub, "next_job", lambda machine, root, public_key, wait, grant="", grant_info="":
                        cr.Hub.next_job(hub, machine, root, public_key, wait, grant_b64,
                                        base64.b64encode(json.dumps(info).encode()).decode()))
    r = cc.build_request(config, {"task": "fix issue 78", "workspace": "calc-demo", "branch": "issue-78",
                                  "commands": ["git commit", "python3 -m pytest"]}, "owner", hub.machines)
    out = cc.run_on_machine(config, home, hub, r)
    t.join(5)
    root, leaf = seen["chain"]
    assert root.id == info["id"] and leaf.depth == 1
    assert leaf.authorized_holder.to_bytes() == key.public_key.to_bytes()
    assert seen["job"]["folder"] == "calc-demo" and seen["job"]["branch"] == "claude/issue-78"
    assert out["ok"] and out["pushed"] and out["branch"] == "claude/issue-78" and out["verified"] == "signed"
    assert "result" not in out  # summary report: Claude's words don't come back
    text = cc.finished_text(r, out)
    assert "Pushed claude/issue-78: a1b2c3d" in text and "Report: signed by laptop ✓" in text
    audit = cc.audit_text(home)
    assert r.id in audit and "approval signed ✓" in audit and "report signed" in audit
    # A changed report no longer verifies.
    run_dir = next((home / "hermes-tenuo" / "claude-code" / "runs").glob("*"))
    result = json.loads((run_dir / "result.json").read_text())
    result.pop("verified")
    assert cc.verify_report({**result, "pushed": False}, pub, root.id) == "bad signature"
    assert cc.verify_report(result, pub, "another-grant") == "signed under another grant"
    approval = json.loads((run_dir / "approval.json").read_text())
    assert cc.approval_ok(approval, cc.issuer_key(home))
    assert not cc.approval_ok({**approval, "branch": "main"}, cc.issuer_key(home))


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
