"""Two real Hermes agents: A delegates with tenuo_delegate, B enforces. Scripted models on both.

  two_agent.py setup     keys, A's warrant and config, B's ingress pins (run once)
  two_agent.py run       the scenarios; prints PASS/FAIL per scenario
"""

import json
import os
import secrets
import subprocess
import sys
from pathlib import Path

import yaml

LAB = Path.home() / "a2a-d0"
A_HOME, B_HOME = LAB / "a-home", LAB / "b-home"
IMG = os.environ["IMG"]  # any image with Hermes and tenuo installed
PY = "/opt/hermes/.venv/bin/python"


def py(code, *mounts):
    cmd = ["docker", "run", "--rm", "--init", "--user", "1000:1000", "-v", f"{LAB}:/lab", "-v", f"{LAB}/src:/d0src:ro",
           "-e", "PYTHONPATH=/d0src", "--entrypoint", PY, IMG, "-c", code]
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout


def setup():
    A_HOME.mkdir(exist_ok=True)
    out = py("""
import base64, json
from tenuo import SigningKey, Warrant, Wildcard
from hermes_tenuo.a2a_ingress import public_key_b64
b = SigningKey.from_bytes(base64.b64decode(open('/lab/b-home/tenuo/a2a.key').read().strip()))
root, a = SigningKey.generate(), SigningKey.generate()
w = (Warrant.mint_builder().holder(a.public_key)
     .capability('light_get', {'entity_id': Wildcard()})
     .capability('light_set', {'entity_id': Wildcard(), 'state': Wildcard()})
     .capability('tenuo_delegate', {'peer': Wildcard(), 'task': Wildcard(), 'tools': Wildcard(), 'ttl_seconds': Wildcard()})
     .capability('first__write', {'value': Wildcard()})
     .ttl(86400).mint(root))
s = lambda k: base64.b64encode(k.secret_key_bytes()).decode()
print(json.dumps({'root': public_key_b64(root), 'a_pub': public_key_b64(a), 'a_key': s(a),
                  'w_a': w.to_base64(), 'b_pub': public_key_b64(b)}))""")
    d = json.loads(out)
    token = secrets.token_urlsafe(24)
    a_cfg = {
        "model": {"default": "stub", "provider": "custom", "api_mode": "chat_completions",
                  "base_url": "http://d0-model:8080/v1", "api_key": "local-test-not-a-secret"},
        "plugins": {"enabled": ["hermes-tenuo"], "entries": {"hermes-tenuo": {
            "warrant": d["w_a"], "trusted_root": d["root"],
            "audit_log": "/home/hermes/.hermes/tenuo-audit.jsonl",
            "a2a_delegation": {"peers": {"home": {"url": "http://d0-hermes-b:9900/", "public_key": d["b_pub"],
                                                  "token_env": "A2A_TOKEN_HOME"}},
                               "reply_timeout_seconds": 120}}}},
    }
    (A_HOME / "config.yaml").write_text(yaml.safe_dump(a_cfg, sort_keys=False))
    (A_HOME / ".env").write_text(f"TENUO_SIGNING_KEY={d['a_key']}\nA2A_TOKEN_HOME={token}\n")
    (A_HOME / ".env").chmod(0o600)
    b_cfg = yaml.safe_load((B_HOME / "config.stub.yaml").read_text())
    ingress = b_cfg["plugins"]["entries"]["hermes-tenuo"]["a2a_ingress"]
    ingress["peers"] = {"agent-a": d["a_pub"]}
    ingress["trusted_roots"] = [d["root"]]
    (B_HOME / "config.yaml").write_text(yaml.safe_dump(b_cfg, sort_keys=False))
    (LAB / "peer_tokens").write_text(f"agent-a:{token}")
    # B reaches a test MCP server through the Tenuo wrapper, which trusts the same operator root.
    (LAB / "root.pub").write_text(d["root"])
    (LAB / "mcp.json").write_text(json.dumps({"mcpServers": {"first": {
        "command": PY, "args": ["/lab/mcp_backend.py", "/lab/mcp_effects.txt"]}}}))
    subprocess.run(["rm", "-rf", str(B_HOME / "wrapped")], check=True)
    subprocess.run(["docker", "run", "--rm", "--init", "--user", "1000:1000", "-v", f"{LAB}:/lab", "-v", f"{LAB}/src:/d0src:ro",
                    "-v", f"{B_HOME}:/home/hermes/.hermes", "-w", "/lab", "-e", "PYTHONPATH=/d0src", "--entrypoint", PY, IMG,
                    "-m", "hermes_tenuo.cli", "mcp", "wrap", "/lab/mcp.json", "/home/hermes/.hermes/wrapped",
                    "--trust-root", "/lab/root.pub"], check=True)
    b_cfg["mcp_servers"] = {"wrapped": {"command": PY, "args": ["-m", "hermes_tenuo.cli", "mcp", "serve",
                                                              "/home/hermes/.hermes/wrapped"],
                                      "env": {"PYTHONPATH": "/d0src"}}}
    b_cfg["plugins"]["entries"]["hermes-tenuo"]["mcp_proofs"] = {"servers": ["wrapped"]}
    b_cfg.setdefault("platform_toolsets", {}).setdefault("a2a", []).append("wrapped")
    (B_HOME / "config.yaml").write_text(yaml.safe_dump(b_cfg, sort_keys=False))
    print("A key", d["a_pub"][:12], "B key", d["b_pub"][:12], "root", d["root"][:12])


def ask_a(text):
    """One-shot chat on Hermes A (CLI platform: its static warrant applies)."""
    cmd = ["docker", "run", "--rm", "--init", "--user", "1000:1000", "--network", "a2a-d0",
           "-v", f"{A_HOME}:/home/hermes/.hermes", "-v", f"{LAB}/src:/d0src:ro", "-e", "HOME=/home/hermes",
           "-e", "HERMES_HOME=/home/hermes/.hermes", "-e", "PYTHONPATH=/d0src", "--entrypoint", PY, IMG,
           "-m", "hermes_cli.main", "chat", "-q", text, "--oneshot", "-t", "tenuo"]
    return subprocess.run(cmd, capture_output=True, text=True).stdout


def lines(path):
    return path.read_text().splitlines() if path.exists() else []


def b_call(tool, args):
    return "CALL tool_call " + json.dumps({"calls": [{"name": tool, "arguments": args}]})


def delegate(task, tools, peer="home"):
    """A's model calls tenuo_delegate (through tool_call: Hermes defers plugin tools)."""
    return b_call("tenuo_delegate", {"peer": peer, "task": task, "tools": tools, "ttl_seconds": 120})


GUEST = {"light_set": {"entity_id": {"equals": "light.guest_room"}, "state": {"one_of": ["on", "off"]}}}


def run():
    effects = B_HOME / "d0_effects.jsonl"
    a_audit = A_HOME / "tenuo-audit.jsonl"
    cases = [
        ("A delegates the guest light; B turns it on",
         delegate(b_call("light_set", {"entity_id": "light.guest_room", "state": "on"}), GUEST),
         ["light_set:light.guest_room"], "TASK_STATE_COMPLETED"),
        ("A's grant covers the guest light; B's task tries the office",
         delegate(b_call("light_set", {"entity_id": "light.office", "state": "on"}), GUEST), [], "TASK_STATE_COMPLETED"),
        ("A tries to delegate the door, which A does not hold",
         delegate(b_call("door_unlock", {"door": "front"}), {"door_unlock": {"door": {"equals": "front"}}}),
         [], "not within this session's own authority"),
        ("A names a peer it is not paired with",
         delegate(b_call("light_get", {"entity_id": "light.guest_room"}),
                  {"light_get": {"entity_id": {"equals": "light.guest_room"}}}, peer="office"), [], "no paired peer"),
    ]
    wrapped = {"first__write": {"value": {"equals": "verified"}}}
    cases += [
        ("A delegates 'write verified'; B writes it through the Tenuo-wrapped MCP server",
         delegate(b_call("mcp__wrapped__first__write", {"value": "verified"}), wrapped), ["mcp:verified"],
         "TASK_STATE_COMPLETED"),
        ("Same grant; B's task tries to write another value",
         delegate(b_call("mcp__wrapped__first__write", {"value": "changed"}), wrapped), [], "TASK_STATE_COMPLETED"),
    ]
    mcp_effects = LAB / "mcp_effects.txt"
    passed = 0
    for name, prompt, expected, marker in cases:
        m0 = len(lines(mcp_effects))
        e0, a0 = len(lines(effects)), len(lines(a_audit))
        out = ask_a(prompt)
        did = [f"{json.loads(r)['tool']}:{json.loads(r)['args'].get('entity_id') or json.loads(r)['args'].get('door')}"
               for r in lines(effects)[e0:]] + [f"mcp:{v}" for v in lines(mcp_effects)[m0:]]
        a_dec = [f"{json.loads(r)['tool']}:{json.loads(r)['decision']}" for r in lines(a_audit)[a0:]]
        ok = sorted(did) == sorted(expected) and marker in out
        passed += ok
        snippet = out.strip().replace("\n", " ")[-260:]
        print(f"\n## {name} [{'PASS' if ok else 'FAIL'}]\n  A's guard: {sorted(set(a_dec))}\n  B effects: {did}\n  A said: {snippet}")
    print(f"\nTOTAL: {passed}/{len(cases)}")


if __name__ == "__main__":
    {"setup": setup, "run": run}[sys.argv[1]]()
