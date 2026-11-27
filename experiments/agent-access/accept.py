# /// script
# requires-python = ">=3.10"
# dependencies = ["tenuo[mcp]==0.3.8", "httpx"]
# ///
"""Guest side: pair with one link, then call the shared server with the picked-up warrant.

  uv run accept.py 'http://HOST:8765/#HG-XXXX-XXXX' --as Alex --agent "Claude Code"
  uv run accept.py --call list_events day=2026-11-27

This file stands alone, so a guest can run it straight from its URL. The key is
created on this machine and never leaves it. Before each call the latest warrant
is fetched, so the owner's changes need no action here.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import os
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from tenuo import PublicKey, SigningKey, Warrant, configure, key_scope, warrant_scope
from tenuo.mcp import SecureMCPClient

HOME = Path(os.environ.get("TENUO_GUEST_HOME", Path.home() / ".tenuo-agent-access"))


# --- small helpers -------------------------------------------------------------------
def b64(data: bytes) -> str:
    return base64.b64encode(bytes(data)).decode()


def unb64(text: str) -> bytes:
    return base64.b64decode(text, validate=True)


def fingerprint(public_key_bytes: bytes) -> str:
    digest = hashlib.sha256(bytes(public_key_bytes)).hexdigest()[:8]
    return f"{digest[:4]}-{digest[4:]}"


def write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def load_or_create_key(path: Path) -> SigningKey:
    if path.exists():
        return SigningKey.from_bytes(unb64(path.read_text().strip()))
    key = SigningKey.generate()
    write_private(path, b64(key.secret_key_bytes()).encode())
    return key


def read_state(home: Path):
    try:
        return json.loads((home / "server.json").read_text())
    except FileNotFoundError:
        return None


def write_state(home: Path, value: dict) -> None:
    write_private(home / "server.json", json.dumps(value, indent=2).encode())


def until(warrant: Warrant) -> str:
    value = warrant.expires_at()
    when = (datetime.fromisoformat(value.replace("Z", "+00:00")) if isinstance(value, str)
            else datetime.fromtimestamp(value))
    return when.astimezone().strftime("%a %H:%M")


# --- pairing ---------------------------------------------------------------------------
def fetch(server: str, holder: str):
    r = httpx.get(f"{server}/tenuo/warrant", params={"holder": holder}, timeout=10)
    body = r.json()
    w = Warrant.from_base64(body["warrant"]) if body.get("warrant") else None
    return body["status"], w, body.get("issuer")


def describe(w: Warrant) -> str:
    return f"You can use {', '.join(sorted(w.tools))} until {until(w)}."


def pair(link: str, person: str, agent: str, home: Path, wait: float) -> int:
    parts = urlsplit(link.strip())
    code = parts.fragment
    server = f"{parts.scheme}://{parts.netloc}"
    if not code or not parts.netloc:
        print("✗ That doesn't look like a whole invitation link. It ends with #HG-…; paste all of it.")
        return 2
    key = load_or_create_key(home / "key")
    holder = b64(key.public_key_bytes())
    print(f"✓ Created a key for this computer (fingerprint {fingerprint(key.public_key_bytes())})")
    try:
        r = httpx.post(f"{server}/tenuo/pair", timeout=10,
                       json={"code": code, "public_key": holder, "person": person, "agent": agent})
    except httpx.HTTPError:
        print(f"✗ Couldn't reach {parts.netloc}. Check that you're on a network that can reach it, "
              "and that the owner's server is running.")
        return 2
    if r.status_code != 202:
        print(f"✗ {r.json().get('error', r.text)}")
        return 2
    print(f"✓ Sent it to {parts.netloc}")
    print(f"… Waiting for the owner to approve. Tell them your key is {fingerprint(key.public_key_bytes())}.")
    write_state(home, {"server": server, "holder": holder})
    return wait_for_approval(home, wait)


def wait_for_approval(home: Path, wait: float) -> int:
    state = read_state(home)
    deadline = time.time() + wait
    while True:
        status, w, issuer = fetch(state["server"], state["holder"])
        if status == "approved":
            # Pin the owner's key now; later pickups must match it.
            write_state(home, {**state, "issuer": issuer})
            print(f"✓ Approved. {describe(w)}")
            print(f"  Try it: {sys.argv[0]} --call {sorted(w.tools)[0]} …")
            return 0
        if status in ("declined", "ended"):
            print("✗ The owner declined this request.")
            return 1
        if time.time() >= deadline:
            print(f"Still waiting. Run '{sys.argv[0]} --status' later to check again.")
            return 1
        time.sleep(1)


# --- calling ---------------------------------------------------------------------------
async def call(home: Path, tool: str, args: dict) -> int:
    state = read_state(home)
    if not state or "issuer" not in state:
        print("✗ Not paired yet. Run this with the link you were sent.")
        return 2
    status, w, issuer = fetch(state["server"], state["holder"])
    if issuer and issuer != state["issuer"]:
        print("✗ This server's owner key changed since you paired. Not calling it.")
        return 2
    if status != "approved":
        print("✗ The owner ended this access." if status == "ended" else f"✗ Access isn't active ({status}).")
        return 2
    key = load_or_create_key(home / "key")
    configure(issuer_key=key, trusted_roots=[PublicKey.from_bytes(unb64(state["issuer"]))])
    async with SecureMCPClient(url=f"{state['server']}/mcp", transport="http", inject_warrant=True) as client:
        if tool not in client.tools:
            print(f"✗ This server has no tool called {tool}. It offers: {', '.join(sorted(client.tools))}.")
            return 2
        with warrant_scope(w), key_scope(key):
            try:
                result = await client.tools[tool](**args)
            except Exception as exc:  # refusals surface as tool errors
                print(f"✗ Refused: {str(exc).splitlines()[0]}")
                return 1
    parts = result if isinstance(result, list) else [result]
    print("✓ " + "\n".join(getattr(p, "text", str(p)) for p in parts))
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="accept", description="Use access someone shared with you.")
    ap.add_argument("link", nargs="?", help="the invitation link you were sent")
    ap.add_argument("--as", dest="person", default="guest", help="your name, shown to the owner")
    ap.add_argument("--agent", default="agent", help="your agent's name, shown to the owner")
    ap.add_argument("--home", type=Path, default=HOME, help=f"where your key is kept (default {HOME})")
    ap.add_argument("--wait", type=float, default=300, help="seconds to wait for approval")
    ap.add_argument("--status", action="store_true", help="check whether the owner has approved")
    ap.add_argument("--call", nargs="+", metavar=("TOOL", "ARG=VALUE"), help="call a shared tool")
    args = ap.parse_args(argv)
    if args.call:
        tool, *pairs = args.call
        bad = [p for p in pairs if "=" not in p]
        if bad:
            ap.error(f"write arguments as name=value, for example day=2026-11-27 (got {bad[0]!r})")
        return asyncio.run(call(args.home, tool, dict(p.split("=", 1) for p in pairs)))
    if args.status:
        if not read_state(args.home):
            print("✗ Not paired yet. Run this with the link you were sent.")
            return 2
        return wait_for_approval(args.home, 0)
    if not args.link:
        ap.error("paste the invitation link you were sent")
    return pair(args.link, args.person, args.agent, args.home, args.wait)


if __name__ == "__main__":
    raise SystemExit(main())
