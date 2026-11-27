"""Guest side: pair with one link, then call the shared server with the picked-up warrant.

  python accept.py 'https://host:8765/#HG-XXXX-XXXX' [--as Alex] [--agent "Claude Code"]
  python accept.py --call list_events day=2026-11-27

The key is created here and never leaves this machine. Before each call the
latest warrant is fetched, so extensions and changes need no action.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from tenuo import Warrant, configure, key_scope, warrant_scope
from tenuo.mcp import SecureMCPClient

from common import b64, public_key, unb64, fingerprint, load_or_create_key, public_bytes, read_json, until, write_json

HOME = Path.home() / ".tenuo-spike-guest"


def pair(link: str, person: str, agent: str, home: Path, wait: float) -> int:
    parts = urlsplit(link)
    code = parts.fragment
    server = f"{parts.scheme}://{parts.netloc}"
    if not code:
        sys.exit("That link has no invitation code after '#'. Paste the whole link.")
    key = load_or_create_key(home / "key")
    holder = b64(public_bytes(key))
    print(f"✓ Created a key for this computer (fingerprint {fingerprint(public_bytes(key))})")
    r = httpx.post(f"{server}/tenuo/pair", json={"code": code, "public_key": holder, "person": person, "agent": agent})
    if r.status_code != 202:
        sys.exit(f"✗ {r.json().get('error', r.text)}")
    print(f"✓ Sent it to {parts.netloc}")
    print("… Waiting for the owner to approve")
    write_json(home / "server.json", {"server": server, "holder": holder})
    deadline = time.time() + wait
    while time.time() < deadline:
        status, w, issuer = fetch(server, holder)
        if status == "approved":
            # Pin the owner's key at pairing; later pickups must match it.
            write_json(home / "server.json", {"server": server, "holder": holder, "issuer": issuer})
            print(f"✓ Approved. {describe(w)}")
            print(f"Add this server to your agent: {server}/mcp")
            return 0
        if status in ("declined", "ended"):
            sys.exit("✗ The owner declined this request.")
        time.sleep(1)
    print("Still waiting. Run this command again later to check.")
    return 1


def fetch(server: str, holder: str):
    r = httpx.get(f"{server}/tenuo/warrant", params={"holder": holder})
    body = r.json()
    w = Warrant.from_base64(body["warrant"]) if body.get("warrant") else None
    return body["status"], w, body.get("issuer")


def describe(w: Warrant) -> str:
    tools = ", ".join(sorted(w.tools))
    ends = until(w)
    return f"You can use {tools} until {ends}."


async def call(home: Path, tool: str, args: dict) -> int:
    state = read_json(home / "server.json", None)
    if not state:
        sys.exit("Not paired yet. Run accept.py with the link you were sent.")
    status, w, issuer = fetch(state["server"], state["holder"])
    if issuer and issuer != state.get("issuer"):
        print("✗ This server's owner key changed since you paired. Not calling it.")
        return 2
    if status == "ended":
        print("✗ The owner ended this access.")
        return 2
    if status != "approved":
        print(f"✗ Access isn't active ({status}).")
        return 2
    key = load_or_create_key(home / "key")
    configure(issuer_key=key, trusted_roots=[public_key(unb64(state["issuer"]))])
    async with SecureMCPClient(url=f"{state['server']}/mcp", transport="http", inject_warrant=True) as client:
        with warrant_scope(w), key_scope(key):
            try:
                result = await client.tools[tool](**args)
            except Exception as exc:  # denials surface as tool errors
                print(f"✗ Refused: {str(exc).splitlines()[0]}")
                return 1
    text = "\n".join(getattr(part, "text", str(part)) for part in (result if isinstance(result, list) else [result]))
    print(f"✓ {text}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="accept")
    ap.add_argument("link", nargs="?")
    ap.add_argument("--as", dest="person", default="guest")
    ap.add_argument("--agent", default="agent")
    ap.add_argument("--home", type=Path, default=HOME)
    ap.add_argument("--wait", type=float, default=300)
    ap.add_argument("--call", nargs="+", metavar=("TOOL", "ARG=VALUE"))
    args = ap.parse_args(argv)
    if args.call:
        tool, *pairs = args.call
        return asyncio.run(call(args.home, tool, dict(p.split("=", 1) for p in pairs)))
    if not args.link:
        ap.error("paste the link you were sent")
    return pair(args.link, args.person, args.agent, args.home, args.wait)


if __name__ == "__main__":
    raise SystemExit(main())
