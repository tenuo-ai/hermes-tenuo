# /// script
# requires-python = ">=3.10"
# dependencies = ["tenuo[mcp,fastmcp]==0.3.8", "httpx"]
# ///
"""Owner side: create an invitation, approve a paired agent, extend or end access.

The issuer key lives in OWNER/private and never leaves it. The server only reads
OWNER/public (issuer public key, invitations, pairings, revocation list).
"""

from __future__ import annotations

import argparse
import secrets
import sys
import time
from pathlib import Path

from tenuo import SignedRevocationList, Warrant, Wildcard

from common import (
    b64, code_hash, fingerprint, load_or_create_key, public_bytes, public_key,
    read_json, unb64, until, write_json, write_private,
)

# Where a guest runs the client from, without cloning anything.
ACCEPT_URL = ("https://raw.githubusercontent.com/tenuo-ai/hermes-tenuo/"
              "experiments/agent-access-pairing/experiments/agent-access/accept.py")

# Scopes this experiment offers, in the words a card would use.
SCOPES = {
    "calendar.read": {
        "label": "Calendar: read events",
        "tools": {"list_events": {"day": Wildcard()}},
    },
    "calendar.write": {
        "label": "Calendar: read and add events",
        "tools": {"list_events": {"day": Wildcard()}, "add_event": {"day": Wildcard(), "title": Wildcard()}},
    },
}


class Owner:
    def __init__(self, home: Path):
        self.private = home / "private"
        self.public = home / "public"
        self.issuer = load_or_create_key(self.private / "issuer.key")
        write_private(self.public / "issuer.pub", b64(public_bytes(self.issuer)).encode())

    # --- files the server reads ---------------------------------------------------
    @property
    def invites_path(self):
        return self.public / "invites.json"

    @property
    def pairings_path(self):
        return self.public / "pairings.json"

    @property
    def srl_path(self):
        return self.public / "revocations.srl"

    # --- actions ------------------------------------------------------------------
    def share(self, person: str, scope: str, seconds: int, server: str) -> str:
        code = "HG-" + "-".join(secrets.token_hex(2).upper() for _ in range(2))
        invites = read_json(self.invites_path, {})
        invites[code_hash(code)] = {
            "person": person, "scope": scope, "seconds": seconds,
            "expires": time.time() + 86400, "used": False,
        }
        write_json(self.invites_path, invites)
        return f"{server.rstrip('/')}/#{code}"

    def mint(self, holder_b64: str, scope: str, seconds: int) -> Warrant:
        builder = Warrant.mint_builder().holder(public_key(unb64(holder_b64))).ttl(seconds)
        for tool, args in SCOPES[scope]["tools"].items():
            builder = builder.capability(tool, **args)
        return builder.mint(self.issuer)

    def approve(self, holder_b64: str) -> Warrant:
        pairings = read_json(self.pairings_path, {})
        p = pairings[holder_b64]
        w = self.mint(holder_b64, p["scope"], p["seconds"])
        p.update(status="approved", warrant=w.to_base64(), warrant_id=w.id, approved_at=time.time())
        write_json(self.pairings_path, pairings)
        return w

    def decline(self, holder_b64: str) -> None:
        pairings = read_json(self.pairings_path, {})
        pairings[holder_b64]["status"] = "declined"
        write_json(self.pairings_path, pairings)

    def change(self, holder_b64: str, *, scope: str | None = None, seconds: int | None = None) -> Warrant:
        """Extend or narrow: a new warrant to the same key; the old one is revoked."""
        pairings = read_json(self.pairings_path, {})
        p = pairings[holder_b64]
        old = p["warrant_id"]
        if scope:
            p["scope"] = scope
        if seconds:
            p["seconds"] = seconds
        w = self.mint(holder_b64, p["scope"], p["seconds"])
        p.update(warrant=w.to_base64(), warrant_id=w.id)
        write_json(self.pairings_path, pairings)
        self.revoke([old])
        return w

    def end(self, holder_b64: str) -> None:
        pairings = read_json(self.pairings_path, {})
        p = pairings[holder_b64]
        p["status"] = "ended"
        write_json(self.pairings_path, pairings)
        self.revoke([p["warrant_id"]])

    def revoke(self, ids):
        ids = set(ids)
        version = 1
        if self.srl_path.exists():
            current = SignedRevocationList.from_bytes(self.srl_path.read_bytes())
            ids |= set(current.revoked_ids)
            version = current.version + 1
        builder = SignedRevocationList.builder()
        for i in sorted(ids):
            builder = builder.revoke(i)
        write_private(self.srl_path, builder.version(version).build(self.issuer).to_bytes())

    def pending(self):
        return {k: v for k, v in read_json(self.pairings_path, {}).items() if v["status"] == "pending"}


def card(holder_b64: str, p: dict) -> str:
    hours = p["seconds"] / 3600
    return (
        f"{p['person']} connected an agent ({p.get('agent', 'agent')}), key {fingerprint(unb64(holder_b64))}.\n"
        f"  {SCOPES[p['scope']]['label']} · for {hours:g} h"
    )


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="owner")
    ap.add_argument("--home", type=Path, required=True)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("share")
    s.add_argument("person")
    s.add_argument("scope", choices=SCOPES)
    s.add_argument("--hours", type=float, default=24)
    s.add_argument("--server", required=True)
    a = sub.add_parser("approve")
    a.add_argument("--yes", action="store_true", help="approve without asking (for scripts)")
    a.add_argument("--wait", type=float, default=0, help="seconds to wait for an agent to connect")
    c = sub.add_parser("change")
    c.add_argument("fingerprint")
    c.add_argument("--scope", choices=SCOPES)
    c.add_argument("--hours", type=float)
    e = sub.add_parser("end")
    e.add_argument("fingerprint")
    sub.add_parser("list")
    args = ap.parse_args(argv)
    owner = Owner(args.home)

    def by_fp(fp):
        for k, v in read_json(owner.pairings_path, {}).items():
            if fingerprint(unb64(k)) == fp:
                return k
        sys.exit(f"No agent with key {fp}.")

    if args.cmd == "share":
        link = owner.share(args.person, args.scope, int(args.hours * 3600), args.server)
        print(f"{SCOPES[args.scope]['label']} for {args.person}, {args.hours:g} h from when you approve.")
        print(f"Send {args.person} this command (it needs uv, https://docs.astral.sh/uv/):\n")
        print(f"  uv run {ACCEPT_URL} '{link}' --as {args.person}\n")
        print(f"The link works once, for 24 hours. When {args.person} runs it, approve with:")
        print(f"  uv run owner.py --home {args.home} approve --wait 600")
    elif args.cmd == "approve":
        waiting = owner.pending()
        if not waiting and args.wait:
            print("Waiting for an agent to connect…")
            deadline = time.time() + args.wait
            while not waiting and time.time() < deadline:
                time.sleep(1)
                waiting = owner.pending()
        if not waiting:
            print("No agents are waiting.")
        for k, p in waiting.items():
            print(card(k, p))
            print("  Check the key matches what they tell you.")
            ok = args.yes or input("  Approve? [y/N] ").strip().lower() == "y"
            if ok:
                w = owner.approve(k)
                print(f"  Approved until {until(w)}.")
            else:
                owner.decline(k)
                print("  Declined.")
    elif args.cmd == "change":
        k = by_fp(args.fingerprint)
        w = owner.change(k, scope=args.scope, seconds=int(args.hours * 3600) if args.hours else None)
        print(f"Changed. New access until {until(w)}; "
              "their agent picks it up on its next call.")
    elif args.cmd == "end":
        owner.end(by_fp(args.fingerprint))
        print("Ended. Their next call is refused.")
    elif args.cmd == "list":
        for k, p in read_json(owner.pairings_path, {}).items():
            print(f"{fingerprint(unb64(k))}  {p['person']:<10} {p['status']:<9} {SCOPES[p['scope']]['label']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
