# /// script
# requires-python = ">=3.10"
# dependencies = ["tenuo[mcp,fastmcp]==0.3.8", "httpx"]
# ///
"""An MCP server (a calendar fixture) that checks Tenuo chains and hands out warrants.

Reads only OWNER/public: the issuer public key, invitations, pairings and the
revocation list. It can't mint access: the issuer private key isn't here.

Routes next to /mcp:
  POST /tenuo/pair     {"code", "public_key", "person", "agent"}  -> 202 pending
  GET  /tenuo/warrant?holder=<b64 public key>                     -> 200 warrant | 202 | 410
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

from fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse
from tenuo import Authorizer, SignedRevocationList
from tenuo.mcp import MCPVerifier, TenuoMiddleware

from common import code_hash, fingerprint, public_key, read_json, unb64, write_json

EVENTS = {"2026-11-27": ["09:00 Standup", "14:00 Dentist"], "2026-11-28": ["All day: offsite"]}
MAX_ATTEMPTS = 10  # pairing attempts per minute, all callers


def build(home: Path) -> FastMCP:
    public = home / "public"
    issuer = public_key(unb64((public / "issuer.pub").read_text().strip()))
    authorizer = Authorizer(trusted_roots=[issuer])
    verifier = MCPVerifier(authorizer=authorizer, require_warrant=True)
    srl_state = {"mtime": None}
    attempts: list[float] = []

    def refresh_revocations():
        path = public / "revocations.srl"
        if not path.exists():
            return
        mtime = path.stat().st_mtime_ns
        if mtime != srl_state["mtime"]:
            srl = SignedRevocationList.from_bytes(path.read_bytes())
            srl.verify(issuer)
            authorizer.set_revocation_list(srl)
            srl_state["mtime"] = mtime

    class Checked(TenuoMiddleware):
        async def on_call_tool(self, context, call_next):
            refresh_revocations()
            return await super().on_call_tool(context, call_next)

    mcp = FastMCP("calendar", middleware=[Checked(verifier)])

    @mcp.tool()
    def list_events(day: str) -> str:
        """List calendar events on a day (YYYY-MM-DD)."""
        return "\n".join(EVENTS.get(day, [])) or "Nothing scheduled."

    @mcp.tool()
    def add_event(day: str, title: str) -> str:
        """Add an event to the calendar."""
        EVENTS.setdefault(day, []).append(title)
        return f"Added {title!r} on {day}."

    @mcp.custom_route("/tenuo/pair", methods=["POST"])
    async def pair(request: Request):
        now = time.time()
        attempts[:] = [t for t in attempts if now - t < 60]
        if len(attempts) >= MAX_ATTEMPTS:
            return JSONResponse({"error": "Too many attempts. Try again in a minute."}, 429)
        attempts.append(now)
        try:
            body = await request.json()
            code, holder = str(body["code"]), str(body["public_key"])
            public_key(unb64(holder))
        except Exception:
            return JSONResponse({"error": "That request isn't a valid pairing."}, 400)
        invites = read_json(public / "invites.json", {})
        invite = invites.get(code_hash(code))
        if not invite or invite["used"] or invite["expires"] < now:
            return JSONResponse({"error": "This invitation isn't valid. Ask for a new one."}, 404)
        invite["used"] = True
        write_json(public / "invites.json", invites)
        pairings = read_json(public / "pairings.json", {})
        pairings[holder] = {
            "person": invite["person"], "agent": str(body.get("agent", "agent"))[:40],
            "scope": invite["scope"], "seconds": invite["seconds"],
            "status": "pending", "requested_at": now,
        }
        write_json(public / "pairings.json", pairings)
        print(f"{invite['person']}'s agent connected (key {fingerprint(unb64(holder))}). "
              f"Approve it with: owner.py --home {home} approve", flush=True)
        return JSONResponse({"status": "pending", "fingerprint": fingerprint(unb64(holder))}, 202)

    @mcp.custom_route("/tenuo/warrant", methods=["GET"])
    async def warrant(request: Request):
        p = read_json(public / "pairings.json", {}).get(request.query_params.get("holder", ""))
        if p is None:
            return JSONResponse({"status": "unknown"}, 404)
        if p["status"] == "pending":
            return JSONResponse({"status": "pending"}, 202)
        if p["status"] in ("ended", "declined"):
            return JSONResponse({"status": p["status"]}, 410)
        return JSONResponse({"status": "approved", "warrant": p["warrant"], "name": mcp.name,
                             "issuer": (public / "issuer.pub").read_text().strip()})

    return mcp


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--home", type=Path, required=True)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8765)
    args = ap.parse_args()
    if not (args.home / "public" / "issuer.pub").exists():
        raise SystemExit(f"No owner setup in {args.home}. Run owner.py --home {args.home} share … first.")
    where = "this machine only" if args.host in ("127.0.0.1", "localhost") else "other machines too"
    print(f"Serving the calendar on port {args.port} ({where}). Agents connect to /mcp.", flush=True)
    build(args.home).run(transport="http", host=args.host, port=args.port, show_banner=False)


if __name__ == "__main__":
    main()
