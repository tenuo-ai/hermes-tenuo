"""Multi-user gateway: one warrant per session.

When a Telegram / Discord / Slack session starts, call
`guard.set_session_warrant(session_id, warrant)`. Clear it on session end.
Do not rely on the single-agent child heuristic for concurrent users.

    python gateway_multiuser.py
"""

from __future__ import annotations

from typing import Optional

from tenuo import SigningKey, Subpath, Warrant, Wildcard
from hermes_tenuo import HermesGuard

control_key = SigningKey.generate()
gateway_signing_key = SigningKey.generate()


def make_warrant_for_user(user_role: str) -> Optional[Warrant]:
    if user_role == "admin":
        return (
            Warrant.mint_builder()
            .holder(gateway_signing_key.public_key)
            .capability("read_file", path=Subpath("/data"))
            .capability("write_file", path=Subpath("/data"), content=Wildcard())
            .capability("web_search", query=Wildcard())
            .capability("terminal", command=Wildcard())
            .capability("memory", action=Wildcard(), key=Wildcard())
            .ttl(3600)
            .mint(control_key)
        )
    if user_role == "analyst":
        return (
            Warrant.mint_builder()
            .holder(gateway_signing_key.public_key)
            .capability("read_file", path=Subpath("/data/reports"))
            .capability("web_search", query=Wildcard())
            .capability("memory", action=Wildcard(), key=Wildcard())
            .ttl(1800)
            .mint(control_key)
        )
    if user_role == "viewer":
        return (
            Warrant.mint_builder()
            .holder(gateway_signing_key.public_key)
            .capability("read_file", path=Subpath("/data/public"))
            .capability("web_search", query=Wildcard())
            .ttl(900)
            .mint(control_key)
        )
    return None


guard = HermesGuard(
    signing_key=gateway_signing_key,
    trusted_roots=[control_key.public_key],
    on_denial="block",
)


def session_start(session_id: str, user_role: str) -> None:
    warrant = make_warrant_for_user(user_role)
    if warrant:
        guard.set_session_warrant(session_id, warrant, gateway_signing_key)
        print(f"  Session {session_id} ({user_role}): warrant registered")
    else:
        print(f"  Session {session_id} (unknown): no warrant — calls are blocked")


def session_end(session_id: str) -> None:
    guard.clear_session_warrant(session_id)


def call(tool: str, args: dict, session_id: str) -> None:
    result = guard.pre_tool_call(tool, args, session_id=session_id)
    status = f"BLOCKED — {result['message']}" if result else "ALLOWED"
    print(f"    {tool}({args}): {status}")


if __name__ == "__main__":
    users = [
        ("session-alice", "admin"),
        ("session-bob", "analyst"),
        ("session-carol", "viewer"),
        ("session-eve", "unknown"),
    ]

    for session_id, role in users:
        print(f"\n{role.upper()} ({session_id}):")
        session_start(session_id, role)
        call("web_search", {"query": "quarterly results"}, session_id)
        call("read_file", {"path": "/data/reports/q1.csv"}, session_id)
        call("write_file", {"path": "/data/output/x.txt", "content": "hi"}, session_id)
        call("terminal", {"command": "ls /data"}, session_id)
        session_end(session_id)
