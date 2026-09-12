"""Scripted allow/deny transcript. No Hermes process, no API key."""

from __future__ import annotations

from typing import Any, Optional

from tenuo import SigningKey, Subpath, Warrant, Wildcard

from hermes_tenuo.hermes_guard import HermesGuard

# Lines CI and the README both pin. Do not reword without updating both.
CRON_ALLOW = "ALLOW  read_file  path=/data/reports/q3.csv"
CRON_DENY_PASSWD = "DENY   read_file  path=/etc/passwd"
CRON_DENY_TERMINAL = "DENY   terminal  command=ls"
CHILD_ALLOW_SEARCH = "[researcher] ALLOW  web_search  query=AI papers 2026"
CHILD_DENY_WRITE = "[researcher] DENY   write_file  path=/data/output/x.md"
VIEWER_DENY_REPORTS = "[viewer] DENY   read_file  path=/data/reports/q1.csv"


def _args_label(args: dict[str, Any]) -> str:
    parts = []
    for key, value in args.items():
        if key == "content":
            continue
        text = str(value)
        if len(text) > 40:
            text = text[:37] + "..."
        parts.append(f"{key}={text}")
    return "  ".join(parts)


def _call(
    lines: list[str],
    guard: HermesGuard,
    tool: str,
    args: dict[str, Any],
    *,
    session_id: str = "",
    tag: str = "",
) -> Optional[dict[str, Any]]:
    result = guard.pre_tool_call(tool, args, session_id=session_id)
    status = "DENY  " if result else "ALLOW "
    label = _args_label(args)
    prefix = f"[{tag}] " if tag else ""
    line = f"  {prefix}{status} {tool}"
    if label:
        line = f"{line}  {label}"
    lines.append(line.rstrip())
    if result:
        message = str(result.get("message") or "").strip()
        if message:
            lines.append(f"         {message}")
    return result


def render_demo() -> str:
    lines: list[str] = [
        "Give each Hermes agent a signed, expiring permission slip.",
        "Nothing outside it runs. No Hermes process, no API key.",
        "",
        "== Cron ==",
        "Nightly job: read /data/reports, write /tmp/nightly, then stop.",
    ]

    control = SigningKey.generate()
    cron_key = SigningKey.generate()
    cron_warrant = (
        Warrant.mint_builder()
        .holder(cron_key.public_key)
        .capability("read_file", path=Subpath("/data/reports"))
        .capability("write_file", path=Subpath("/tmp/nightly"), content=Wildcard())
        .capability("memory", action=Wildcard(), key=Wildcard())
        .ttl(3600)
        .mint(control)
    )
    cron = HermesGuard(
        warrant=cron_warrant,
        signing_key=cron_key,
        trusted_roots=[control.public_key],
        on_denial="block",
    )
    _call(lines, cron, "read_file", {"path": "/data/reports/q3.csv"}, session_id="cron")
    _call(
        lines,
        cron,
        "write_file",
        {"path": "/tmp/nightly/report.md", "content": "# Report"},
        session_id="cron",
    )
    _call(lines, cron, "read_file", {"path": "/etc/passwd"}, session_id="cron")
    _call(lines, cron, "terminal", {"command": "ls"}, session_id="cron")

    lines.extend(
        [
            "",
            "== delegate_task ==",
            "Authority is traced across the child session.",
        ]
    )
    orch_key = SigningKey.generate()
    orch_warrant = (
        Warrant.mint_builder()
        .holder(orch_key.public_key)
        .capability("read_file", path=Subpath("/data"))
        .capability("write_file", path=Subpath("/data/output"), content=Wildcard())
        .capability("web_search", query=Wildcard())
        .capability("delegate_task", task=Wildcard(), context=Wildcard())
        .ttl(7200)
        .mint(control)
    )
    child_warrant = (
        Warrant.mint_builder()
        .holder(orch_key.public_key)
        .capability("web_search", query=Wildcard())
        .ttl(600)
        .mint(control)
    )
    orch = HermesGuard(
        warrant=orch_warrant,
        signing_key=orch_key,
        child_warrant=child_warrant,
        trusted_roots=[control.public_key],
        on_denial="block",
    )
    _call(
        lines,
        orch,
        "read_file",
        {"path": "/data/input.csv"},
        session_id="orchestrator",
        tag="orchestrator",
    )
    _call(
        lines,
        orch,
        "delegate_task",
        {"task": "research q3", "context": "web_search only"},
        session_id="orchestrator",
        tag="orchestrator",
    )
    # Same injection subagent_start performs after delegate_task is allowed.
    orch.set_session_warrant("researcher", child_warrant, orch_key)
    _call(
        lines,
        orch,
        "web_search",
        {"query": "AI papers 2026"},
        session_id="researcher",
        tag="researcher",
    )
    _call(
        lines,
        orch,
        "write_file",
        {"path": "/data/output/x.md", "content": "..."},
        session_id="researcher",
        tag="researcher",
    )

    lines.extend(
        [
            "",
            "== Gateway ==",
            "Analyst and viewer on the same server, different warrants.",
        ]
    )
    gw_key = SigningKey.generate()

    def role_warrant(path: str) -> Any:
        return (
            Warrant.mint_builder()
            .holder(gw_key.public_key)
            .capability("read_file", path=Subpath(path))
            .capability("web_search", query=Wildcard())
            .ttl(1800)
            .mint(control)
        )

    gw = HermesGuard(
        signing_key=gw_key,
        trusted_roots=[control.public_key],
        on_denial="block",
    )
    gw.set_session_warrant("session-analyst", role_warrant("/data/reports"), gw_key)
    gw.set_session_warrant("session-viewer", role_warrant("/data/public"), gw_key)
    _call(
        lines,
        gw,
        "read_file",
        {"path": "/data/reports/q1.csv"},
        session_id="session-analyst",
        tag="analyst",
    )
    _call(
        lines,
        gw,
        "write_file",
        {"path": "/data/output/x.txt", "content": "hi"},
        session_id="session-analyst",
        tag="analyst",
    )
    _call(
        lines,
        gw,
        "read_file",
        {"path": "/data/public/faq.md"},
        session_id="session-viewer",
        tag="viewer",
    )
    _call(
        lines,
        gw,
        "read_file",
        {"path": "/data/reports/q1.csv"},
        session_id="session-viewer",
        tag="viewer",
    )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    print(render_demo(), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
