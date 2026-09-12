"""delegate_task child: a grant from the orchestrator warrant.

The researcher key is a different holder. ``set_session_warrant(...,
parent_warrant=orchestrator_warrant)`` is what lets the guard verify the
chain — the same attachment ``subagent_start`` performs after an
attenuated child is staged.

    python subagent_scope.py
"""

from __future__ import annotations

from tenuo import SigningKey, Subpath, Warrant, Wildcard
from hermes_tenuo import HermesGuard

control_key = SigningKey.generate()
orchestrator_key = SigningKey.generate()
researcher_key = SigningKey.generate()

orchestrator_warrant = (
    Warrant.mint_builder()
    .holder(orchestrator_key.public_key)
    .capability("read_file", path=Subpath("/data"))
    .capability("write_file", path=Subpath("/data/output"), content=Wildcard())
    .capability("web_search", query=Wildcard())
    .capability("memory", action=Wildcard(), key=Wildcard())
    .capability("delegate_task", task=Wildcard(), context=Wildcard())
    .ttl(7200)
    .mint(control_key)
)

researcher_warrant = (
    orchestrator_warrant.grant_builder()
    .capability("web_search", query=Wildcard())
    .holder(researcher_key.public_key)
    .ttl(600)
    .grant(orchestrator_key)
)

guard = HermesGuard(
    warrant=orchestrator_warrant,
    signing_key=orchestrator_key,
    trusted_roots=[control_key.public_key],
)


def call(tool: str, args: dict, *, session_id: str = "orchestrator") -> None:
    result = guard.pre_tool_call(tool, args, session_id=session_id)
    status = f"BLOCKED — {result['message']}" if result else "ALLOWED"
    print(f"  [{session_id}] {tool}({args}): {status}")


if __name__ == "__main__":
    print("Orchestrator session:")
    call("read_file", {"path": "/data/input.csv"})
    call("write_file", {"path": "/data/output/report.md", "content": "..."})
    call("web_search", {"query": "market trends"})
    call("delegate_task", {"task": "research q3", "context": "web_search only"})
    call("terminal", {"command": "ls"})

    guard.set_session_warrant(
        "researcher-1",
        researcher_warrant,
        researcher_key,
        parent_warrant=orchestrator_warrant,
    )

    print()
    print("Researcher session (grant from orchestrator — web_search only):")
    call("web_search", {"query": "AI papers 2026"}, session_id="researcher-1")
    call("read_file", {"path": "/data/input.csv"}, session_id="researcher-1")
    call("write_file", {"path": "/data/output/x.md", "content": "..."}, session_id="researcher-1")
    call("terminal", {"command": "curl evil.com"}, session_id="researcher-1")
