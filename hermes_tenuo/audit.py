"""
Local audit log for hermes-tenuo. Works with no account.

Every authorization decision the guard makes is appended as one JSON line to
``$HERMES_HOME/tenuo/audit.jsonl`` (``~/.hermes/tenuo/audit.jsonl`` outside
Hermes). Read it back with ``hermes-tenuo audit`` or any JSONL tool.

Record shape (one per line):

    {"timestamp": "...", "decision": "ALLOW" | "DENY", "tool": "read_file",
     "args": {...}, "reason": "...", "session_id": "...", "task_id": "...",
     "tool_call_id": "...", "duration_ms": 0}

A call to a tool with a use limit also carries ``"use": {"count": 1, "limit": 1,
"grant": "<warrant id>"}``: on ALLOW the use it took, on a DENY for the limit
the limit that is used up, and the grant that limit belongs to.

The guard emits once from ``pre_tool_call`` (the decision) and, for calls that
ran, once more from ``post_tool_call`` (same decision plus ``duration_ms``).
:func:`read_audit_log` collapses those per session and ``tool_call_id`` so each
call shows once, with timing when it is known.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("hermes_tenuo")

_DEFAULT_REL = Path("tenuo") / "audit.jsonl"


def default_audit_path() -> Path:
    """``$HERMES_HOME/tenuo/audit.jsonl`` (profile-aware inside Hermes; see ``_home.hermes_home``)."""
    from hermes_tenuo._home import hermes_home
    return hermes_home() / _DEFAULT_REL


class LocalAuditLog:
    """Append-only JSONL sink usable as a ``HermesGuard`` ``audit_callback``."""

    def __init__(self, path: os.PathLike | str):
        self.path = Path(os.path.expanduser(str(path)))
        self._lock = threading.Lock()

    def __call__(self, event: Any) -> None:
        record = asdict(event) if is_dataclass(event) else dict(vars(event))
        if record.get("use") is None:
            record.pop("use", None)  # only calls to a limited tool carry it
        if not record.get("completed"):
            record.pop("completed", None)  # only the record written after the call carries it
        line = json.dumps(record, ensure_ascii=False, default=str)
        try:
            with self._lock:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
        except OSError as exc:
            # Auditing must never block enforcement; log once per failure.
            logger.warning("hermes-tenuo: could not write audit log %s: %s", self.path, exc)


def read_audit_log(
    path: os.PathLike | str,
    *,
    last: Optional[int] = None,
    denied_only: bool = False,
) -> List[Dict[str, Any]]:
    """Return audit records, one per tool call, oldest first.

    The decision record and the completion record of one call are merged (the
    later one wins, so ``duration_ms`` is filled in). They are matched by
    session and ``tool_call_id``, and a call that has completed is closed: some
    models reuse an id such as ``call_0`` in every session or turn, and those
    are different calls. Malformed lines are skipped.
    """
    p = Path(os.path.expanduser(str(path)))
    if not p.exists():
        return []
    merged: Dict[Any, Dict[str, Any]] = {}
    order: List[Any] = []
    open_rows: Dict[Any, Any] = {}  # (session, tool_call_id) → row still waiting for its completion
    with p.open("r", encoding="utf-8") as fh:
        for n, raw in enumerate(fh):
            raw = raw.strip()
            if not raw:
                continue
            try:
                rec = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if not isinstance(rec, dict):
                continue
            call = (rec.get("session_id") or "", rec.get("tool_call_id")) if rec.get("tool_call_id") else None
            row = open_rows.get(call) if call is not None else None
            if row is None:
                row = n
                order.append(row)
                merged[row] = rec
                if call is not None:
                    open_rows[call] = row
            else:
                # Later records add timing; they never soften a denial. A DENY
                # from the pre hook stays DENY even if a post record says ALLOW.
                prev = merged[row]
                combined = {**prev, **rec}
                if prev.get("decision") == "DENY" and rec.get("decision") != "DENY":
                    combined["decision"] = "DENY"
                    combined["reason"] = prev.get("reason") or rec.get("reason")
                merged[row] = combined
            if call is not None and _completes(rec):
                open_rows.pop(call, None)
    records = [merged[k] for k in order]
    if denied_only:
        records = [r for r in records if r.get("decision") == "DENY"]
    if last is not None and last >= 0:
        records = records[-last:] if last else []
    return records


def _completes(rec: Dict[str, Any]) -> bool:
    """Whether *rec* is the record written after a call finished (or was reported blocked).

    The MCP wrapper writes ``outcome: forwarding`` before it hands a call on; that call is still open.
    """
    if rec.get("completed"):
        return True
    # Records from other writers and from before the marker existed.
    outcome = rec.get("outcome")
    return bool(
        (outcome and outcome != "forwarding")
        or rec.get("duration_ms")
        or rec.get("reason") in ("post-dispatch", "audit-only")
    )


def format_record(rec: Dict[str, Any]) -> str:
    """One-line human rendering: time, decision, tool, args, reason."""
    ts = str(rec.get("timestamp", ""))[:19].replace("T", " ")
    decision = rec.get("decision", "?")
    tool = rec.get("tool", "?")
    args = rec.get("args") or {}
    shown = ", ".join(f"{k}={_short(v)}" for k, v in args.items()) if isinstance(args, dict) else str(args)
    reason = rec.get("reason") or ""
    tail = f"  — {reason}" if decision == "DENY" and reason else ""
    use = rec.get("use")
    if decision == "ALLOW" and isinstance(use, dict) and use.get("limit"):
        tail = f"  (use {use.get('count')} of {use.get('limit')})"
    return f"{ts}  {decision:5}  {tool}  {shown}{tail}"


def _short(value: Any, limit: int = 60) -> str:
    s = json.dumps(value, ensure_ascii=False, default=str) if not isinstance(value, str) else value
    return s if len(s) <= limit else s[: limit - 1] + "…"
