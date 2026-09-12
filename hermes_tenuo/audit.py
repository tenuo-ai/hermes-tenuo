"""
Local audit log for hermes-tenuo. Works with no account.

Every authorization decision the guard makes is appended as one JSON line to
``$HERMES_HOME/tenuo/audit.jsonl`` (``~/.hermes/tenuo/audit.jsonl`` outside
Hermes). Read it back with ``hermes-tenuo audit`` or any JSONL tool.

Record shape (one per line):

    {"timestamp": "...", "decision": "ALLOW" | "DENY", "tool": "read_file",
     "args": {...}, "reason": "...", "session_id": "...", "task_id": "...",
     "tool_call_id": "...", "duration_ms": 0}

The guard emits once from ``pre_tool_call`` (the decision) and, for calls that
ran, once more from ``post_tool_call`` (same decision plus ``duration_ms``).
:func:`read_audit_log` collapses those by ``tool_call_id`` so each call shows
once, with timing when it is known.
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
    """``$HERMES_HOME/tenuo/audit.jsonl``, profile-aware when Hermes is importable."""
    try:
        from hermes_constants import get_hermes_home
        return Path(get_hermes_home()) / _DEFAULT_REL
    except Exception:
        return Path(os.path.expanduser("~/.hermes")) / _DEFAULT_REL


class LocalAuditLog:
    """Append-only JSONL sink usable as a ``HermesGuard`` ``audit_callback``."""

    def __init__(self, path: os.PathLike | str):
        self.path = Path(os.path.expanduser(str(path)))
        self._lock = threading.Lock()

    def __call__(self, event: Any) -> None:
        record = asdict(event) if is_dataclass(event) else dict(vars(event))
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

    Pre- and post-call records sharing a ``tool_call_id`` are merged (the later
    one wins, so ``duration_ms`` is filled in). Malformed lines are skipped.
    """
    p = Path(os.path.expanduser(str(path)))
    if not p.exists():
        return []
    merged: Dict[str, Dict[str, Any]] = {}
    order: List[str] = []
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
            key = rec.get("tool_call_id") or f"_line{n}"
            if key not in merged:
                order.append(key)
                merged[key] = rec
            else:
                merged[key] = {**merged[key], **rec}
    records = [merged[k] for k in order]
    if denied_only:
        records = [r for r in records if r.get("decision") == "DENY"]
    if last is not None and last >= 0:
        records = records[-last:] if last else []
    return records


def format_record(rec: Dict[str, Any]) -> str:
    """One-line human rendering: time, decision, tool, args, reason."""
    ts = str(rec.get("timestamp", ""))[:19].replace("T", " ")
    decision = rec.get("decision", "?")
    tool = rec.get("tool", "?")
    args = rec.get("args") or {}
    shown = ", ".join(f"{k}={_short(v)}" for k, v in args.items()) if isinstance(args, dict) else str(args)
    reason = rec.get("reason") or ""
    tail = f"  — {reason}" if decision == "DENY" and reason else ""
    return f"{ts}  {decision:5}  {tool}  {shown}{tail}"


def _short(value: Any, limit: int = 60) -> str:
    s = json.dumps(value, ensure_ascii=False, default=str) if not isinstance(value, str) else value
    return s if len(s) <= limit else s[: limit - 1] + "…"
