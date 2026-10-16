"""Session-scoped dynamic authority, evaluated independently for every call."""
from __future__ import annotations

from pathlib import Path
from hermes_tenuo.hermes_guard import HermesGuard, HermesAuditEvent, _format_denial_reason
from hermes_tenuo.session_store import read_session, _decode


class SessionGuard(HermesGuard):
    """No static fallback, no implicit delegation, no authority union across grants."""

    def __init__(self, directory: Path, **kwargs):
        super().__init__(require_session_warrant=True, **kwargs)
        self.directory = Path(directory).expanduser().resolve()

    @property
    def has_warrant(self):
        # Configured enforcement, even before the first operator attachment.
        return True

    def pre_tool_call(self, tool_name, args, *, session_id="", task_id="", tool_call_id=""):
        from tenuo._enforcement import enforce_tool_call
        from tenuo.config import resolve_trusted_roots
        allowed = False
        selected = ""
        pending = ""
        approved_by = []
        reason = "tenuo: no attached warrant authorizes this call"
        try:
            if self._static_signing_key is None:
                raise ValueError("holder signing key is not configured")
            with self._trusted_roots_lock:
                if not self._trusted_roots:
                    raise ValueError("explicit trusted issuer is not configured")
                roots = resolve_trusted_roots(self._trusted_roots)
            if not roots:
                raise ValueError("trusted issuer is not configured")
            candidates = read_session(session_id, self.directory)
            for raw in candidates:
                try:
                    warrant = _decode(raw)
                    if warrant.session_id is not None and warrant.session_id != session_id:
                        continue
                    approval_handler = (self._operation_approval_store.handler(warrant, session_id, roots)
                                        if self._operation_approval_store else self._approval_handler)
                    result = enforce_tool_call(
                        tool_name=tool_name, tool_args=args,
                        bound_warrant=warrant.bind(self._static_signing_key),
                        trusted_roots=roots,
                        approval_handler=approval_handler,
                    )
                    if result.allowed:
                        allowed, selected, reason = True, str(warrant.id), ""
                        approved_by = getattr(approval_handler, "approved_by", [])
                        break
                    reason = _format_denial_reason(result, tool_name)
                except Exception as exc:
                    from hermes_tenuo.operation_approvals import OperationApprovalPending
                    if isinstance(exc, OperationApprovalPending):
                        pending = str(exc)
                    # A bad or expired grant must not hide an independent valid grant.
                    continue
        except Exception as exc:
            reason = f"tenuo: session authority unavailable: {exc}"
        if not allowed and pending:
            reason = pending
        self._remember_decision(tool_call_id, allowed, reason)
        if self._audit_callback:
            event = HermesAuditEvent(tool=tool_name, args=args,
                decision="ALLOW" if allowed else "DENY", reason=reason,
                session_id=session_id, task_id=task_id, tool_call_id=tool_call_id,
                warrant_id=selected, approvers=approved_by)
            try:
                self._audit_callback(event)
            except Exception:
                pass
        if not allowed:
            return {"action": "block", "message": reason,
                    **({"code": "operation_approval_required"} if pending else {})}
        return None

    def post_tool_call(self, *args, tool_call_id="", **kwargs):
        # Decision was already recorded once, including the selected warrant.
        with self._pre_decisions_lock:
            self._pre_decisions.pop(tool_call_id, None)

    def on_session_end(self, session_id):
        # Hermes fires this at turn end; persistent attachments survive turns.
        pass

    def on_session_start(self, **kwargs):
        pass

    def on_subagent_start(self, **kwargs):
        # Children need their own explicit session attachments.
        pass
