"""Hermes session routing over the shared Python SDK's local artifacts."""
from __future__ import annotations

import logging
import shlex
from dataclasses import replace

from hermes_tenuo.hermes_guard import HermesAuditEvent, HermesGuard, _format_denial_reason


class SharedLocalGuard(HermesGuard):
    """Check one attached full warrant per call; never combine partial grants."""

    def __init__(self, home, *, key="agent", audit_callback=None):
        from tenuo.local import LocalAuthority

        if not isinstance(key, str) or not key.strip():
            raise ValueError("local_key must name the agent key or a private key file")
        super().__init__(require_session_warrant=True, audit_callback=audit_callback)
        self.authority = LocalAuthority(path=home, key=key)

    @property
    def has_warrant(self):
        return True  # Configured enforcement includes sessions with no attachments.

    def pre_tool_call(self, tool_name, args, *, session_id="", task_id="", tool_call_id=""):
        from tenuo._enforcement import enforce_tool_call
        from tenuo.approval import ApprovalRequired
        from tenuo.local import load_warrant_chain, read_session

        allowed, selected = False, ""
        pending = ""
        snapshot = None
        reason = (f"Session {session_id!r} has no attached authority. Ask an operator to run "
                  f"tenuo-cli session attach --session {shlex.quote(session_id)} --file WARRANT")
        try:
            snapshot = self.authority.snapshot()
            manifest = read_session(self.authority.workspace, session_id)
            for wid in manifest["warrants"]:
                try:
                    chain = load_warrant_chain(self.authority.workspace.path / "warrants" / (wid + ".warrant"))
                    if str(chain[-1].id) != wid:
                        raise ValueError("warrant ID does not match its stored filename")
                    if chain[-1].session_id is not None and chain[-1].session_id != session_id:
                        raise ValueError("warrant is bound to a different session")
                    # Expiry, revocation and trust are judged by the runtime's authorizer,
                    # which signs a receipt for the refusal; checking here first would skip it.
                    with self.authority.scope(replace(snapshot, chain=chain)) as (current, session, approvals):
                        result = enforce_tool_call(tool_name=tool_name, tool_args=args,
                                                   bound_warrant=session.bound, trusted_roots=current.roots,
                                                   warrant_chain=chain[:-1], approval_handler=approvals)
                    if result.allowed:
                        allowed, selected, reason = True, wid, ""
                        break
                    reason = _format_denial_reason(result, tool_name)
                except ApprovalRequired as exc:
                    pending = str(exc)
                except Exception as exc:
                    from tenuo.exceptions import ExpiredError, RevokedError

                    if isinstance(exc, RevokedError):
                        reason = f"Warrant {wid} is revoked; ask the operator for new authority"
                    elif isinstance(exc, ExpiredError):
                        reason = f"Warrant {wid} has expired; ask the operator to issue a replacement"
                    else:
                        reason = f"tenuo: attached warrant unavailable ({type(exc).__name__}); run tenuo-cli doctor"
        except FileNotFoundError:
            if snapshot is None:
                reason = "Local verification files are missing; run tenuo-cli doctor"
        except Exception as exc:
            reason = f"tenuo: session authority unavailable ({type(exc).__name__}); run tenuo-cli doctor"
        if not allowed and pending:
            reason = pending
        self._remember_decision(tool_call_id, allowed, reason)
        if self._audit_callback:
            try:
                self._audit_callback(HermesAuditEvent(tool=tool_name, args=args,
                    decision="ALLOW" if allowed else "DENY", reason=reason, session_id=session_id,
                    task_id=task_id, tool_call_id=tool_call_id, warrant_id=selected))
            except Exception:
                logging.getLogger(__name__).warning("Local Hermes audit callback failed", exc_info=True)
        if not allowed:
            return {"action": "block", "message": reason,
                    **({"code": "operation_approval_required"} if pending else {})}
        return None

    def post_tool_call(self, *args, tool_call_id="", **kwargs):
        with self._pre_decisions_lock:
            self._pre_decisions.pop(tool_call_id, None)

    def on_session_end(self, session_id):
        pass  # Hermes fires this hook at turn end; attachments survive turns.

    def on_session_start(self, **kwargs):
        pass

    def on_subagent_start(self, **kwargs):
        pass  # A new child session must receive explicit authority.

    def set_session_warrant(self, *args, **kwargs):
        raise ValueError("local_home uses tenuo-cli session attach, not in-memory attachments")

    def clear_session_warrant(self, *args, **kwargs):
        raise ValueError("local_home uses tenuo-cli session detach")

    def set_trusted_roots(self, *args, **kwargs):
        raise ValueError("local_home reads operator-controlled trust files")
