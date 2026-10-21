"""Hermes session routing over the shared Python SDK's local artifacts."""
from __future__ import annotations

import logging
import shlex
from dataclasses import replace

from hermes_tenuo.hermes_guard import HermesAuditEvent, HermesGuard, _format_denial_reason


# What the operator can do about a refusal of an attached warrant.
_NEXT_STEP = {
    "expired": "Ask the operator to issue a replacement.",
    "revoked": "Ask the operator for new authority.",
    "untrusted_issuer": "Run tenuo-cli doctor.",
}


def _with_next_step(reason, error_type):
    step = _NEXT_STEP.get(error_type)
    return f"{reason.rstrip('.')}. {step}" if step else reason


class SharedLocalGuard(HermesGuard):
    """Check one attached full warrant per call; never combine partial grants.

    With the workspace in observe mode (``tenuo-cli mode observe``) nothing is
    blocked: each call is recorded to the workspace's observations.jsonl, with
    its arguments and the decision enforcement would have made, for drafting a
    warrant. The Hermes session is the recorded run.
    """

    def __init__(self, home, *, key="agent", step="hermes", audit_callback=None):
        from tenuo.local import LocalAuthority

        if not isinstance(key, str) or not key.strip():
            raise ValueError("local_key must name the agent key or a private key file")
        if not isinstance(step, str) or not step.strip():
            raise ValueError("local_step must be a nonempty name")
        super().__init__(require_session_warrant=True, audit_callback=audit_callback)
        self.authority = LocalAuthority(path=home, key=key)
        self.step = step

    @property
    def has_warrant(self):
        return True  # Configured enforcement includes sessions with no attachments.

    def _observing(self):
        try:
            return self.authority.observing
        except Exception:
            return False  # An unreadable config enforces, and the snapshot then refuses.

    def _evaluate(self, tool_name, args, session_id, *, observing):
        """Return (allowed, warrant_id, reason, pending, kind, argument) over the session's attachments.

        ``argument`` names the argument a constraint denial failed on, never its value.
        """
        from tenuo._enforcement import enforce_tool_call
        from tenuo.approval import ApprovalRequired
        from tenuo.local import load_warrant_chain, read_session

        allowed, selected, pending, kind, argument = False, "", "", "no_warrant", None
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
                    selected = wid
                    # Expiry, revocation and trust are judged by the runtime's authorizer,
                    # which signs a receipt for the refusal; checking here first would skip it.
                    with self.authority.scope(replace(snapshot, chain=chain)) as (current, session, approvals):
                        result = enforce_tool_call(tool_name=tool_name, tool_args=args,
                                                   bound_warrant=session.bound, trusted_roots=current.roots,
                                                   warrant_chain=chain[:-1],
                                                   approval_handler=None if observing else approvals)
                    if result.allowed:
                        return True, wid, "", "", None, None
                    kind = result.error_type or "denied"
                    argument = result.constraint_violated if kind == "constraint_violation" else None
                    reason = _with_next_step(_format_denial_reason(result, tool_name), result.error_type)
                except ApprovalRequired as exc:
                    pending, kind = str(exc), "approval_required"
                except Exception as exc:
                    from tenuo.exceptions import ExpiredError, RevokedError, UntrustedRoot

                    kinds = ((RevokedError, "revoked"), (ExpiredError, "expired"), (UntrustedRoot, "untrusted_issuer"))
                    kind = next((k for cls, k in kinds if isinstance(exc, cls)), None)
                    if kind is not None:
                        reason = _with_next_step(str(exc), kind)
                    else:
                        kind = "unavailable:" + type(exc).__name__
                        reason = f"tenuo: attached warrant unavailable ({type(exc).__name__}); run tenuo-cli doctor"
        except FileNotFoundError:
            if snapshot is None:
                kind, reason = "missing_file", "Local verification files are missing; run tenuo-cli doctor"
        except Exception as exc:
            kind = "unavailable:" + type(exc).__name__
            reason = f"tenuo: session authority unavailable ({type(exc).__name__}); run tenuo-cli doctor"
        if pending:
            reason = pending
        return allowed, selected, reason, pending, kind, argument

    def pre_tool_call(self, tool_name, args, *, session_id="", task_id="", tool_call_id=""):
        observing = self._observing()
        allowed, selected, reason, pending, kind, argument = self._evaluate(
            tool_name, args, session_id, observing=observing)
        if observing:
            decision = "allow" if allowed else (None if kind == "no_warrant" else "deny")
            try:
                self.authority.record(tool_name, args, decision=decision, reason=None if allowed else kind,
                                      warrant_id=selected or None, argument=argument,
                                      run=session_id or None, step=self.step)
            except Exception:
                logging.getLogger(__name__).warning("Tenuo observe: could not record %s", tool_name, exc_info=True)
            if not allowed:
                reason = f"observe: would deny: {reason}"
            allowed, pending = True, ""
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


def report_shared_local_config():
    """Print the shared workspace's mode and usable attachments; True when calls can proceed."""
    from hermes_tenuo._guard import build_plugin_guard

    try:
        from tenuo.local import list_sessions, load_warrant_chain

        guard = build_plugin_guard(None)._guard
        if guard._observing():
            print("  Mode: shared local CLI files, observe (nothing is blocked; calls are recorded)")
            print(f"  Recording to {guard.authority.observations_path}")
            return True
        snapshot = guard.authority.snapshot()
        workspace = guard.authority.workspace
        valid = 0
        for manifest in list_sessions(workspace):
            for wid in manifest["warrants"]:
                try:
                    chain = load_warrant_chain(workspace.path / "warrants" / (wid + ".warrant"))
                    snapshot.authorizer.verify_chain(chain)
                    if str(chain[-1].id) != wid:
                        raise ValueError
                    if bytes(chain[-1].holder_key.to_bytes()) != bytes(snapshot.key.public_key.to_bytes()):
                        raise ValueError
                    if chain[-1].session_id is not None and chain[-1].session_id != manifest["session_id"]:
                        raise ValueError
                    valid += 1
                except Exception:
                    print(f"  ✗  unusable attachment {wid} in session {manifest['session_id']}")
        print("  Mode: shared local CLI files (enforcement enabled)")
        print(f"  Verified {valid} current session attachment(s)")
        if not valid:
            print("  Calls deny until an operator uses tenuo-cli session attach for the reported session ID")
        return valid > 0
    except Exception:
        print("  ✗  shared local setup invalid; use the matching SDK and tenuo-cli doctor")
        return False
