"""Configuration diagnostics for dynamic mode, without claiming activation."""
from __future__ import annotations


def report_dynamic_config() -> bool | None:
    """Return None for legacy mode, otherwise report local configuration health.

    This does not enumerate sessions or verify grants on behalf of a runtime.
    """
    from hermes_tenuo._config import (
        _get_plugin_entry, get_session_warrants_dir, get_signing_key, get_trusted_roots,
    )
    if "local_home" in _get_plugin_entry(None):
        return report_shared_local_config()
    try:
        directory = get_session_warrants_dir(None)
    except ValueError:
        print("  ✗  invalid session_warrants_dir; protected calls block")
        return False
    if directory is None:
        return None
    print("  Mode: dynamic session warrants (enforcement enabled)")
    print(f"  Published membership directory: {directory}")
    print("  Published files are not an activation acknowledgement.")
    key_ok = get_signing_key(None) is not None
    roots_ok = bool(get_trusted_roots(None))
    print(f"  {'✓' if key_ok else '✗'}  holder signing key {'loadable' if key_ok else 'missing or invalid'}")
    print(f"  {'✓' if roots_ok else '✗'}  explicit trusted issuer {'loadable' if roots_ok else 'missing or invalid'}")
    if key_ok and roots_ok:
        print("  Configured to enforce; calls deny until an authorizing warrant is attached.")
        print("  The runtime verifies each grant before use; no static warrant is required.")
    else:
        print("  Protected calls block until identity and trust configuration are fixed.")
    return key_ok and roots_ok


def report_shared_local_config():
    from hermes_tenuo._guard import build_plugin_guard

    try:
        from tenuo.local import list_sessions, load_warrant_chain

        guard = build_plugin_guard(None)._guard
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
