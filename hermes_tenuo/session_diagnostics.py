"""Configuration diagnostics for dynamic mode, without claiming activation."""
from __future__ import annotations


def report_dynamic_config() -> bool | None:
    """Return None for legacy mode, otherwise report local configuration health.

    This does not enumerate sessions or verify grants on behalf of a runtime.
    """
    from hermes_tenuo._config import (
        get_session_warrants_dir, get_signing_key, get_trusted_roots,
    )
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
