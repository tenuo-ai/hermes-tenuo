"""``hermes-tenuo a2a``: pair agents, revoke delegations and check the A2A setup.

  hermes-tenuo a2a key                    this agent's A2A key (created on first use), for a peer's config
  hermes-tenuo a2a check                  verify a2a_ingress / a2a_delegation in this HERMES_HOME
  hermes-tenuo a2a revoke ID... --root-key FILE --list FILE
                                          add warrant or grant ids to a signed revocation list
"""

from __future__ import annotations

import base64
import os
import sys
from pathlib import Path
from typing import Any, List


def cmd_key(_args: Any) -> int:
    from hermes_tenuo.a2a_ingress import a2a_key_path, load_or_create_a2a_key, public_key_b64

    key = load_or_create_a2a_key()
    pub = public_key_b64(key)
    print(f"This agent's A2A key: {pub}")
    print(f"(private key: {a2a_key_path()}, never shared)\n")
    print("On an agent that delegates to this one, under plugins.entries.hermes-tenuo:")
    print("  a2a_delegation:\n    peers:\n      <name for this agent>:\n"
          f"        url: <this agent's A2A URL>\n        public_key: \"{pub}\"\n"
          "        token_env: <secret holding the bearer token for this agent's A2A endpoint>")
    return 0


def cmd_check(_args: Any) -> int:
    """Offline readiness check. Exit 1 when something configured cannot be used."""
    from dotenv import dotenv_values

    from hermes_tenuo.a2a_delegate import load_sender_config
    from hermes_tenuo.a2a_ingress import IngressRefused, load_ingress, public_key_b64
    from hermes_tenuo._home import hermes_home

    problems: List[str] = []
    ingress = None
    profile_env = {}
    try:
        profile_env = {key: value for key, value in dotenv_values(
            hermes_home() / ".env", encoding="utf-8-sig",
        ).items() if value is not None}
        ingress = load_ingress(None, read_env=lambda name: profile_env.get(name, os.environ.get(name)))
    except Exception as exc:
        problems.append(f"a2a_ingress: {exc} (every inbound A2A message would be dropped)")
    if ingress is not None:
        print(f"Receiving: on. Key {public_key_b64(ingress.own_key)}")
        print(f"  pinned peers: {', '.join(sorted(ingress.peers))}")
        print(f"  trusted roots: {len(ingress.trusted_roots)}")
        try:
            srl = ingress.revocations()
            print(f"  revocation list: {'none' if srl is None else f'version {srl.version}, {len(srl.revoked_ids)} revoked'}")
        except IngressRefused as refused:
            problems.append(f"a2a_ingress: {refused} (every delegation is refused until it is fixed)")
        print("  Hermes side: enable platforms.a2a, use one named sender, and keep this\n"
              "  plugin the only pre_gateway_dispatch plugin on this agent.")
    elif not problems:
        print("Receiving: off (no a2a_ingress block).")
    sender = None
    try:
        sender = load_sender_config(None)
    except Exception as exc:
        problems.append(f"a2a_delegation: {exc}")
    if sender is not None:
        print(f"Delegating: on. Peers: {', '.join(sorted(sender.peers))}")
        for peer in sender.peers.values():
            token = "set" if profile_env.get(peer.token_env, os.environ.get(peer.token_env)) else f"{peer.token_env} not in this environment"
            print(f"  {peer.name}: {peer.url} (token {token})")
        print("  The session must hold a warrant that allows tenuo_delegate and covers what it delegates.")
    elif not any(p.startswith("a2a_delegation") for p in problems):
        print("Delegating: off (no a2a_delegation block).")
    for problem in problems:
        print(f"PROBLEM  {problem}", file=sys.stderr)
    return 1 if problems else 0


def cmd_revoke(args: Any) -> int:
    """Add ids to a revocation list signed by the operator root. Receivers pick up the new file."""
    from tenuo import SignedRevocationList, SigningKey

    root = SigningKey.from_bytes(base64.b64decode(Path(args.root_key).read_text().strip()))
    target = Path(args.list)
    ids = set(args.ids)
    version = 1
    if target.exists():
        from hermes_tenuo.a2a_ingress import srl_bytes

        current = SignedRevocationList.from_bytes(srl_bytes(target.read_bytes()))
        ids |= set(current.revoked_ids)
        version = current.version + 1
    builder = SignedRevocationList.builder()
    for warrant_id in sorted(ids):
        builder = builder.revoke(warrant_id)
    srl = builder.version(version).build(root)
    target.parent.mkdir(parents=True, exist_ok=True)
    _write_bytes(target, srl.to_bytes())
    print(f"Revocation list version {version}: {len(ids)} revoked. Copy {target} to each receiving agent's "
          "a2a_ingress.revocation_list path; it is re-read on change.")
    return 0


def _write_bytes(path: Path, data: bytes) -> None:
    """Raw bytes (the format the MCP wrapper reads as revocations.srl), atomically and 0600."""
    import tempfile

    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(temporary, path)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise


def add_parser(subparsers: Any) -> None:
    a2a = subparsers.add_parser("a2a", help="Delegate tasks between Hermes agents with Tenuo grants")
    sub = a2a.add_subparsers(dest="a2a_command")
    sub.add_parser("key", help="Show this agent's A2A key for pairing")
    sub.add_parser("check", help="Check the A2A delegation setup in this HERMES_HOME")
    revoke = sub.add_parser("revoke", help="Revoke delegations by warrant or grant id")
    revoke.add_argument("ids", nargs="+", metavar="ID")
    revoke.add_argument("--root-key", required=True, help="file with the operator root's private key (base64)")
    revoke.add_argument("--list", required=True, help="revocation list file to create or extend")


def run(args: Any) -> int:
    command = getattr(args, "a2a_command", None)
    if command == "key":
        return cmd_key(args)
    if command == "check":
        return cmd_check(args)
    if command == "revoke":
        return cmd_revoke(args)
    print(__doc__)
    return 0
