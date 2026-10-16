"""Unsigned, immutable requests reviewed and signed outside the agent process."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import shlex
import sys
import uuid

from hermes_tenuo.issuance import mint_for_holder, read_public_key, read_signing_key, write_private_file
from hermes_tenuo.policy import capabilities_from_allow, compile_capabilities, load_policy, validate_capabilities

MAX_REQUEST_BYTES = 64 * 1024
REQUEST_TOOL = "tenuo_request_authority"


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate request field: {key}")
        result[key] = value
    return result


def validate_request(data: dict) -> dict:
    fields = {"version", "id", "session_id", "holder_public_key", "description", "ttl", "capabilities"}
    if not isinstance(data, dict) or set(data) != fields:
        raise ValueError("request must contain exactly: " + ", ".join(sorted(fields)))
    if type(data["version"]) is not int or data["version"] != 1:
        raise ValueError("unsupported request version")
    if not isinstance(data["id"], str) or str(uuid.UUID(data["id"])) != data["id"]:
        raise ValueError("request id must be a canonical UUID")
    for field, limit in (("session_id", 512), ("description", 4000)):
        value = data[field]
        if not isinstance(value, str) or not value.strip() or len(value) > limit:
            raise ValueError(f"{field} must be a nonempty string of at most {limit} characters")
        if any(ord(c) < 32 for c in value) and field == "session_id":
            raise ValueError("session_id must not contain control characters")
    if not isinstance(data["holder_public_key"], str):
        raise ValueError("holder_public_key must be base64 text")
    from tenuo import PublicKey
    public = PublicKey.from_bytes(base64.b64decode(data["holder_public_key"], validate=True))
    from hermes_tenuo.cli import _parse_ttl
    if not isinstance(data["ttl"], str):
        raise ValueError("ttl must be a duration string")
    try:
        _parse_ttl(data["ttl"])
    except (ValueError, OverflowError) as exc:
        raise ValueError("ttl must be a finite positive duration") from exc
    return {**data, "holder_public_key": base64.b64encode(public.to_bytes()).decode(),
            "capabilities": validate_capabilities(data["capabilities"])}


def new_request(holder, session_id: str, capabilities: dict, ttl: str, description: str) -> dict:
    return validate_request({"version": 1, "id": str(uuid.uuid4()), "session_id": session_id,
                             "holder_public_key": base64.b64encode(holder.to_bytes()).decode(),
                             "description": description, "ttl": ttl, "capabilities": capabilities})


def load_request(path: str | Path) -> dict:
    with Path(path).expanduser().open("rb") as stream:
        raw = stream.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        raise ValueError("request exceeds 64 KiB")
    return validate_request(json.loads(raw, object_pairs_hook=_unique_object))


def save_request(path: str | Path, request: dict) -> None:
    encoded = json.dumps(validate_request(request), indent=2, sort_keys=True)
    if len(encoded.encode()) > MAX_REQUEST_BYTES:
        raise ValueError("request exceeds 64 KiB")
    write_private_file(path, encoded)


def review_text(request: dict) -> str:
    # JSON escaping keeps untrusted descriptions/session labels from issuing terminal escapes.
    public = base64.b64decode(request["holder_public_key"])
    fingerprint = hashlib.sha256(public).hexdigest()[:16]
    return ("Unsigned authority request; confirm the holder fingerprint independently.\n"
            f"Holder fingerprint (SHA256 prefix): {fingerprint}\n" + json.dumps(request, indent=2, sort_keys=True))


def approve_request(request: dict, issuer, output: str | Path):
    """Only the already-reviewed in-memory snapshot is signed; never reread its path."""
    request = validate_request(request)
    from tenuo import PublicKey
    from hermes_tenuo.cli import _parse_ttl
    holder = PublicKey.from_bytes(base64.b64decode(request["holder_public_key"]))
    warrant = mint_for_holder(issuer, holder, compile_capabilities(request["capabilities"]),
                              _parse_ttl(request["ttl"]), session_id=request["session_id"])
    write_private_file(output, warrant.to_base64())
    return warrant


def cmd_request_create(args: argparse.Namespace) -> int:
    try:
        policy = load_policy(args.policy) if args.policy else None
        capabilities = policy["capabilities"] if policy else capabilities_from_allow(args.allow or [])
        request = new_request(read_public_key(args.holder_public_key), args.session,
                              capabilities, args.ttl or (policy or {}).get("ttl", "20m"), args.description)
        save_request(args.out, request)
        print(f"Request written: {args.out}\nReview: hermes-tenuo request show {shlex.quote(str(args.out))}")
        return 0
    except (OSError, ValueError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def cmd_request_show(args: argparse.Namespace) -> int:
    try:
        print(review_text(load_request(args.path)))
        return 0
    except (OSError, ValueError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def cmd_approve(args: argparse.Namespace) -> int:
    try:
        snapshot = load_request(args.request)
        print(review_text(snapshot))
        output = args.out or str(Path(args.request).with_suffix(".warrant"))
        print(f"Output: {output}")
        if args.attach:
            print("Also attach to the request's session in the configured local store.")
        if not args.yes:
            if input("Sign exactly this request? [y/N] ").strip().lower() not in ("y", "yes"):
                print("Not approved.")
                return 1
        issuer = read_signing_key(args.issuer_key)
        warrant = approve_request(snapshot, issuer, output)
        print(f"Issued warrant: {warrant.id}; file: {output}")
        if args.attach:
            from hermes_tenuo.session_store import attach_encoded_warrant
            from hermes_tenuo._config import get_session_warrants_dir
            directory = args.directory or get_session_warrants_dir(None)
            if directory is None:
                raise ValueError("--attach needs --directory or configured session_warrants_dir; warrant was issued only")
            attach_encoded_warrant(warrant.to_base64(), snapshot["session_id"], directory)
            print("Published to session; runtime verifies on its next tool call. No gateway restart needed.")
        return 0
    except (OSError, ValueError, TypeError, EOFError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def register_commands(subparsers) -> None:
    parser = subparsers.add_parser("request", help="Create or review an unsigned authority request")
    commands = parser.add_subparsers(dest="request_command", required=True)
    create = commands.add_parser("create", help="Snapshot proposed authority without signing")
    create.add_argument("--holder-public-key", required=True)
    create.add_argument("--session", required=True)
    create.add_argument("--description", required=True)
    create.add_argument("--ttl")
    scope = create.add_mutually_exclusive_group(required=True)
    scope.add_argument("--allow", action="append")
    scope.add_argument("--policy")
    create.add_argument("--out", required=True)
    create.set_defaults(authority_request_handler=cmd_request_create)
    show = commands.add_parser("show", help="Show the exact scope and holder for review")
    show.add_argument("path")
    show.set_defaults(authority_request_handler=cmd_request_show)
    approve = subparsers.add_parser("approve", help="Review and sign one request outside Hermes")
    approve.add_argument("request")
    approve.add_argument("--issuer-key", required=True)
    approve.add_argument("--out")
    approve.add_argument("--yes", action="store_true", help="Explicitly approve without interactive confirmation")
    approve.add_argument("--attach", action="store_true", help="Publish to the session in the request")
    approve.add_argument("--directory", help="Operator-selected session warrant store")
    approve.set_defaults(authority_request_handler=cmd_approve)
