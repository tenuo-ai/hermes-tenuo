"""Bounded authority-request control tool; it never issues or activates authority."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shlex

from hermes_tenuo.authority_requests import REQUEST_TOOL, new_request, save_request
from hermes_tenuo.policy import capabilities_from_allow


def register_request_tool(ctx) -> bool:
    from hermes_tenuo._config import _get_plugin_entry, get_session_warrants_dir, get_signing_key
    entry = _get_plugin_entry(ctx)
    directory = entry.get("requests_dir")
    if directory is None:
        return False
    if not isinstance(directory, str) or not directory.strip():
        raise ValueError("requests_dir must be a nonempty path")
    session_directory = get_session_warrants_dir(ctx)
    if session_directory is None:
        raise ValueError("requests_dir requires session_warrants_dir (no static authority fallback)")
    base = Path(directory).expanduser().resolve()
    session_directory = Path(session_directory).expanduser().resolve()

    def handler(args, *, session_id="", **_kwargs):
        try:
            if not isinstance(args, dict) or set(args) != {"allow", "ttl", "description"}:
                raise ValueError("request needs exactly allow, ttl and description")
            if not isinstance(args["allow"], list) or not 1 <= len(args["allow"]) <= 32:
                raise ValueError("allow must contain 1..32 CLI scope strings")
            if any(not isinstance(item, str) or len(item) > 2048 for item in args["allow"]):
                raise ValueError("each allow entry must be a string of at most 2048 characters")
            # session_id is dispatcher context, never a model-controlled tool argument.
            holder = get_signing_key(ctx)
            if holder is None:
                raise ValueError("holder identity is not configured")
            request = new_request(holder.public_key, session_id, capabilities_from_allow(args["allow"]),
                                  args["ttl"], args["description"])
            destination = base / hashlib.sha256(session_id.encode()).hexdigest()
            destination.mkdir(mode=0o700, parents=True, exist_ok=True)
            if destination.is_symlink() or destination.resolve().parent != base:
                raise ValueError("request destination must be a real session directory")
            # Requests do not grant authority; cap retained files to bound repeated model requests.
            for index, _ in enumerate(destination.glob("*.request.json")):
                if index >= 99:
                    raise ValueError("session request limit reached; operator must archive old requests")
            path = destination / f"{request['id']}.request.json"
            save_request(path, request)
            return json.dumps({"status": "pending_external_approval", "request": str(path),
                               "approve_command": "hermes-tenuo approve " + shlex.quote(str(path)) +
                               " --issuer-key /path/to/issuer.key --attach --directory " + shlex.quote(str(session_directory)),
                               "message": "No authority was granted. Ask the operator to review this file outside Hermes."})
        except (OSError, ValueError, TypeError) as exc:
            return json.dumps({"error": str(exc)})

    ctx.register_tool(name=REQUEST_TOOL, toolset="tenuo", schema={
        "name": REQUEST_TOOL,
        "description": "Propose scoped authority for this session. Writes an unsigned request; external approval is required.",
        "parameters": {"type": "object", "properties": {
            "allow": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 32},
            "ttl": {"type": "string", "description": "Requested duration, e.g. 20m"},
            "description": {"type": "string", "maxLength": 4000}},
            "required": ["allow", "ttl", "description"], "additionalProperties": False}}, handler=handler)
    return True
