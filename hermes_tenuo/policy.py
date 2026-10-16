"""Strict, versioned local scope documents; loading a policy grants no authority."""
from __future__ import annotations

import copy
import base64
import json
import math
from pathlib import Path
from typing import Any

import yaml

MAX_SAFE_INTEGER = (1 << 53) - 1
MAX_POLICY_BYTES = 1024 * 1024


class PolicyError(ValueError):
    """A policy cannot be safely interpreted."""


class _StrictLoader(yaml.SafeLoader):
    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise PolicyError("YAML aliases are not supported")
        event = self.peek_event()
        if event.anchor is not None:
            raise PolicyError("YAML anchors are not supported")
        return super().compose_node(parent, index)

    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise PolicyError("mapping keys must be strings")
            if key in result:
                raise PolicyError(f"duplicate field: {key}")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def _mapping(value, where):
    if not isinstance(value, dict) or any(not isinstance(k, str) or not k.strip() for k in value):
        raise PolicyError(f"{where} must be a mapping with nonempty string keys")


def _number(value):
    return type(value) in (int, float) and abs(value) <= MAX_SAFE_INTEGER and math.isfinite(value)


def validate_capabilities(capabilities: Any) -> dict:
    """Validate and copy the canonical tool -> argument -> typed constraint mapping."""
    _mapping(capabilities, "capabilities")
    if not capabilities:
        raise PolicyError("capabilities must include at least one tool")
    for tool, arguments in capabilities.items():
        _mapping(arguments, f"capabilities.{tool}")
        for argument, constraint in arguments.items():
            where = f"capabilities.{tool}.{argument}"
            _mapping(constraint, where)
            if len(constraint) != 1:
                raise PolicyError(f"{where} requires exactly one constraint type")
            kind, value = next(iter(constraint.items()))
            valid = False
            if kind == "exact":
                valid = isinstance(value, str)
            elif kind == "one_of":
                valid = isinstance(value, list) and bool(value) and all(isinstance(v, str) for v in value)
            elif kind == "range":
                valid = (isinstance(value, dict) and set(value) == {"min", "max"}
                         and _number(value["min"]) and _number(value["max"])
                         and value["min"] <= value["max"])
            elif kind in ("pattern", "subpath"):
                valid = isinstance(value, str) and bool(value) and "\x00" not in value
                if kind == "subpath":
                    valid = valid and value.startswith("/")
            elif kind == "wildcard":
                valid = value is True
            if not valid:
                raise PolicyError(f"{where}: invalid {kind!r} constraint")
    return copy.deepcopy(capabilities)


def _approval_shape(data, capabilities, key_field):
    _mapping(data, "approvals")
    if set(data) != {key_field, "gates"}:
        raise PolicyError(f"approvals requires exactly {key_field} and gates; one authorized signature is sufficient")
    keys = data[key_field]
    if (not isinstance(keys, list) or not 1 <= len(keys) <= 128
            or any(not isinstance(key, str) or not key.strip() or "\x00" in key for key in keys)):
        raise PolicyError(f"approvals.{key_field} must contain 1-128 nonempty strings")
    if len(set(keys)) != len(keys):
        raise PolicyError("approval keys must be distinct")
    _mapping(data["gates"], "approvals.gates")
    if not data["gates"]:
        raise PolicyError("approvals.gates must not be empty")
    for tool, gate in data["gates"].items():
        if tool not in capabilities:
            raise PolicyError(f"approval gate names an ungranted tool: {tool}")
        if not isinstance(gate, dict) or set(gate) != {"always"} or gate["always"] is not True:
            raise PolicyError(f"approvals.gates.{tool} requires always: true")
    return copy.deepcopy(data)


def validate_approval_snapshot(data, capabilities):
    """Portable requests carry public key bytes, never paths to read at approval time."""
    from tenuo import PublicKey
    result = _approval_shape(data, capabilities, "public_keys")
    try:
        keys = [PublicKey.from_bytes(base64.b64decode(key, validate=True)) for key in result["public_keys"]]
    except Exception as exc:
        raise PolicyError("invalid approval public key") from exc
    encoded = [base64.b64encode(key.to_bytes()).decode() for key in keys]
    if len(set(encoded)) != len(encoded):
        raise PolicyError("approval keys must be distinct")
    result["public_keys"] = encoded
    return result


def resolve_policy_approvals(policy, policy_path):
    """Freeze file contents once, relative to the policy file, before review/signing."""
    if "approvals" not in policy:
        return None
    from hermes_tenuo.issuance import read_public_key
    base = Path(policy_path).expanduser().resolve().parent
    keys = []
    for raw in policy["approvals"]["keys"]:
        path = Path(raw)
        try:
            public = read_public_key(path if path.is_absolute() else base / path)
        except Exception as exc:
            raise PolicyError(f"cannot load approval public key: {raw}") from exc
        keys.append(base64.b64encode(public.to_bytes()).decode())
    return validate_approval_snapshot({"public_keys": keys, "gates": policy["approvals"]["gates"]},
                                      policy["capabilities"])


def approval_mint_kwargs(snapshot):
    if snapshot is None:
        return {}
    from tenuo import PublicKey
    return {"approval_gates": list(snapshot["gates"]),
            "approvers": [PublicKey.from_bytes(base64.b64decode(key, validate=True))
                          for key in snapshot["public_keys"]]}


def validate_policy(data: Any) -> dict:
    """Return a JSON-compatible policy snapshot; reject unsupported fields/types."""
    _mapping(data, "policy")
    version = data.get("version")
    if type(version) is not int or version not in (1, 2):
        raise PolicyError("policy version must be 1 or 2")
    allowed = {"version", "name", "ttl", "capabilities"}
    if version == 2:
        allowed.add("approvals")
    unknown = set(data) - allowed
    if unknown:
        raise PolicyError(f"unknown policy fields: {', '.join(sorted(unknown))}")
    result = {"version": version}
    if "name" in data:
        if not isinstance(data["name"], str) or not data["name"].strip():
            raise PolicyError("name must be a nonempty string")
        result["name"] = data["name"]
    if "ttl" in data:
        if not isinstance(data["ttl"], str):
            raise PolicyError("ttl must be a duration string, e.g. 20m")
        from hermes_tenuo.cli import _parse_ttl
        try:
            _parse_ttl(data["ttl"])
        except (ValueError, OverflowError) as exc:
            raise PolicyError(f"invalid ttl: {data['ttl']!r}") from exc
        result["ttl"] = data["ttl"]
    result["capabilities"] = validate_capabilities(data.get("capabilities"))
    if "approvals" in data:
        result["approvals"] = _approval_shape(data["approvals"], result["capabilities"], "keys")
    return result


def load_policy(path: str | Path) -> dict:
    """Load YAML/JSON without duplicate keys, aliases, tags, or interpolation."""
    try:
        with Path(path).open("rb") as stream:
            raw = stream.read(MAX_POLICY_BYTES + 1)
        if len(raw) > MAX_POLICY_BYTES:
            raise PolicyError("policy exceeds 1 MiB")
        return validate_policy(yaml.load(raw.decode("utf-8"), Loader=_StrictLoader))
    except (OSError, UnicodeError, yaml.YAMLError, RecursionError) as exc:
        raise PolicyError(f"cannot load policy: {exc}") from exc


def compile_capabilities(capabilities: dict) -> dict:
    """Compile validated canonical constraints into existing Tenuo SDK objects."""
    from tenuo import Exact, OneOf, Pattern, Range, Subpath, Wildcard
    factories = {"exact": Exact, "one_of": OneOf, "pattern": Pattern, "subpath": Subpath}
    result = {}
    for tool, arguments in validate_capabilities(capabilities).items():
        result[tool] = {}
        for argument, constraint in arguments.items():
            kind, value = next(iter(constraint.items()))
            if kind == "range":
                compiled = Range(value["min"], value["max"])
            elif kind == "wildcard":
                compiled = Wildcard()
            else:
                compiled = factories[kind](value)
            result[tool][argument] = compiled
    return result


def capabilities_from_allow(specs: list[str]) -> dict:
    """Convert CLI scope syntax into the same typed, serializable representation."""
    from hermes_tenuo.cli import parse_allow
    from tenuo import Exact, OneOf, Pattern, Range, Subpath, Wildcard
    capabilities = {}
    for spec in specs:
        tool, constraints, display = parse_allow(spec)
        if tool in capabilities:
            raise PolicyError(f"duplicate tool: {tool}")
        capabilities[tool] = {}
        for argument, constraint in constraints.items():
            if isinstance(constraint, Exact):
                value = {"exact": constraint.value}
            elif isinstance(constraint, OneOf):
                value = {"one_of": [v.strip() for v in display[argument].split("|") if v.strip()]}
            elif isinstance(constraint, Pattern):
                value = {"pattern": constraint.pattern}
            elif isinstance(constraint, Range):
                value = {"range": {"min": constraint.min, "max": constraint.max}}
            elif isinstance(constraint, Subpath):
                value = {"subpath": constraint.root}
            elif isinstance(constraint, Wildcard):
                value = {"wildcard": True}
            else:
                raise PolicyError("unsupported CLI constraint")
            capabilities[tool][argument] = value
    return validate_capabilities(capabilities)


def cmd_policy(args) -> int:
    import sys
    try:
        policy = load_policy(args.path)
        compile_capabilities(policy["capabilities"])
        resolved = resolve_policy_approvals(policy, args.path)
    except (PolicyError, ValueError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.policy_command == "show":
        shown = dict(policy)
        if resolved:
            from hermes_tenuo.operation_approvals import fingerprint
            from tenuo import PublicKey
            shown["resolved_approval_keys"] = [
                {"public_key": key, "fingerprint": fingerprint(PublicKey.from_bytes(base64.b64decode(key)))}
                for key in resolved["public_keys"]]
        print(json.dumps(shown, indent=2, sort_keys=True))
    else:
        print(f"Policy valid: {args.path}")
    return 0
