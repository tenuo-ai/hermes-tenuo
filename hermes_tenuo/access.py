"""Role-based access for the gateway: one warrant per user role, from plain config.

An operator writes an ``access:`` block under ``plugins.entries.hermes-tenuo``
and gets per-user authorization with no code, no manual minting, and no
``set_session_warrant`` glue. This module is the front-end: it parses the block
and compiles each role's ``allow`` into a Tenuo warrant. Binding a warrant to
the current message's sender happens in the guard (see ``hermes_guard``); here
we only turn config into warrants and answer "which role is this identity".

    access:
      roles:
        owner:
          match: { user: ["telegram:12345"] }
          allow:
            terminal:   { command: { binaries: ["git", "ls"] } }
            read_file:  { path: "/data/**" }
            write_file: { path: "/data/**" }
            web_search: {}
        guest:
          default: true
          allow:
            web_search: {}
      on_unmatched: guest        # or: deny

Friendlier than hand-minting in two ways: a constrained tool keeps its other
arguments by default (``read_file: {path: ...}`` still allows ``limit``), and
``terminal: {command: {binaries: [...]}}`` is a real allowlist, not a glob.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from hermes_tenuo.delegation import ALLOW_UNKNOWN, capability_members

logger = logging.getLogger("hermes_tenuo.access")

# How a role's identity criteria are named; a role matches when the current
# sender satisfies every dimension it lists (and any value within a dimension).
_MATCH_KEYS = ("user", "chat", "platform")
_DEFAULT_TTL = 3600


class AccessConfigError(ValueError):
    """The access block is missing fields, malformed, or inconsistent."""


# A message on a chat platform with no single sender (a shared feed). It matches
# no ``user`` rule, so such a turn falls to the default role or is denied.
NOBODY = "?"


def current_sender() -> Optional[Dict[str, str]]:
    """The current turn's sender, for role matching, or None off a gateway.

    ``user`` and ``chat`` are ``"<platform>:<id>"``; ``platform`` is the bare
    platform. The identity follows the message's actual sender where Hermes names
    it (``HERMES_SESSION_ACTOR_ID``), so a shared group chat is authorised per
    message rather than per session — the sender a model believes it is talking
    to never changes who the tool call is authorised as. A messaging turn with no
    single sender is ``NOBODY``. A non-gateway turn (CLI / local, no platform)
    returns None so access does not govern it.
    """
    try:
        from gateway import session_context as context
    except Exception:
        return None
    try:
        import inspect

        read = context.get_session_env
        platform = str(read("HERMES_SESSION_PLATFORM", "") or "")
        if not platform:
            return None
        # Access governs only messaging (gateway) turns. A CLI, desktop or API turn
        # has a platform too, but it is the operator, not a chat user: leave it to
        # the static warrant (return None). Fall back to a small local-surface list
        # on a Hermes without the messaging-surface check.
        messaging = getattr(context, "session_is_messaging_surface", None)
        is_messaging = messaging() if callable(messaging) else platform not in (
            "cli", "desktop", "local", "api_server", "tui", "codex", "tool", "webhook")
        if not is_messaging:
            return None
        chat = str(read("HERMES_SESSION_CHAT_ID", "") or "")
        names_sender = "actor_id" in inspect.signature(context.set_session_vars).parameters
        raw = read("HERMES_SESSION_ACTOR_ID" if names_sender else "HERMES_SESSION_USER_ID", "")
        person = str(raw or "")
        return {
            "user": f"{platform}:{person}" if person else NOBODY,
            "chat": f"{platform}:{chat}" if chat else "",
            "platform": platform,
        }
    except Exception:
        # Fail closed: an unreadable identity matches no role.
        return {"user": NOBODY, "chat": "", "platform": ""}


def _constraint(value: Any, where: str) -> Any:
    """Compile one friendly argument value to a Tenuo constraint.

    Strings: ``"*"`` is unconstrained, ``"/a/**"`` is any path under ``/a``,
    anything else is an exact match. Objects use explicit keys (``subpath``,
    ``exact``, ``wildcard``) or the advanced ``binaries``/``patterns``/``range``
    form shared with delegation plans.
    """
    from tenuo import All, Exact, Subpath, Wildcard

    if isinstance(value, str):
        if value == "*":
            return Wildcard()
        if value.endswith("/**"):
            return Subpath(value[:-3] or "/")
        return Exact(value)
    if not isinstance(value, dict):
        raise AccessConfigError(f"{where}: value must be a string or an object")
    if value.get("wildcard") is True or value == {}:
        return Wildcard()
    if "subpath" in value:
        if not isinstance(value["subpath"], str) or not value["subpath"]:
            raise AccessConfigError(f"{where}: subpath must be a non-empty string")
        return Subpath(value["subpath"])
    if "exact" in value:
        if not isinstance(value["exact"], str):
            raise AccessConfigError(f"{where}: exact must be a string")
        return Exact(value["exact"])
    unknown = set(value) - {"binaries", "patterns", "range"}
    if unknown or not value:
        raise AccessConfigError(
            f"{where}: unknown constraint keys {sorted(unknown)}; use a string, "
            "subpath/exact/wildcard, or binaries/patterns/range"
        )
    members = capability_members(value)  # reuses delegation plan validation/building
    if not members:
        raise AccessConfigError(f"{where}: no constraint built from {sorted(value)}")
    return All(members)


def _compile_allow(allow: Any, where: str) -> Dict[str, Dict[str, Any]]:
    """A role's ``allow`` → ``{tool: {arg: Constraint, _allow_unknown: True}}``.

    ``allow`` is a map of tool → argument constraints, or a list of tool names
    to allow unconstrained. A tool maps to ``{}`` (or ``"*"``) to allow it with
    no argument constraints. By default a tool keeps its unnamed arguments; a
    tool (or the whole role) may set ``strict: true`` to deny them.
    """
    if isinstance(allow, list):
        allow = {str(tool): {} for tool in allow}
    if not isinstance(allow, dict) or not allow:
        raise AccessConfigError(f"{where}: allow must be a non-empty map of tool → constraints")
    caps: Dict[str, Dict[str, Any]] = {}
    for tool, spec in allow.items():
        if not isinstance(tool, str) or not tool:
            raise AccessConfigError(f"{where}: tool names must be non-empty strings")
        tool_where = f"{where}.{tool}"
        if spec in ("*", None) or spec == {}:
            caps[tool] = {ALLOW_UNKNOWN: True}
            continue
        if not isinstance(spec, dict):
            raise AccessConfigError(f"{tool_where}: constraints must be an object, '*', or empty")
        strict = bool(spec.get("strict", False))
        constraints: Dict[str, Any] = {}
        for arg, value in spec.items():
            if arg == "strict":
                continue
            if not isinstance(arg, str) or not arg or arg.startswith("_"):
                raise AccessConfigError(f"{tool_where}: argument names must be non-empty and not start with '_'")
            constraints[arg] = _constraint(value, f"{tool_where}.{arg}")
        if not strict:
            constraints[ALLOW_UNKNOWN] = True
        if not constraints:
            raise AccessConfigError(f"{tool_where}: strict tool must name at least one argument")
        caps[tool] = constraints
    return caps


@dataclass(frozen=True)
class Role:
    name: str
    match: Dict[str, Tuple[str, ...]]
    capabilities: Dict[str, Dict[str, Any]]
    is_default: bool = False

    def matches(self, user: str, chat: str, platform: str) -> bool:
        """True when the sender satisfies every dimension this role names."""
        ident = {"user": user, "chat": chat, "platform": platform}
        if not self.match:
            return False  # a role with no match is reachable only as the default
        return all(ident.get(key, "") in values for key, values in self.match.items())


def _parse_match(raw: Any, where: str) -> Dict[str, Tuple[str, ...]]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise AccessConfigError(f"{where}: match must be an object")
    unknown = set(raw) - set(_MATCH_KEYS)
    if unknown:
        raise AccessConfigError(f"{where}: match has unknown keys {sorted(unknown)}; allowed: {list(_MATCH_KEYS)}")
    out: Dict[str, Tuple[str, ...]] = {}
    for key, values in raw.items():
        if isinstance(values, str):
            values = [values]
        if not isinstance(values, list) or not values or not all(isinstance(v, str) and v for v in values):
            raise AccessConfigError(f"{where}: match.{key} must be a non-empty string or list of strings")
        out[key] = tuple(values)
    return out


@dataclass
class AccessConfig:
    """Parsed, validated access block. Roles keep config order; the default is
    tried last. ``deny`` means an unmatched sender gets no warrant (fail closed)."""

    roles: List[Role]
    default_role: Optional[str]  # name of the role for unmatched senders, or None = deny

    def role_for(self, *, user: str = "", chat: str = "", platform: str = "") -> Optional[Role]:
        # An unattributable message (no single sender) can claim no specific role,
        # not even a platform- or chat-wide one: it gets the default role, or is
        # denied. Only an identified sender is matched against the roles.
        if user != NOBODY:
            for role in self.roles:
                if not role.is_default and role.matches(user, chat, platform):
                    return role
        if self.default_role is not None:
            return next(r for r in self.roles if r.name == self.default_role)
        return None


def parse_access(block: Any) -> AccessConfig:
    """Parse and validate the ``access:`` block. Fail closed: any problem raises."""
    if not isinstance(block, dict):
        raise AccessConfigError("access must be an object")
    unknown = set(block) - {"roles", "on_unmatched"}
    if unknown:
        raise AccessConfigError(f"access has unknown fields: {sorted(unknown)}")
    raw_roles = block.get("roles")
    if not isinstance(raw_roles, dict) or not raw_roles:
        raise AccessConfigError("access.roles must be a non-empty map of role name → definition")

    roles: List[Role] = []
    defaults: List[str] = []
    for name, spec in raw_roles.items():
        if not isinstance(name, str) or not name:
            raise AccessConfigError("role names must be non-empty strings")
        where = f"roles.{name}"
        if not isinstance(spec, dict):
            raise AccessConfigError(f"{where}: role definition must be an object")
        unknown = set(spec) - {"match", "allow", "default"}
        if unknown:
            raise AccessConfigError(f"{where}: unknown fields: {sorted(unknown)}")
        is_default = bool(spec.get("default", False))
        if is_default:
            defaults.append(name)
        match = _parse_match(spec.get("match"), where)
        if not match and not is_default:
            raise AccessConfigError(f"{where}: a non-default role must have a match")
        roles.append(Role(name, match, _compile_allow(spec.get("allow"), f"{where}.allow"), is_default))

    if len(defaults) > 1:
        raise AccessConfigError(f"only one role may be the default; found {sorted(defaults)}")

    on_unmatched = block.get("on_unmatched", "deny")
    if on_unmatched == "deny":
        default_role = defaults[0] if defaults else None
    elif isinstance(on_unmatched, str):
        if on_unmatched not in raw_roles:
            raise AccessConfigError(f"on_unmatched: no role named '{on_unmatched}'")
        default_role = on_unmatched
    else:
        raise AccessConfigError("on_unmatched must be 'deny' or a role name")
    if defaults and default_role != defaults[0]:
        raise AccessConfigError(
            f"role '{defaults[0]}' is marked default but on_unmatched is '{on_unmatched}'; they must agree"
        )
    return AccessConfig(roles, default_role)


@dataclass
class AccessPolicy:
    """Compiled roles with a minted warrant each, ready for per-turn resolution.

    The guard calls ``warrant_for`` on each tool call with the current message's
    sender; an unmatched sender under a ``deny`` policy gets ``(None, None)`` and
    is blocked, never falling back to a broader warrant."""

    config: AccessConfig
    signing_key: Any
    _warrants: Dict[str, Any] = field(default_factory=dict)

    def warrant_for(self, *, user: str = "", chat: str = "", platform: str = "") -> Tuple[Optional[Any], Optional[Any]]:
        role = self.config.role_for(user=user, chat=chat, platform=platform)
        if role is None:
            return None, None
        return self._warrants[role.name], self.signing_key

    def role_name_for(self, *, user: str = "", chat: str = "", platform: str = "") -> Optional[str]:
        role = self.config.role_for(user=user, chat=chat, platform=platform)
        return role.name if role is not None else None


def build_access_policy(block: Any, *, control_key: Any, holder: Any, signing_key: Any,
                        ttl_seconds: int = _DEFAULT_TTL) -> AccessPolicy:
    """Parse the access block and mint one warrant per role.

    ``control_key`` signs the role warrants (its public key is the trusted root);
    ``holder`` is the gateway's public key that will present them; ``signing_key``
    is the gateway's private key the guard uses when checking proof-of-possession.
    """
    from hermes_tenuo.issuance import mint_for_holder

    config = parse_access(block)
    policy = AccessPolicy(config, signing_key)
    for role in config.roles:
        policy._warrants[role.name] = mint_for_holder(control_key, holder, role.capabilities, ttl_seconds)
    return policy
