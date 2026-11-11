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
      on_unmatched: guest

Friendlier than hand-minting in two ways: a constrained tool keeps its other
arguments by default (``read_file: {path: ...}`` still allows ``limit``), and
``terminal: {command: {binaries: [...]}}`` is a real allowlist, not a glob.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from hermes_tenuo.delegation import ALLOW_UNKNOWN, capability_members

logger = logging.getLogger("hermes_tenuo.access")

_OMITTED = object()  # tells an absent `on_unmatched` from an explicit `deny`

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


def subagent_attribution_lookup():
    """Hermes's runtime-owned child identity, independent of lifecycle hooks.

    Older Hermes cannot safely disambiguate unbound children from concurrent
    gateway users, so access-mode delegation must be refused on those builds.
    """
    try:
        from tools.delegate_tool_registry import get_subagent_attribution, list_active_subagents
    except ImportError:
        return None
    if not callable(get_subagent_attribution) or not callable(list_active_subagents):
        return None

    def lookup(task_id):
        attribution = get_subagent_attribution(task_id)
        if attribution is None:
            return None
        # The public live registry also names the owning agent session. This
        # distinguishes local audit-only children from explicitly warranted ones.
        record = next((r for r in list_active_subagents() if r.get("subagent_id") == task_id), {})
        return {**attribution, "parent_session_id": record.get("owner_agent_session_id")}

    return lookup


def _constraint(value: Any, where: str) -> Any:
    """Keep SDK validation errors inside the fail-closed config error boundary."""
    from tenuo.exceptions import TenuoError

    try:
        return _compile_constraint(value, where)
    except AccessConfigError:
        raise
    except (TenuoError, ValueError, TypeError, OverflowError) as exc:
        raise AccessConfigError(f"{where}: {exc}") from exc


def _compile_constraint(value: Any, where: str) -> Any:
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
    if value == {}:
        return Wildcard()
    simple = {"wildcard", "subpath", "exact"} & set(value)
    advanced = {"binaries", "patterns", "range"} & set(value)
    unknown = set(value) - simple - advanced
    if unknown:
        raise AccessConfigError(
            f"{where}: unknown constraint keys {sorted(unknown)}; use a string, "
            "wildcard/subpath/exact, or binaries/patterns/range"
        )
    if simple and advanced:
        raise AccessConfigError(f"{where}: cannot mix {sorted(simple)} with {sorted(advanced)}; use one form")
    if len(simple) > 1:
        raise AccessConfigError(f"{where}: {sorted(simple)} are mutually exclusive; keep one")
    if "wildcard" in value:
        if value["wildcard"] is not True:
            raise AccessConfigError(f"{where}: wildcard must be true when present")
        return Wildcard()
    if "subpath" in value:
        if not isinstance(value["subpath"], str) or not value["subpath"]:
            raise AccessConfigError(f"{where}: subpath must be a non-empty string")
        return Subpath(value["subpath"])
    if "exact" in value:
        if not isinstance(value["exact"], str):
            raise AccessConfigError(f"{where}: exact must be a string")
        return Exact(value["exact"])
    _validate_advanced(value, where)
    return All(capability_members(value))


def _validate_advanced(spec: dict, where: str) -> None:
    """Validate a ``{binaries, patterns, range}`` constraint, raising AccessConfigError.

    Mirrors the delegation-plan checks so a malformed constraint (an empty pattern, a
    string where a list is meant, a bad range) is rejected rather than silently dropped.
    """
    import math

    binaries = spec.get("binaries", [])
    if not isinstance(binaries, list) or not all(isinstance(b, str) and b for b in binaries):
        raise AccessConfigError(f"{where}: binaries must be a list of non-empty strings")
    patterns = spec.get("patterns", [])
    if not isinstance(patterns, list) or not all(
        isinstance(p, str) and p.startswith("^") and p.endswith("$") for p in patterns
    ):
        raise AccessConfigError(f"{where}: patterns must be anchored (^…$) strings in a list")
    rng = spec.get("range")
    if rng is not None and (
        not isinstance(rng, list)
        or len(rng) != 2
        or not all(isinstance(n, (int, float)) and not isinstance(n, bool) and math.isfinite(n) for n in rng)
        or rng[0] > rng[1]
    ):
        raise AccessConfigError(f"{where}: range must be [min, max] with min ≤ max")
    if not binaries and not patterns and rng is None:
        raise AccessConfigError(f"{where}: an advanced constraint needs binaries, patterns or range")


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
        raw_default = spec.get("default", False)
        if not isinstance(raw_default, bool):
            raise AccessConfigError(f"{where}: default must be true or false, not {raw_default!r}")
        is_default = raw_default
        if is_default:
            defaults.append(name)
        match = _parse_match(spec.get("match"), where)
        if not match and not is_default:
            raise AccessConfigError(f"{where}: a non-default role must have a match")
        roles.append(Role(name, match, _compile_allow(spec.get("allow"), f"{where}.allow"), is_default))

    if len(defaults) > 1:
        raise AccessConfigError(f"only one role may be the default; found {sorted(defaults)}")

    on_unmatched = block.get("on_unmatched", _OMITTED)
    if on_unmatched is _OMITTED:
        # Omitted: a `default: true` role catches unmatched senders, else they are denied.
        default_role = defaults[0] if defaults else None
    elif on_unmatched == "deny":
        if defaults:
            raise AccessConfigError(
                f"on_unmatched: deny conflicts with the default role '{defaults[0]}'; remove one"
            )
        default_role = None
    elif isinstance(on_unmatched, str):
        if on_unmatched not in raw_roles:
            raise AccessConfigError(f"on_unmatched: no role named '{on_unmatched}'")
        if defaults and on_unmatched != defaults[0]:
            raise AccessConfigError(
                f"on_unmatched '{on_unmatched}' conflicts with the default role '{defaults[0]}'"
            )
        default_role = on_unmatched
    else:
        raise AccessConfigError("on_unmatched must be 'deny' or a role name")
    return AccessConfig(roles, default_role)


class AccessPolicy:
    """Compiled roles, each with a minted warrant, ready for per-turn resolution.

    The guard calls ``warrant_for`` on each tool call with the current message's
    sender; an unmatched sender under a ``deny`` policy gets ``(None, None)`` and is
    blocked, never falling back to a broader warrant. A role warrant is re-minted as
    it nears expiry, so a long-running gateway does not lose authority after one TTL."""

    def __init__(self, config: AccessConfig, *, control_key: Any, holder: Any,
                 signing_key: Any, ttl_seconds: int):
        self.config = config
        self.signing_key = signing_key
        self._control = control_key
        self._holder = holder
        self._ttl = ttl_seconds
        self._warrants: Dict[str, Tuple[Any, float]] = {}   # role name → (warrant, minted monotonic)
        self._lock = threading.Lock()

    def _role_warrant(self, name: str) -> Any:
        import time
        from hermes_tenuo.issuance import mint_for_holder

        margin = min(300, max(1, self._ttl // 10))
        with self._lock:
            entry = self._warrants.get(name)
            now = time.monotonic()
            if (entry is None or now >= entry[1] + self._ttl - margin
                    or entry[0].ttl_remaining.total_seconds() <= margin):
                role = next(r for r in self.config.roles if r.name == name)
                warrant = mint_for_holder(self._control, self._holder, role.capabilities, self._ttl)
                self._warrants[name] = (warrant, now)
                return warrant
            return entry[0]

    def warrant_for(self, *, user: str = "", chat: str = "", platform: str = "") -> Tuple[Optional[Any], Optional[Any]]:
        role = self.config.role_for(user=user, chat=chat, platform=platform)
        if role is None:
            return None, None
        return self._role_warrant(role.name), self.signing_key

    def role_name_for(self, *, user: str = "", chat: str = "", platform: str = "") -> Optional[str]:
        role = self.config.role_for(user=user, chat=chat, platform=platform)
        return role.name if role is not None else None


def access_key_path():
    """Where the auto-provisioned access signing key lives."""
    from hermes_tenuo._home import hermes_home
    return hermes_home() / "tenuo" / "access.key"


def load_access_key() -> Optional[Any]:
    """The persisted access signing key, or None if not yet provisioned or unreadable."""
    from tenuo import SigningKey
    from hermes_tenuo._config import _b64_to_bytes
    path = access_key_path()
    try:
        if path.is_file():
            return SigningKey.from_bytes(_b64_to_bytes(path.read_text().strip()))
    except Exception as exc:  # noqa: BLE001 - a bad key file must not crash startup
        logger.warning("hermes-tenuo: access key at %s is unreadable (%s); a new one will be made",
                       path, type(exc).__name__)
    return None


def load_or_create_signing_key() -> Any:
    """The gateway's signing key for role warrants. Uses the persisted key, creating one
    under ``$HERMES_HOME/tenuo/access.key`` (0600) on first use so no key need be configured."""
    import base64

    from tenuo import SigningKey
    from hermes_tenuo.issuance import write_private_file

    # A stable sidecar lock must cover reads and corruption recovery as well as
    # creation. Locking the key itself would lock an obsolete inode after replace.
    try:
        import fcntl
    except ImportError as exc:
        raise OSError("access key provisioning requires POSIX file locking") from exc
    import os

    path = access_key_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock_fd = os.open(path.with_suffix(".lock"), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        key = load_access_key()
        if key is not None:
            return key
        key = SigningKey.generate()
        text = base64.b64encode(key.secret_key_bytes()).decode()
        write_private_file(path, text, overwrite=True)
        logger.info("hermes-tenuo: created an access signing key at %s", path)
        return key
    finally:
        os.close(lock_fd)  # releases the lock, including on read/write failure



def build_access_policy(block: Any, *, control_key: Any, holder: Any, signing_key: Any,
                        ttl_seconds: int = _DEFAULT_TTL) -> AccessPolicy:
    """Parse the access block and build the policy, minting one warrant per role.

    ``control_key`` signs the role warrants (its public key is the trusted root);
    ``holder`` is the gateway's public key that will present them; ``signing_key``
    is the gateway's private key the guard uses when checking proof-of-possession.
    The role warrants are re-minted as they near expiry, so authority does not lapse.
    """
    config = parse_access(block)
    policy = AccessPolicy(config, control_key=control_key, holder=holder,
                          signing_key=signing_key, ttl_seconds=ttl_seconds)
    for role in config.roles:
        policy._role_warrant(role.name)   # mint now so a bad constraint fails at startup
    return policy
