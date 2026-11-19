"""Delegation plans: argument-level grants for each depth of a delegate_task tree.

The issuer that mints the root warrant writes a plan saying, for each depth,
which tools a child keeps and which argument constraints it adds. Composite
constraints are opaque once minted, so a child's constraint is rebuilt as
``All(root members + level 1 members + ... + its own)``.

The plan is not trusted: Tenuo checks every grant against the signed parent,
so a plan can only narrow. A grant Tenuo refuses blocks the delegation.

    {"version": 1,
     "root":   {"tools": {"terminal": {"command": {"binaries": ["kubectl"],
                                                   "patterns": ["^kubectl get pods -n shop$"]}},
                          "delegate_task": {}}},
     "levels": [{"ttl_seconds": 1800, "tools": {...}}, {"ttl_seconds": 600, "tools": {...}}]}

``patterns`` are anchored regular expressions; ``binaries`` becomes Shlex;
``range`` is an inclusive numeric ``[min, max]`` (for a numeric argument the
tool always sends, e.g. the terminal timeout). A tool mapped to ``{}`` carries
no argument constraints.
"""

from __future__ import annotations

import json
import math
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


class DelegationPlanError(ValueError):
    """The plan file is missing, malformed, or inconsistent."""


@dataclass(frozen=True)
class Level:
    ttl_seconds: Optional[int]
    tools: Dict[str, Dict[str, dict]]  # tool → arg → {"binaries": [...], "patterns": [...]}
    max_uses: Dict[str, int] = field(default_factory=dict)  # tool → uses a grant at this level allows

    def use_limits(self, tools: Iterable[str]) -> Dict[str, int]:
        """The effective limits for retained tools, with aliases sharing the minimum."""
        keep = set(tools)
        limits: Dict[str, int] = {}
        for tool, limit in self.max_uses.items():
            if tool in keep:
                name = tool.removeprefix("tool:")
                limits[name] = min(limits.get(name, limit), limit)
        return limits


def _members(spec: dict) -> List[Any]:
    from tenuo import AnyOf, Range, Regex
    import tenuo_core

    out: List[Any] = []
    if spec.get("binaries"):
        out.append(tenuo_core.Shlex(allow=list(spec["binaries"])))
    if spec.get("patterns"):
        out.append(AnyOf([Regex(p) for p in spec["patterns"]]))
    if spec.get("range"):
        lo, hi = spec["range"]
        out.append(Range(lo, hi))
    return out


@dataclass(frozen=True)
class DelegationPlan:
    root: Level
    levels: tuple

    @property
    def max_depth(self) -> int:
        return len(self.levels)

    def level(self, depth: int) -> Optional[Level]:
        return self.levels[depth - 1] if 1 <= depth <= len(self.levels) else None

    def constraints_for(self, depth: int) -> Dict[str, Optional[Dict[str, Any]]]:
        """tool → {arg: All(...)} for a child at ``depth``; None means unconstrained.

        Each argument is the ``All`` of every ancestor's members. A warrant that
        delegates under this plan must mint the same ``All`` structure for the
        root (see ``capability_members``) so attenuation stays All-to-All.
        """
        from tenuo import All

        ancestry = [self.root] + list(self.levels[:depth])
        result: Dict[str, Optional[Dict[str, Any]]] = {}
        for tool, args in ancestry[-1].tools.items():
            if any(tool not in lvl.tools for lvl in ancestry):
                raise DelegationPlanError(f"{tool} at depth {depth} is not held by every ancestor")
            named = {
                arg
                for lvl in ancestry
                for arg in (lvl.tools[tool] or {})
                if arg != ALLOW_UNKNOWN
            }
            open_world = all((lvl.tools[tool] or {}).get(ALLOW_UNKNOWN) is True for lvl in ancestry)
            if not named and not open_world:
                result[tool] = None
                continue
            caps: Dict[str, Any] = {
                arg: All([m for lvl in ancestry for m in _members(lvl.tools[tool].get(arg, {}))])
                for arg in named
            }
            # Other arguments stay allowed only if every ancestor level allows them.
            if open_world:
                caps[ALLOW_UNKNOWN] = True
            result[tool] = caps
        return result


# A tool entry may set this to true to let the tool take arguments the plan
# does not name (for example Hermes's optional terminal arguments such as
# workdir). Named arguments are still checked. A child level keeps it only
# when every ancestor level sets it.
ALLOW_UNKNOWN = "_allow_unknown"

# A tool entry in a level may set this to a positive integer: how many times a
# grant at that level may use the tool. A use is taken when a call is allowed,
# so a call that then fails still counts. An object under this name is an
# ordinary argument constraint.
MAX_USES = "max_uses"


def _level(raw: Any, where: str, *, root: bool = False) -> Level:
    if not isinstance(raw, dict) or not isinstance(raw.get("tools"), dict):
        raise DelegationPlanError(f"{where}: expected an object with 'tools'")
    allowed_level_keys = {"tools"} if root else {"tools", "ttl_seconds", "role"}
    unknown_level_keys = set(raw) - allowed_level_keys
    if unknown_level_keys:
        raise DelegationPlanError(f"{where}: unknown fields: {sorted(unknown_level_keys)}")
    ttl = raw.get("ttl_seconds")
    if not root and (not isinstance(ttl, int) or isinstance(ttl, bool) or ttl <= 0):
        raise DelegationPlanError(f"{where}: ttl_seconds must be a positive integer")
    max_uses: Dict[str, int] = {}
    for tool, args in raw["tools"].items():
        if not isinstance(tool, str) or not tool:
            raise DelegationPlanError(f"{where}: tool names must be non-empty strings")
        if not isinstance(args, dict):
            raise DelegationPlanError(f"{where}: {tool} constraints must be an object")
        for arg, spec in args.items():
            if arg == MAX_USES and not isinstance(spec, dict):
                if root:
                    raise DelegationPlanError(f"{where}: {tool}.{MAX_USES} is only supported in levels")
                if not isinstance(spec, int) or isinstance(spec, bool) or spec <= 0:
                    raise DelegationPlanError(f"{where}: {tool}.{MAX_USES} must be a positive integer")
                max_uses[tool] = spec
                continue
            if not isinstance(arg, str) or not arg:
                raise DelegationPlanError(f"{where}: {tool} argument names must be non-empty strings")
            if arg == ALLOW_UNKNOWN:
                if spec is not True:
                    raise DelegationPlanError(f"{where}: {tool}.{ALLOW_UNKNOWN} must be true when present")
                continue
            if not isinstance(spec, dict):
                raise DelegationPlanError(f"{where}: {tool}.{arg} constraint must be an object")
            unknown_spec_keys = set(spec) - {"binaries", "patterns", "range"}
            if unknown_spec_keys:
                raise DelegationPlanError(
                    f"{where}: {tool}.{arg} unknown fields: {sorted(unknown_spec_keys)}"
                )
            patterns = spec.get("patterns", [])
            if not isinstance(patterns, list):
                raise DelegationPlanError(f"{where}: {tool}.{arg} patterns must be a list")
            if not all(isinstance(p, str) and p.startswith("^") and p.endswith("$") for p in patterns):
                raise DelegationPlanError(f"{where}: {tool}.{arg} patterns must be anchored (^...$)")
            binaries = spec.get("binaries", [])
            if not isinstance(binaries, list) or not all(isinstance(b, str) and b for b in binaries):
                raise DelegationPlanError(
                    f"{where}: {tool}.{arg} binaries must be non-empty strings in a list"
                )
            rng = spec.get("range")
            if rng is not None and (
                not isinstance(rng, list)
                or len(rng) != 2
                or not all(
                    isinstance(n, (int, float)) and not isinstance(n, bool) and math.isfinite(n)
                    for n in rng
                )
                or rng[0] > rng[1]
            ):
                raise DelegationPlanError(f"{where}: {tool}.{arg} range must be [min, max] with min <= max")
            if not patterns and not binaries and rng is None:
                raise DelegationPlanError(f"{where}: {tool}.{arg} has no constraints")
            # Validate even specs omitted by all descendants. Composition alone
            # never constructs constraints on tools/arguments dropped later.
            try:
                _members(spec)
            except Exception as exc:
                raise DelegationPlanError(
                    f"{where}: {tool}.{arg} invalid constraint ({type(exc).__name__})"
                ) from exc
    tools = {
        t: {arg: spec for arg, spec in a.items() if not (arg == MAX_USES and t in max_uses)}
        for t, a in raw["tools"].items()
    }
    return Level(ttl, tools, max_uses)


def parse_plan(data: Any) -> DelegationPlan:
    if not isinstance(data, dict) or data.get("version") != 1:
        raise DelegationPlanError("unsupported plan version (expected 1)")
    unknown_keys = set(data) - {"version", "root", "levels"}
    if unknown_keys:
        raise DelegationPlanError(f"plan has unknown fields: {sorted(unknown_keys)}")
    if not isinstance(data.get("levels"), list) or not data["levels"]:
        raise DelegationPlanError("plan needs at least one level")
    plan = DelegationPlan(
        root=_level(data.get("root"), "root", root=True),
        levels=tuple(_level(lvl, f"levels[{i}]") for i, lvl in enumerate(data["levels"])),
    )
    for depth in range(1, plan.max_depth + 1):
        plan.constraints_for(depth)  # report ancestry errors at load time
    inherited_limits: Dict[str, int] = {}
    for index, level in enumerate(plan.levels):
        limits = level.use_limits(level.tools)
        for tool, uses in limits.items():
            if tool in inherited_limits and uses > inherited_limits[tool]:
                raise DelegationPlanError(
                    f"levels[{index}]: {tool}.{MAX_USES} is larger than the level above allows"
                )
        # Omitting a limit does not erase the budget inherited from ancestors.
        inherited_limits.update(limits)
    return plan


def capability_members(spec: dict) -> List[Any]:
    """The constraint members for one argument spec, wrapped for a capability.

    Mint the root warrant with ``All(capability_members(spec))`` per argument so
    its structure matches what children receive from ``constraints_for`` and
    attenuation stays All-to-All.
    """
    return _members(spec)


def load_plan(path: str | Path) -> DelegationPlan:
    p = Path(path).expanduser()
    try:
        if p.is_symlink():
            raise DelegationPlanError(f"delegation plan {p} must not be a symlink")
        # Nonblocking open avoids hanging on FIFOs. Check the opened descriptor,
        # not a separate stat of a path that could be replaced before the read.
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(p, flags)
        try:
            mode = os.fstat(fd).st_mode
            if not stat.S_ISREG(mode):
                raise DelegationPlanError(f"delegation plan {p} must be a regular file")
            if os.name != "nt" and mode & 0o022:
                raise DelegationPlanError(
                    f"delegation plan {p} must not be writable by group or other users"
                )
            with os.fdopen(fd, encoding="utf-8", closefd=False) as stream:
                return parse_plan(json.load(stream))
        finally:
            os.close(fd)
    except FileNotFoundError as exc:
        raise DelegationPlanError(f"delegation plan {p} does not exist") from exc
    except DelegationPlanError:
        raise
    except Exception as exc:
        # Core constraint constructors (e.g. Regex) use their own exception
        # types. All invalid plans must reach the startup block-all handler.
        raise DelegationPlanError(
            f"delegation plan {p} cannot be loaded ({type(exc).__name__})"
        ) from exc
