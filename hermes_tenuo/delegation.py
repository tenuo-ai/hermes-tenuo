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
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


class DelegationPlanError(ValueError):
    """The plan file is missing, malformed, or inconsistent."""


@dataclass(frozen=True)
class Level:
    ttl_seconds: Optional[int]
    tools: Dict[str, Dict[str, dict]]  # tool → arg → {"binaries": [...], "patterns": [...]}


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
            if not args:
                result[tool] = None
                continue
            result[tool] = {
                arg: All([m for lvl in ancestry for m in _members(lvl.tools[tool].get(arg, {}))])
                for arg in args
            }
        return result


def _level(raw: Any, where: str, *, root: bool = False) -> Level:
    if not isinstance(raw, dict) or not isinstance(raw.get("tools"), dict):
        raise DelegationPlanError(f"{where}: expected an object with 'tools'")
    ttl = raw.get("ttl_seconds")
    if not root and (not isinstance(ttl, int) or ttl <= 0):
        raise DelegationPlanError(f"{where}: ttl_seconds must be a positive integer")
    for tool, args in raw["tools"].items():
        for arg, spec in (args or {}).items():
            patterns = spec.get("patterns") or []
            if not all(isinstance(p, str) and p.startswith("^") and p.endswith("$") for p in patterns):
                raise DelegationPlanError(f"{where}: {tool}.{arg} patterns must be anchored (^...$)")
            rng = spec.get("range")
            if rng is not None and (not isinstance(rng, (list, tuple)) or len(rng) != 2
                                    or not all(isinstance(n, (int, float)) for n in rng) or rng[0] > rng[1]):
                raise DelegationPlanError(f"{where}: {tool}.{arg} range must be [min, max] with min <= max")
            if not patterns and not spec.get("binaries") and rng is None:
                raise DelegationPlanError(f"{where}: {tool}.{arg} has no constraints")
    return Level(ttl, {t: dict(a or {}) for t, a in raw["tools"].items()})


def parse_plan(data: Any) -> DelegationPlan:
    if not isinstance(data, dict) or data.get("version") != 1:
        raise DelegationPlanError("unsupported plan version (expected 1)")
    if not isinstance(data.get("levels"), list) or not data["levels"]:
        raise DelegationPlanError("plan needs at least one level")
    plan = DelegationPlan(
        root=_level(data.get("root"), "root", root=True),
        levels=tuple(_level(lvl, f"levels[{i}]") for i, lvl in enumerate(data["levels"])),
    )
    for depth in range(1, plan.max_depth + 1):
        plan.constraints_for(depth)  # report ancestry errors at load time
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
        return parse_plan(json.loads(p.read_text()))
    except FileNotFoundError as exc:
        raise DelegationPlanError(f"delegation plan {p} does not exist") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise DelegationPlanError(f"delegation plan {p} cannot be read: {exc}") from exc
