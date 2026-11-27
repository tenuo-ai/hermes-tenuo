"""Where Hermes would run a delegated task.

Hermes can send a ``delegate_task`` task to another Hermes profile
(``delegation.backend``, for example the ``profile_routes`` strategy). That
profile loads its own plugins and its own config, so the permission checks of
the profile that delegated do not see the child's tool calls.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Mapping, Optional

_PARAMETER = re.compile(r"^[a-z][a-z0-9_]{0,63}$")  # the parameter names Hermes accepts from a strategy


class Destination(str):
    """A Hermes profile name, with the delegation strategy that sends the task there (when one does)."""

    backend: str

    def __new__(cls, profile: str, backend: str = "") -> "Destination":
        self = super().__new__(cls, profile)
        self.backend = backend
        return self


def named_profile(task: Mapping[str, Any]) -> Optional[str]:
    """The profile a task asks for by name, if it asks for one."""
    named = task.get("profile")
    if isinstance(named, str):
        return named.strip() or None
    return str(named) if named else None


def _backends(config: Mapping[str, Any]) -> List[Any]:
    """Every delegation strategy this session's ``delegate_task`` could be routing on.

    A Hermes session keeps the strategy its tools were built with, even after
    ``delegation.backend`` is changed, and a tool-call check is not told which
    one that is. So the saved strategy comes first, then every other one that
    can run here.
    """
    from agent.delegation_provider import DelegationRouteError
    from agent.delegation_registry import get_active_provider

    found: List[Any] = []
    try:
        found.append(get_active_provider(config))
    except DelegationRouteError:
        pass  # Hermes refuses a delegation on the saved strategy itself
    try:
        from agent.delegation_backends import list_backends
        from agent.delegation_registry import backend_status
    except ImportError:
        return found  # a Hermes where a session cannot keep an earlier strategy
    for info in list_backends():
        provider, reason = backend_status(info.name)
        if provider is not None and not reason and all(provider.name != other.name for other in found):
            found.append(provider)
    return found


def _payload(provider: Any, task: Mapping[str, Any], index: int, config: Mapping[str, Any]) -> Dict[str, Any]:
    """What Hermes hands ``provider.route_task``: goal, context, the task's place in the batch and the
    values of the parameters the strategy declares."""
    from agent.delegation_provider import RESERVED_TASK_PARAMETERS

    try:
        declared = provider.task_parameters(config)
    except Exception:  # noqa: BLE001 - Hermes gives a strategy whose parameters fail none
        declared = {}
    names = [
        name for name, schema in (declared.items() if isinstance(declared, Mapping) else ())
        if isinstance(name, str) and _PARAMETER.match(name) and name not in RESERVED_TASK_PARAMETERS
        and isinstance(schema, Mapping)
    ]
    params = {name: task[name] for name in names if task.get(name) is not None}
    return {"goal": task.get("goal"), "context": task.get("context"), "index": index, **params}


def other_profile(task: Mapping[str, Any], index: int = 0) -> Optional[Destination]:
    """Where *task* would run, when Hermes would not run it in this profile.

    *index* is the task's place in its ``delegate_task`` call, counted from 0.
    Asks each delegation strategy the session could be using, the way
    ``delegate_task`` does, so a default profile set in config counts too. An
    error other than Hermes's own "this route cannot run" is raised to the
    caller, which must not treat an unknown destination as this profile.
    """
    named = named_profile(task)
    if named:
        return Destination(named)
    try:
        from agent.delegation_provider import DelegationRouteError
        from agent.delegation_registry import get_active_provider  # noqa: F401
    except ImportError:
        return None  # a Hermes without delegation strategies: every child runs here
    from hermes_tenuo._home import load_hermes_config

    config = load_hermes_config().get("delegation")
    config = dict(config) if isinstance(config, Mapping) else {}
    for provider in _backends(config):
        own = {**config, "backend": provider.name}
        try:
            route = provider.route_task(_payload(provider, task, index, own), own)
        except DelegationRouteError:
            continue  # this strategy starts no subagent for the task
        profile = route.get("profile") if isinstance(route, Mapping) else None
        if profile:
            return Destination(str(profile), str(provider.name))
    return None
