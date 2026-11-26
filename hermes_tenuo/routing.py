"""Where Hermes would run a delegated task.

Hermes can send a ``delegate_task`` task to another Hermes profile
(``delegation.backend``, for example the ``profile_routes`` strategy). That
profile loads its own plugins and its own config, so the permission checks of
the profile that delegated do not see the child's tool calls.
"""
from __future__ import annotations

from typing import Any, Mapping, Optional


def named_profile(task: Mapping[str, Any]) -> Optional[str]:
    """The profile a task asks for by name, if it asks for one."""
    named = task.get("profile")
    if isinstance(named, str):
        return named.strip() or None
    return str(named) if named else None


def other_profile(task: Mapping[str, Any]) -> Optional[str]:
    """The Hermes profile *task* would run as, when Hermes would not run it in this one.

    Asks the delegation strategy Hermes has configured, the way ``delegate_task``
    does, so a default profile set in config counts too. An error other than
    Hermes's own "this route cannot run" is raised to the caller, which must
    not treat an unknown destination as this profile.
    """
    named = named_profile(task)
    if named:
        return named
    try:
        from agent.delegation_provider import DelegationRouteError
        from agent.delegation_registry import get_active_provider
    except ImportError:
        return None  # a Hermes without delegation strategies: every child runs here
    from hermes_tenuo._home import load_hermes_config

    config = load_hermes_config().get("delegation")
    config = config if isinstance(config, Mapping) else {}
    try:
        provider = get_active_provider(config)
    except DelegationRouteError:
        return None  # Hermes refuses this delegation itself: no subagent starts
    route = provider.route_task(task, config)
    if not isinstance(route, Mapping):
        return None
    profile = route.get("profile")
    return str(profile) if profile else None
