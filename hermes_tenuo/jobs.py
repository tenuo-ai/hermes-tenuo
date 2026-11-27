"""Jobs: named limits a parent gives a delegated helper.

People have roles (``access``). Helpers get jobs. A job names the tools a
``delegate_task`` child may use and how, for example "read the logs" or "push
this branch once". The parent picks a job per task; the child's grant is its
parent's grant narrowed to that job, so a helper never gets more than whoever
asked, and usually much less.

    jobs:
      log-reader:
        description: Reads the checkout logs.
        allow:
          terminal: { command: { patterns: ["^\\./checkoutctl logs$"] } }
      restarter:
        description: Restarts checkout, once.
        ttl_seconds: 300
        allow:
          terminal: { max_uses: 1, command: { patterns: ["^\\./checkoutctl restart$"] } }

The argument syntax is the one ``access`` roles use. ``max_uses`` on a tool is
how many times that helper may use it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Tuple

BACKEND = "tenuo"          # delegation.backend value that lets the agent pick a job per task
PARAMETER = "job"          # the per-task delegate_task parameter
_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


class JobsConfigError(ValueError):
    """The ``jobs`` block is malformed. Raised so the plugin fails closed."""


@dataclass(frozen=True)
class Job:
    name: str
    description: str
    ttl_seconds: Optional[int]
    tools: Tuple[str, ...]                                   # the tools this job keeps, without "tool:"
    parts: Dict[str, Dict[str, Any]] = field(default_factory=dict)   # tool → argument → part
    strict: frozenset = frozenset()                          # tools that take only the named arguments
    max_uses: Dict[str, int] = field(default_factory=dict)   # tool → uses


@dataclass(frozen=True)
class Jobs:
    jobs: Dict[str, Job]
    default: Optional[str] = None

    def get(self, name: Optional[str]) -> Optional[Job]:
        return self.jobs.get(name) if name else None


def parse_jobs(block: Any, default: Any = None) -> Jobs:
    """Parse and validate the ``jobs`` block and ``default_job``. Any problem raises."""
    from hermes_tenuo.access import AccessConfigError, constraint_part

    if not isinstance(block, dict) or not block:
        raise JobsConfigError("jobs must be a non-empty map of job name → definition")
    jobs: Dict[str, Job] = {}
    for name, spec in block.items():
        if not isinstance(name, str) or not _NAME.match(name):
            raise JobsConfigError(f"jobs: {name!r} is not a valid job name (lowercase letters, digits, - and _)")
        where = f"jobs.{name}"
        if not isinstance(spec, dict):
            raise JobsConfigError(f"{where}: a job must be an object")
        unknown = set(spec) - {"description", "ttl_seconds", "allow"}
        if unknown:
            raise JobsConfigError(f"{where}: unknown fields: {sorted(unknown, key=str)}")
        description = spec.get("description", "")
        if not isinstance(description, str):
            raise JobsConfigError(f"{where}: description must be text")
        ttl = spec.get("ttl_seconds")
        if ttl is not None and (not isinstance(ttl, int) or isinstance(ttl, bool) or ttl <= 0):
            raise JobsConfigError(f"{where}: ttl_seconds must be a positive integer")
        allow = spec.get("allow")
        if isinstance(allow, list):
            allow = {str(tool): {} for tool in allow}
        if not isinstance(allow, dict) or not allow:
            raise JobsConfigError(f"{where}: allow must be a non-empty map of tool → limits")
        parts: Dict[str, Dict[str, Any]] = {}
        strict, limits = set(), {}
        tools = []
        for written, limit in allow.items():
            # "tool:terminal" and "terminal" name one tool; everything below is kept under the plain name.
            tool = written.removeprefix("tool:") if isinstance(written, str) else ""
            if not tool:
                raise JobsConfigError(f"{where}.allow: tool names must be non-empty strings")
            if tool in tools:
                raise JobsConfigError(f"{where}.allow: {tool} is listed twice (as {tool} and tool:{tool})")
            tools.append(tool)
            tool_where = f"{where}.allow.{written}"
            if limit in ("*", None) or limit == {}:
                continue
            if not isinstance(limit, dict):
                raise JobsConfigError(f"{tool_where}: limits must be an object, '*', or empty")
            for arg, value in limit.items():
                if arg == "strict":
                    if value is True:
                        strict.add(tool)
                    elif value is not False:
                        raise JobsConfigError(f"{tool_where}: strict must be true or false")
                elif arg == "max_uses":
                    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                        raise JobsConfigError(f"{tool_where}: max_uses must be a positive integer")
                    limits[tool] = value
                elif not isinstance(arg, str) or not arg or arg.startswith("_"):
                    raise JobsConfigError(f"{tool_where}: argument names must be non-empty and not start with '_'")
                else:
                    try:
                        parts.setdefault(tool, {})[arg] = constraint_part(value, f"{tool_where}.{arg}")
                    except AccessConfigError as exc:
                        raise JobsConfigError(str(exc)) from exc
        jobs[name] = Job(name, description.strip(), ttl, tuple(tools), parts, frozenset(strict), limits)
    if default is not None and (not isinstance(default, str) or default not in jobs):
        raise JobsConfigError(f"default_job: no job named {default!r}")
    return Jobs(jobs, default)


def narrowed(job: Job, tool: str, parent_caps: Mapping[str, Any], parent_parts: Mapping[str, Any],
             unknown_allowed: bool) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """*tool*'s arguments for a child doing *job*: (constraints to grant, the parts they are made of).

    A job limit joins the parent's own limit on the same argument when both are made of
    members; otherwise the job's limit is offered as it is and the core accepts it only
    if it is narrower than the parent's.
    """
    from tenuo import All
    from hermes_tenuo.delegation import ALLOW_UNKNOWN

    caps: Dict[str, Any] = {}
    parts: Dict[str, Any] = {}
    wanted = job.parts.get(tool, {})
    for arg in [a for a in parent_caps if a != ALLOW_UNKNOWN] + [a for a in wanted if a not in parent_caps]:
        mine, theirs = wanted.get(arg), parent_parts.get(arg)
        if mine is None:
            caps[arg] = parent_caps[arg]
            if theirs is not None:
                parts[arg] = theirs
        elif mine[0] == "all":
            members = (list(theirs[1]) if theirs is not None and theirs[0] == "all" else []) + list(mine[1])
            caps[arg], parts[arg] = All(members), ("all", members)
        else:
            caps[arg], parts[arg] = mine[1], mine
    if unknown_allowed and tool not in job.strict:
        caps[ALLOW_UNKNOWN] = True
    return caps, parts


def delegation_provider(jobs: Jobs) -> Any:
    """A Hermes delegation strategy (``delegation.backend: tenuo``) that adds a per-task ``job``
    choice to ``delegate_task``. It routes every task exactly as the default strategy does."""
    from agent.delegation_provider import DelegationProvider

    listing = "; ".join(f"{job.name}" + (f" ({job.description})" if job.description else "") for job in jobs.jobs.values())

    class TenuoJobs(DelegationProvider):
        @property
        def name(self) -> str:
            return BACKEND

        @property
        def display_name(self) -> str:
            return "Tenuo jobs"

        @property
        def summary(self) -> str:
            return "The agent gives each subagent a job; the subagent gets only that job's permissions."

        def task_parameters(self, config: Mapping[str, Any]) -> Dict[str, Dict[str, Any]]:
            return {PARAMETER: {
                "type": "string", "enum": sorted(jobs.jobs),
                "description": f"The job this subagent does. It gets only that job's permissions. Jobs: {listing}.",
            }}

        def description(self, config: Mapping[str, Any]) -> str:
            return ("Each task should set `job`: the subagent can then do only what that job allows, "
                    "and never more than you can.")

        def route_task(self, task: Mapping[str, Any], config: Mapping[str, Any]) -> Dict[str, Any]:
            return {k: v for k, v in config.items() if k != "service_tier"}

    return TenuoJobs()
