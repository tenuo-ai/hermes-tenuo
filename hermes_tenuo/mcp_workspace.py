"""Import MCP connection settings and expose the selected tools by server name."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import math
import os
import re
import sys
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import httpx2
import yaml
from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client
from tenuo import SigningKey

from hermes_tenuo.issuance import write_private_file

_VARIABLE = re.compile(r"\$\{([A-Za-z_][A-Za-z_0-9]*)\}")
_NAME = re.compile(r"[A-Za-z0-9_-]+")


def _string_list(value):
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _mapping(value, description):
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError(f"{description} must be an object with string keys")
    return value


def _read_servers(path):
    try:
        document = yaml.safe_load(path.read_text())
    except yaml.YAMLError:
        raise ValueError("Could not parse the source config as JSON or YAML") from None
    document = _mapping(document, "MCP config")
    if "mcp_servers" in document and "mcpServers" in document:
        raise ValueError("Use one server map (mcp_servers or mcpServers)")
    return _mapping(document.get("mcp_servers", document.get("mcpServers")), "MCP server map")


def _validate_server(name, spec):
    if not _NAME.fullmatch(name) or "__" in name:
        raise ValueError(f"Server name {name!r} must use letters, numbers, hyphens or single underscores")
    spec = _mapping(spec, f"Server {name}")
    if spec.get("enabled", True) is not True or spec.get("disabled", False) is not False:
        raise ValueError(f"Server {name!r} is disabled")
    if bool(spec.get("command")) == bool(spec.get("url")):
        raise ValueError(f"Server {name!r} needs exactly one command or URL")
    transport = spec.get("transport", spec.get("type"))
    common = {"enabled", "disabled", "type", "transport", "tools", "timeout", "connect_timeout"}
    for key in ("timeout", "connect_timeout"):
        if key not in spec:
            continue
        value = spec[key]
        if type(value) not in (float, int) or not math.isfinite(value) or value <= 0:
            raise ValueError(f"{key} for {name!r} must be a positive number of seconds")
    if spec.get("command"):
        if transport not in (None, "stdio") or not isinstance(spec["command"], str):
            raise ValueError(f"Server {name!r} needs a stdio command string")
        if not _string_list(spec.get("args", [])) or not isinstance(spec.get("cwd", ""), str):
            raise ValueError(f"Server {name!r} needs string args and a string cwd")
        allowed = common | {"command", "args", "env", "cwd"}
        env = _mapping(spec.get("env", {}), f"Environment for {name}")
        if not all(isinstance(value, str) for value in env.values()):
            raise ValueError(f"Environment values for {name!r} must be strings")
    else:
        if transport not in (None, "http", "streamable-http", "streamable_http"):
            raise ValueError(f"Server {name!r} needs Streamable HTTP")
        if not isinstance(spec["url"], str):
            raise ValueError(f"Server {name!r} needs a URL string")
        allowed = common | {"url", "headers"}
        headers = _mapping(spec.get("headers", {}), f"Headers for {name}")
        if not all(isinstance(value, str) for value in headers.values()):
            raise ValueError(f"Header values for {name!r} must be strings")
    if spec.keys() - allowed:
        raise ValueError(f"Unsupported settings for {name!r}: {', '.join(sorted(spec.keys() - allowed))}")
    filters = _mapping(spec.get("tools", {}), f"Tool filters for {name}")
    if filters.keys() - {"include", "exclude"} or not all(map(_string_list, filters.values())):
        raise ValueError(f"Tool filters for {name!r} must be include/exclude lists of names")
    return spec


def _fingerprint(spec):
    return hashlib.sha256(json.dumps(spec, sort_keys=True, allow_nan=False).encode()).hexdigest()


def _resolved_server(spec, cwd):
    """Resolve once before pinning or connecting; keep expanded secrets out of workspace files."""
    resolved = dict(spec)
    if "command" in spec:
        resolved["command"] = os.path.expanduser(_expand(spec["command"]))
        resolved["args"] = [_expand(arg) for arg in spec.get("args", [])]
        resolved["env"] = {key: _expand(value) for key, value in spec.get("env", {}).items()}
        resolved["cwd"] = str(Path(cwd) / os.path.expanduser(_expand(spec.get("cwd", ""))))
    else:
        resolved["url"] = _expand(spec["url"])
        resolved["headers"] = {key: _expand(value) for key, value in spec.get("headers", {}).items()}
    return resolved


def _encode_key(key):
    return base64.b64encode(key).decode()


def create_workspace(source: Path, destination: Path, names: list[str], trust_root: Path | None):
    source = source.expanduser().resolve()
    destination = destination.expanduser().resolve()
    servers = _read_servers(source)
    if not names:
        names = [
            name for name, spec in servers.items()
            if _mapping(spec, f"Server {name}").get("enabled", True)
            and not spec.get("disabled", False)
        ]
    if not names:
        raise ValueError("No enabled servers to wrap")
    if set(names) - servers.keys():
        raise ValueError(f"Unknown server(s): {', '.join(sorted(set(names) - servers.keys()))}")
    selected = {name: _fingerprint(_validate_server(name, servers[name])) for name in names}
    cwd = str(Path.cwd())
    resolved = {name: _fingerprint(_resolved_server(servers[name], cwd)) for name in names}
    if trust_root:
        from hermes_tenuo.issuance import read_public_key

        public_key = read_public_key(trust_root)
        issuer = None
    else:
        issuer = SigningKey.generate()
        public_key = issuer.public_key
    destination.mkdir(mode=0o700)
    try:
        if issuer is not None:
            write_private_file(destination / "issuer.key", _encode_key(issuer.secret_key_bytes()))
        write_private_file(destination / "trusted-root.pub", _encode_key(public_key.to_bytes()))
        write_private_file(destination / "workspace.json", json.dumps({
            "source": str(source), "servers": selected, "cwd": cwd, "resolved_servers": resolved,
        }, indent=2))
    except BaseException:
        for name in ("issuer.key", "trusted-root.pub", "workspace.json"):
            (destination / name).unlink(missing_ok=True)
        destination.rmdir()
        raise
    return selected


def load_servers(workspace: Path):
    config = json.loads((workspace / "workspace.json").read_text())
    source = Path(config["source"])
    servers = _read_servers(source)
    selected = {}
    for name, fingerprint in config["servers"].items():
        if name not in servers or _fingerprint(servers[name]) != fingerprint:
            raise ValueError(f"Server {name!r} changed in the source config. Wrap it into a new workspace.")
        spec = _resolved_server(_validate_server(name, servers[name]), config["cwd"])
        if _fingerprint(spec) != config.get("resolved_servers", {}).get(name):
            raise ValueError(f"Resolved settings for {name!r} changed or were not pinned. Wrap it into a new workspace.")
        selected[name] = spec
    return selected


def launch_args(workspace: Path) -> list[str]:
    return ["-m", "hermes_tenuo.cli", "mcp", "serve", str(workspace.resolve())]


def _expand(value: str) -> str:
    def replace(match):
        name = match[1]
        if name not in os.environ:
            raise ValueError(f"Set environment variable {name} before launching the wrapper")
        return os.environ[name]

    return _VARIABLE.sub(replace, value)


@asynccontextmanager
async def connect(transport, *, timeout=60, connect_timeout=60):
    async with transport as streams:
        async with ClientSession(*streams[:2], read_timeout_seconds=max(timeout, connect_timeout)) as session:
            await asyncio.wait_for(session.initialize(), timeout=connect_timeout)
            yield session


@asynccontextmanager
async def connect_wrapper(workspace):
    servers = load_servers(workspace)
    connect_timeout = 10 + sum(spec.get("connect_timeout", 60) for spec in servers.values())
    timeout = 10 + max(spec.get("timeout", 60) for spec in servers.values())
    params = StdioServerParameters(command=sys.executable, args=launch_args(workspace), env=dict(os.environ))
    async with connect(stdio_client(params), timeout=timeout, connect_timeout=connect_timeout) as session:
        yield session


@asynccontextmanager
async def _connect_upstream(spec):
    timeouts = {"timeout": spec.get("timeout", 60), "connect_timeout": spec.get("connect_timeout", 60)}
    if "command" in spec:
        params = StdioServerParameters(
            command=spec["command"],
            args=spec["args"],
            env=spec["env"],
            cwd=spec["cwd"],
        )
        async with connect(stdio_client(params), **timeouts) as session:
            yield session
    else:
        url = spec["url"]
        parsed = urlsplit(url)
        if parsed.username or parsed.password or not (
            parsed.scheme == "https" and parsed.hostname
            or parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        ):
            raise ValueError("MCP URLs require HTTPS or loopback HTTP, with credentials in headers")
        headers = spec["headers"]
        http_timeout = httpx2.Timeout(timeouts["timeout"], connect=timeouts["connect_timeout"])
        async with httpx2.AsyncClient(headers=headers, timeout=http_timeout) as client:
            async with connect(streamable_http_client(url, http_client=client), **timeouts) as session:
                yield session


async def list_tools(session):
    cursor = None
    seen = set()
    while True:
        page = await session.list_tools(params=types.PaginatedRequestParams(cursor=cursor) if cursor else None)
        for tool in page.tools:
            yield tool
        cursor = page.next_cursor
        if not cursor:
            break
        if cursor in seen:
            raise ValueError("MCP tool listing repeated a pagination cursor")
        seen.add(cursor)


@dataclass(frozen=True)
class UpstreamTool:
    server: str
    name: str
    definition: types.Tool
    session: ClientSession
    timeout: float


@asynccontextmanager
async def connect_tools(servers):
    async with AsyncExitStack() as stack:
        routes = {}
        for name, spec in servers.items():
            try:
                session = await stack.enter_async_context(_connect_upstream(spec))
                filters = spec.get("tools", {})
                async for tool in list_tools(session):
                    if ("include" in filters and tool.name not in filters["include"]
                            or tool.name in filters.get("exclude", [])):
                        continue
                    alias = f"{name}__{tool.name}"
                    if len(alias) > 128 or not re.fullmatch(r"[A-Za-z0-9_.-]+", alias):
                        raise ValueError(f"Cannot expose tool {tool.name!r} under server name {name!r}")
                    if alias in routes:
                        raise ValueError(f"Duplicate MCP tool name: {alias}")
                    definition = tool.model_copy(update={"name": alias})
                    routes[alias] = UpstreamTool(name, tool.name, definition, session, spec.get("timeout", 60))
            except ValueError:
                raise
            except Exception as exc:
                raise ValueError(
                    f"Could not discover tools from {name!r} ({type(exc).__name__}). "
                    "Check the original server command, URL and credentials."
                ) from None
        yield routes
