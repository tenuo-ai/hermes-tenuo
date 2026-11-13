"""A disposable MCP server with one tool, write(value), that records each value it receives."""
import asyncio
import sys

from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

EFFECTS = sys.argv[1] if len(sys.argv) > 1 else "/lab/mcp_effects.txt"


async def list_tools(_context, _params):
    return types.ListToolsResult(tools=[types.Tool(name="write", description="Record a value.", input_schema={
        "type": "object", "properties": {"value": {"type": "string"}}, "required": ["value"],
        "additionalProperties": False})])


async def call_tool(_context, params):
    with open(EFFECTS, "a") as fh:
        fh.write(params.arguments["value"] + "\n")
    return types.CallToolResult(content=[types.TextContent(type="text", text="recorded " + params.arguments["value"])])


async def main():
    server = Server("first", on_list_tools=list_tools, on_call_tool=call_tool)
    async with stdio_server() as (reader, writer):
        await server.run(reader, writer, server.create_initialization_options())


asyncio.run(main())
