# /// script
# requires-python = ">=3.10"
# dependencies = ["tenuo[mcp,fastmcp]==0.3.8", "httpx"]
# ///
"""A guest client that skips its own check, to show the server refuses on its own.

  python bypass.py GUEST_HOME TOOL '{"arg": "value"}' signed|none [WARRANT_B64_FILE]

"signed" signs the call with the guest's key and its current warrant (or the
warrant in WARRANT_B64_FILE, for replaying an old one). "none" sends no warrant.
"""

import asyncio
import json
import sys
import time
from pathlib import Path

import httpx
from fastmcp import Client
from tenuo import SigningKey, Warrant
from tenuo_core import sign_meta

from common import unb64


async def main(home: Path, tool: str, args: dict, mode: str, warrant_file: str | None) -> None:
    state = json.loads((home / "server.json").read_text())
    meta = None
    if mode == "signed":
        if warrant_file:
            text = Path(warrant_file).read_text().strip()
        else:
            text = httpx.get(state["server"] + "/tenuo/warrant", params={"holder": state["holder"]}).json()["warrant"]
        key = SigningKey.from_bytes(unb64((home / "key").read_text().strip()))
        warrant = Warrant.from_base64(text)
        meta = {"tenuo": sign_meta([warrant], key, tool, json.dumps(args), int(time.time()), None)}
    async with Client(state["server"] + "/mcp") as client:
        result = await client.call_tool(tool, args, meta=meta, raise_on_error=False)
        text = result.content[0].text if result.content else ""
        print("SERVER REFUSED" if result.is_error else "RAN", "|", text.splitlines()[0][:150] if text else "")


if __name__ == "__main__":
    a = sys.argv[1:]
    asyncio.run(main(Path(a[0]), a[1], json.loads(a[2]), a[3], a[4] if len(a) > 4 else None))
