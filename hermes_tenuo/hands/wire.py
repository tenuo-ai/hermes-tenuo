"""What the server plugin and the device agree on: names, encodings and the warrants.

The device (your laptop) is the authority. It signs a warrant that lets one server run
commands in one folder until a deadline, held by that server's key. The server signs every
command with that key; the device checks the signature, the folder and the deadline offline
before running anything.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

API = "/hands/v1"
TOOL = "hands"              # the server's capability: run a command in a folder
TOOL_POLL = "hands_poll"    # the device's own capabilities, to sign what it sends
TOOL_RESULT = "hands_result"
POLL_SECONDS = 25
MAX_BODY = 32 * 1024 * 1024


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def unb64(text: str) -> bytes:
    s = text.strip()
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def digest(*parts: Any) -> str:
    """One hash over the parts of a message, so a signature covers all of them."""
    blob = json.dumps(parts, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(blob.encode()).hexdigest()


def public_key(text: str):
    from tenuo import PublicKey
    return PublicKey.from_bytes(unb64(text))


def key_text(key: Any) -> str:
    return b64(bytes(key.to_bytes()))


def same_key(a: Any, b: Any) -> bool:
    return bytes(a.to_bytes()) == bytes(b.to_bytes())


@dataclass
class Invite:
    """`hands://host:port/<secret>#<server key>`: where to connect, and to whom."""

    url: str
    secret: str
    server_key: str

    @classmethod
    def parse(cls, text: str) -> "Invite":
        parts = urlsplit(text.strip())
        scheme = {"hands": "http", "hands+https": "https"}.get(parts.scheme)
        secret = parts.path.strip("/")
        if not scheme or not parts.netloc or not secret or not parts.fragment:
            raise ValueError("not a Hands invite (expected hands://host:port/<secret>#<key>)")
        try:
            public_key(parts.fragment)  # refuse a malformed key now, not at the first command
        except Exception as e:
            raise ValueError("this Hands invite is damaged: copy the whole line from `/hands invite`") from e
        return cls(f"{scheme}://{parts.netloc}", secret, parts.fragment)

    def render(self) -> str:
        parts = urlsplit(self.url)
        scheme = "hands+https" if parts.scheme == "https" else "hands"
        return f"{scheme}://{parts.netloc}/{self.secret}#{self.server_key}"


def mint_grant(device_key: Any, server_key: Any, folder: str, ttl_seconds: int):
    """The device's grant to the server: any command, in `folder`, until the deadline."""
    from tenuo import Subpath, Warrant, Wildcard
    return (Warrant.mint_builder().holder(server_key).ttl(ttl_seconds)
            .capability(TOOL, dir=Subpath(folder), cmd=Wildcard()).mint(device_key))


def mint_identity(device_key: Any, ttl_seconds: int):
    """A warrant the device holds itself, so the server can check what the device sends."""
    from tenuo import Warrant, Wildcard
    return (Warrant.mint_builder().holder(device_key.public_key).ttl(ttl_seconds)
            .capability(TOOL_POLL, nonce=Wildcard())
            .capability(TOOL_RESULT, job=Wildcard(), digest=Wildcard()).mint(device_key))


def sign(warrant: Any, key: Any, tool: str, args: Dict[str, str], now: Optional[int] = None) -> str:
    return b64(bytes(warrant.sign(key, tool, args, int(now if now is not None else time.time()))))


def check(chain: List[Any], trusted: Any, tool: str, args: Dict[str, str], signature: str) -> None:
    """Raise unless `chain` starts at `trusted`, allows the call, and its holder signed it."""
    from tenuo import Authorizer
    Authorizer(trusted_roots=[trusted]).check_chain(chain, tool, args, signature=unb64(signature))


def load_chain(items: List[str]):
    from tenuo import Warrant
    if not items or len(items) > 8:
        raise ValueError("a command must carry between one and eight warrants")
    return [Warrant.from_base64(item) for item in items]
