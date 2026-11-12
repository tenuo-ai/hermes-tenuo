"""What the server plugin and the device agree on: names, encodings and the warrants.

The device (your laptop) is the authority. It signs a warrant that lets one server run
commands in one folder until a deadline, held by that server's key. The server signs every
command with that key; the device checks the signature, the folder and the deadline offline
before running anything.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import socket
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


MAX_TEXT = 24 * 1024 * 1024  # room for one piece of text inside a message, as it is sent
REPORT_GRACE = 120  # seconds after its time window in which a device may still report a result


def sent_size(text: str) -> int:
    """How many bytes `text` takes inside a message. Some characters take six."""
    return len(json.dumps(text))


def fit(text: str) -> str:
    """`text`, cut if needed so that the message carrying it is never too big to deliver."""
    size = sent_size(text)
    if size <= MAX_TEXT:
        return text
    while size > MAX_TEXT:
        text = text[: max(0, int(len(text) * MAX_TEXT / size * 0.95))]
        size = sent_size(text)
    return text + "\nhands: output cut to fit one message\n"


_SHARED = ipaddress.ip_network("100.64.0.0/10")  # carrier-grade NAT space, which Tailscale uses


def private_host(host: str) -> bool:
    """True if `host` is this machine or on a private network: every address it has is a
    loopback, private, link-local or shared-space one. Commands and results are signed but
    not encrypted, so a plain connection is only for such a network. A name that cannot be
    looked up here is not private: something else (a proxy) may still reach it."""
    host = host.strip("[]")
    try:
        found = {info[4][0].split("%")[0] for info in socket.getaddrinfo(host, None)}
    except (OSError, UnicodeError):
        return False
    for text in found:
        try:
            address = ipaddress.ip_address(text)
        except ValueError:
            return False
        mapped = getattr(address, "ipv4_mapped", None)
        address = mapped or address
        if not (address.is_loopback or address.is_private or address.is_link_local
                or (address.version == 4 and address in _SHARED)):
            return False
    return bool(found)


def _through_proxy(authority: str) -> bool:
    """True if this machine would send a plain request for `authority` through an HTTP proxy,
    which then sees it whatever network the host is on. `authority` is the host as the URL
    writes it, with its port and an IPv6 address's brackets: the form the proxy rules of
    the request itself are matched against."""
    import urllib.request
    try:
        return bool(urllib.request.getproxies().get("http")) and not urllib.request.proxy_bypass(authority)
    except Exception:
        return True


def plain_and_public(url: str) -> bool:
    """True for an address that would carry commands unencrypted across the internet."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    return parts.scheme == "http" and (not private_host(host) or _through_proxy(parts.netloc))


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
            .capability(TOOL_POLL, nonce=Wildcard(), op=Wildcard())
            .capability(TOOL_RESULT, job=Wildcard(), digest=Wildcard()).mint(device_key))


def request(op: str, nonce: str) -> Dict[str, str]:
    """What a device signs for one request: which operation it is, and a value used once.
    A signature made for one operation is no use for another."""
    return {"nonce": nonce, "op": op}


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
