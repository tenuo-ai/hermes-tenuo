# Experiment: give someone else's agent access to your MCP server

An experiment, not a supported feature. It tests whether an owner can give another
person's agent scoped, expiring access to an MCP server, with one link and no key handling
on either side, using only released Tenuo (0.3.8).

## The journey

1. **The owner shares.** `owner.py share Alex calendar.read --hours 2 --server URL` prints
   one command to send Alex. The link carries the server address and a one-time code.
2. **Alex runs it.** `accept.py 'URL/#HG-XXXX-XXXX'` creates a key on Alex's machine and
   sends only the public key. It then waits, saying what it's waiting for.
3. **The owner approves one card**, which names the person, their agent, the key
   fingerprint, the access and how long it lasts. Only then is a warrant signed, to Alex's
   public key.
4. **Alex's client picks up the warrant** from the same server, and pins the owner's
   public key.
5. **Every call carries the chain** in MCP `params._meta.tenuo`. The server verifies it
   against the owner's key before the tool runs.
6. **The owner changes or ends access.** A change signs a new warrant to the same key
   and revokes the old one. Alex's client picks it up before its next call. Ending
   revokes the warrant, and the next call is refused.

## Run it

You need [uv](https://docs.astral.sh/uv/getting-started/installation/) on both machines.
It installs each script's dependencies on first run, so there's no virtualenv to set up.

### On two machines

**Owner**, on the machine that runs the server:

```bash
git clone https://github.com/tenuo-ai/hermes-tenuo.git
cd hermes-tenuo/experiments/agent-access
uv run owner.py --home ~/calendar-owner share Alex calendar.read --hours 2 \
  --server http://ADDRESS:8765          # an address Alex's machine can reach
uv run server.py --home ~/calendar-owner --host 0.0.0.0
```

`share` prints the one command to send Alex. In a second terminal, wait for Alex and approve:

```bash
uv run owner.py --home ~/calendar-owner approve --wait 600
```

**Alex**, on any machine with uv, runs the command they were sent. Nothing to clone:

```bash
uv run https://raw.githubusercontent.com/…/accept.py 'http://ADDRESS:8765/#HG-XXXX-XXXX' --as Alex
uv run https://raw.githubusercontent.com/…/accept.py --call list_events day=2026-11-27
```

The owner changes or ends access with `owner.py change KEY --scope calendar.write --hours 4`
and `owner.py end KEY`, where KEY is the fingerprint shown on the card and by `owner.py list`.

### On one machine, with every check

```bash
./journey.sh
```

## How it's built

- `owner.py` holds the issuer key in `OWNER/private`. Everything the server needs is in
  `OWNER/public`: the issuer public key, invitations, pairings and a signed revocation list.
- `server.py` is a FastMCP calendar with `TenuoMiddleware` and two HTTP routes next to
  `/mcp`: `POST /tenuo/pair` and `GET /tenuo/warrant`. It can't sign access, and it
  re-reads the revocation list when the file changes.
- `accept.py` is the guest's client: it pairs, then calls tools through `SecureMCPClient`
  with the picked-up warrant and its own key.

## What we learned

- **The guest needs the owner's public key,** because the client checks each call locally
  before signing. The server returns it at pickup, and the client pins it then. Putting
  the owner's key fingerprint in the link would let the client check it on first contact.
- **Pairing must run over TLS or a private network.** Pairing binds the guest's public
  key, so an attacker on the path could substitute their own. The card shows the
  fingerprint so the owner and guest can compare.
- **Pairing is an HTTP route, not an MCP tool,** so a model can't be talked into calling it.
  Codes are single-use, expire after a day and are rate-limited.
- **Revocation stays in the owner's domain,** because the server that checks calls belongs
  to the owner.
- **Refusals need plain words.** The server's reason ("Tool 'add_event' is not
  authorized") should become "Your access is read-only. Ask the owner for more?"

## Limits

- The guest's client is a script. Agents such as Claude Code or Hermes need a client that
  adds the chain to their MCP calls.
- Approval is a terminal prompt. State is kept in JSON files without locking, and plain
  HTTP is used locally.
