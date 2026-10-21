# Reply to a thread

Most people stop at drafts: the agent writes the reply, a person presses send.
This lets Hermes send the reply itself, on one thread, to one address, within
the hour.

What Hermes and Google already do: an OAuth scope can make Gmail read-only or
drafts-only, and Hermes can drop the send tool by name. Once send is allowed,
`gmail.send` reaches anyone, on any thread, until you revoke it. What the
warrant adds: the thread and the recipient, checked on every send, for an hour.

[`warrant.yaml`](warrant.yaml): read the thread, and `send_gmail_message` with
`thread_id` and `to` pinned, for Google Workspace MCP (`workspace-mcp`)
configured in Hermes as `google_workspace`. Arguments it doesn't list (`cc`,
`bcc`, `forward_message_id`, `attachments`, `reply_all`, `quote_original`) are
refused.

## Set it up

```yaml
mcp_servers:
  google_workspace:
    command: uvx
    args: [workspace-mcp, --tools, gmail]
```

Per thread, edit your address, the thread ID (from the Gmail URL or
`search_gmail_messages`) and the recipient, then:

```bash
tenuo-cli warrant issue --template warrant.yaml --holder agent --out reply.warrant
hermes-tenuo session attach --session telegram:<your user ID> --file reply.warrant
```

## What it allows and refuses

| Call | Result |
|------|--------|
| `get_gmail_thread_content` for the thread | allowed |
| `send_gmail_message` to bob@vendor.com on the thread | allowed |
| … to someone@else.com | refused: Constraint 'to' not satisfied |
| … with `bcc` or `forward_message_id` | refused: unknown field not allowed |
| … on another thread | refused: Constraint 'thread_id' not satisfied |
| `search_gmail_messages` | refused: not authorized |

## Limits

- `to` is matched exactly, so write it in lowercase as the model will. To answer
  several people, list them (`to: [bob@vendor.com, alice@yourco.com]`): each send
  may go to one of them.
- The warrant decides where a message goes, not what it says: if Bob asks for
  something from earlier in the thread, the model may include it.
