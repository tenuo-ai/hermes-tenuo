# Reply to a thread

Most people stop at drafts: the agent writes the reply, a person presses send.
This lets Hermes send the reply itself, for one thread, to one address, within
the hour. `gmail.send` would let it write to anyone about anything until you
revoke it; read-only and drafts-only you can already get from OAuth scopes.

[`warrant.yaml`](warrant.yaml) uses Google Workspace MCP (`workspace-mcp`)
configured in Hermes as `google_workspace`: read the thread and
`send_gmail_message` with `thread_id` and `to` pinned. Arguments it doesn't list
(`cc`, `bcc`, `forward_message_id`, `attachments`, `reply_all`) are refused.

## Set it up

```yaml
mcp_servers:
  google_workspace:
    command: uvx
    args: [workspace-mcp, --tools, gmail]
```

Per thread, edit your address, the thread ID and the recipient, then issue and
attach as in the other recipes.

## What it allows and refuses

| Call | Result |
|------|--------|
| `get_gmail_thread_content` for the thread | allowed |
| `send_gmail_message` to bob@vendor.com on the thread | allowed |
| … to someone@else.com | refused: Constraint 'to' not satisfied |
| … with `bcc` | refused: 'bcc' unknown field not allowed |
| … on another thread, or with no thread | refused: Constraint 'thread_id' not satisfied |
| `search_gmail_messages` | refused: not authorized |

## Limits

`to` is one address. To answer several people, list them
(`to: [bob@vendor.com, alice@yourco.com]`): each call may go to one of them.
The warrant doesn't read the message; it decides where it can go.
