# Your first Hands session

Keep your existing Hermes on its server, with its memory and skills. Give one conversation access to one folder on your laptop. This walkthrough uses a disposable project, needs Python 3 and no model-specific configuration, and should take about five minutes once the server listener is reachable.

Supported devices: macOS with sandbox-exec, or Linux with working bubblewrap. Native Windows and GUI/browser control are not supported. A Linux share with internet access additionally needs enabled Landlock ABI 6; the offline practice project does not need it.

## 1. Install and enable on the server

In the Hermes environment/profile serving your chat:

```sh
hermes plugins install tenuo-ai/hermes-tenuo --ref v0.4.0
hermes plugins enable hermes-tenuo
```

Leave the optional credential prompts empty for Hands. Restart that Hermes gateway/profile after installation. `/hands setup` is available even before its listener is configured.

Hands requires hermes-tenuo 0.4.0 or newer on both the server and laptop.

## 2. Connect your server and laptop

For a first session, use **Tailscale** to connect the two machines privately.
You do not need a public domain, a reverse proxy, or an incoming port on your laptop.
If you already have an HTTPS endpoint for Hands, use the alternative below.

1. [Install Tailscale](https://tailscale.com/download) on the server and laptop,
   sign both into the same tailnet, and keep Tailscale connected on both.
2. On the **server**, run `tailscale ip -4` and copy its address.
3. In the **server's Hermes config** (`~/.hermes/config.yaml`, or the config for
   the profile serving your chat), merge the following into your existing
   `plugins` settings. Replace both occurrences of `100.64.0.10` with the
   server address you just copied; preserve your other plugin settings:

```yaml
plugins:
  entries:
    hermes-tenuo:
      hands:
        listen: "100.64.0.10:8765"
        url: "http://100.64.0.10:8765"
```

4. Restart that Hermes gateway/profile. In your **Hermes chat**, run `/hands setup`.
   It should now offer the read/edit/online choices.
5. On the **laptop**, confirm the server is reachable with
   `tailscale ping 100.64.0.10`, using your server's address.
   Your tailnet policy and the server firewall must allow the laptop to reach
   TCP port 8765 on the Tailscale interface. There is no need to expose it on
   the server's public interface.

The `http://` address here travels over your private Tailscale network. This is
Hands' own listener, not the Hermes Desktop gateway port. A successful Tailscale
ping checks the network path; the Hands preflight in the next steps checks the
actual service. See Tailscale's [connection guide](https://tailscale.com/docs/how-to/connect-to-devices)
if the machines cannot reach each other.

<details>
<summary>Already have an HTTPS reverse proxy?</summary>

Use a dedicated Hands URL, forward it to this loopback listener, and restart
Hermes after merging the configuration:

```yaml
plugins:
  entries:
    hermes-tenuo:
      hands:
        listen: "127.0.0.1:8765"
        url: "https://hands.example.com"
```

Replace `https://hands.example.com` with your actual HTTPS endpoint. The proxy
must reach port 8765 in the same network namespace as Hermes and support the
Hands client's long-poll requests. Run `/hands setup` after restarting Hermes.

</details>

The laptop connects outward. Keep it awake and its sharing terminal open for
the session. If Hermes runs in a container, the private listener address must
be available inside that container; otherwise use the HTTPS proxy route.

## 3. Create a practice folder on the laptop

Install [uv](https://docs.astral.sh/uv/getting-started/installation/) if `uvx` is not available, then run:

```sh
uvx --refresh hermes-tenuo --version
uvx hermes-tenuo hands demo
```

The version command refreshes any older cached CLI; check that it reports 0.4.0 or newer.
The demo prints a new temporary folder and a `cd` command. Run that command locally. Nothing has been paired yet and no existing project was changed.

## 4. Choose permissions and connect

In the originating Hermes chat, run `/hands setup edit`. Copy its generated command into the laptop terminal in the practice folder. It shares this folder for one hour and runs automatic preflight before pairing.

The other choices are `/hands setup read` (no project writes) and `/hands setup online` (writes plus internet/network access). Offline edit is sufficient for this demo. Online access is not restricted to package downloads.

When the laptop says Hands is up, run `/hands verify` in the originating chat. You should see the machine, folder, read/write mode, internet off, remaining time, and the verified folder path. This read-only probe uses the signed Hands execution path. Push notifications are not available on every Hermes surface, so verification is explicit.

## 5. Complete one useful task

Ask Hermes:

> Run `python3 -m unittest -v` in the shared folder. Fix the invoice calculation in invoice.py without changing the tests, then rerun the tests.

Inspect `invoice.py` locally and run the tests yourself. No package installation or internet access is needed. Memory and skills remain on the server. Browser and MCP tools have not moved to the laptop.

## 6. End access

Press Ctrl-C in the laptop's sharing terminal. Its commands and background processes stop; file edits remain. `/hands status` should show the device as not answering. `/hands off` sends the conversation back to the server. **Using `/hands off` alone does not end the laptop grant.** For a whole profile with `terminal.backend: hands`, change the profile's terminal backend to return to the server; `/hands off` cannot switch it. Delete the practice folder when done.

The laptop prints a reconnect command that preserves your choices and the original `TENUO_HANDS_HOME` identity directory and configured `SSL_CERT_FILE` CA path (made absolute at startup), and excludes the consumed invite. Running it locally grants a new time window. After revocation, request a new invite instead.

## When something goes wrong

| What you see | What to do |
|---|---|
| `/hands` is unknown | Enable the plugin and restart the gateway/profile serving this chat; check its version includes Hands. |
| Hands is off | Follow `/hands setup`; no laptop connection is possible until the server listener is configured. |
| Cannot reach server / wrong service | Check `hands.url`, the proxy route, port and private-network connection. Run `hands check` locally. |
| No sandbox | Follow `hands check` diagnostics. On Ubuntu, see the bubblewrap setup in the [reference](reference.md). The demo does not need `--no-sandbox`. |
| Invite expired or already used | Generate a new invite; do not repeatedly reuse the old one. |
| Install/download fails | Internet is off in read/edit shares. Choose online only if you want that access, then restart locally. |
| Device disconnected or expired | Inspect the laptop terminal and use its reconnect command. No silent server fallback occurs. |
| Outcome unknown | Check the device and files before retrying; a lost reply does not mean a command failed. |

## Preview and keep private files out

Before running the generated `hands up` command, append `--preview` to inspect
its permissions locally. Remove `--preview` to connect. Preview does not consume
the invite or test the server connection.

Personal exclusions live in `~/.config/hermes-tenuo/never-share`, one existing
literal path per line, relative to the shared folder or absolute. For example,
`customers/` keeps that directory's contents out of terminal and file operations.
Missing paths are errors; globs are not supported. Restart Hands to apply rule
changes. See the [reference](reference.md) for platform behavior and path-alias limitations.

Recognized secrets in results and command logs are redacted locally. A result
says when redaction occurred; it does not modify project files. Detection is
best effort, so exclude material you must not send to Hermes or its model.
