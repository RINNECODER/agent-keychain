---
name: agent-keychain
description: Get and use API keys without seeing them. Use whenever a task needs an API key or token (OpenAI, Anthropic, GitHub, Stripe, Hugging Face, any service), when a command needs a key in an environment variable, or when the user offers to paste a key.
---

# agent-keychain

Keys live in the macOS Keychain. You only ever see their names (`<service>/<key name>`).

## Rules

- Never ask the user to paste a key into the chat, a file or a command. If they offer, point them to `grab_key` instead.
- Never print, echo, log or write out an environment variable that holds a key (`env`, `printenv`, `echo $KEY`, `set -x`, debug dumps). Output is scrubbed, but don't test it.
- Never put a key value into a file, a commit or a URL yourself. Pass it to the process that needs it.
- Never type passwords in the grab window. The user signs in.

## Steps

1. `list_keys`: see if a key already exists.
2. No key: `grab_key(service, name?)`. A window opens on the service's API-key page. The user creates the key, or drives it for them with `page_snapshot`, `page_click(ref)` and `page_type(ref, text)`. The new key is saved straight to the Keychain. If the status is `waiting` or `waiting_for_user_sign_in`, tell the user what to do and call `grab_key` again.
3. Use it: `run_with_secret(command, args, env: {"OPENAI_API_KEY": "openai/<name>"})`. The user approves each run with Touch ID or their password. There is no shell unless you pass `command: "/bin/sh", args: ["-c", "..."]`. Injected values come back as `[secret:<name>]`.
4. `delete_key(name)` when the user asks. It needs their approval too.

CLI equivalents: `agent-keychain list | grab <service> [name] | run -e VAR=<name> -- <cmd> … | delete <name>`.
