# codex-claudecode-proxy

A local proxy installer CLI that translates the OpenAI OAuth API into a Claude-compatible API.

## One-Liner

```bash
npx -y codex-claudecode-proxy
```

## Requirements

- macOS only (for now)
- Claude Code is installed
- You are logged in to Codex CLI

## Commands

```bash
# Install (safe to re-run)
npx -y codex-claudecode-proxy

# Status
npx -y codex-claudecode-proxy status

# Start/stop manually
npx -y codex-claudecode-proxy start
npx -y codex-claudecode-proxy stop

# Uninstall: stop background services and restore Claude Code settings
npx -y codex-claudecode-proxy uninstall

# Purge: uninstall + remove installed files
npx -y codex-claudecode-proxy purge
```

## Integrity / Safety

- Claude Code settings are configured automatically, and a backup is created before changes.
- Running `uninstall` removes the proxy-related Claude settings and restores the original behavior.

## License

MIT
