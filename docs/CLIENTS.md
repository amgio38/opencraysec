# Connecting an AI assistant

`opencraysec mcp` speaks the Model Context Protocol over stdio. Any MCP client can launch it. It
exposes read-only checks (`scan_dependencies`, `scan_code`, `scan_agent_config`, `scan_runtime`, `explain_advisory`,
`plan_fix`, `verify_fix`), `record_fix` (writes to the activity log only) and `update_db`. See
[TOOLS.md](TOOLS.md) for every tool.

The server **never edits your project**. It tells the assistant what to run; the assistant (with
your approval) runs it.

## Which directory may it scan?

`--workspace DIR` (default: the directory the client starts it in) is the only place the tools may
read. A path that resolves outside it, by `..` or by a symlink, is refused. Point it at the project
you are working on.

## Claude Code

```sh
claude mcp add opencraysec -- opencraysec mcp                       # the project you start Claude Code in
claude mcp add opencraysec -- opencraysec mcp --workspace "$HOME/work/app"
```

Install the bundled [Agent Skill](../skills/opencraysec/SKILL.md) so the assistant knows the
workflow (scan, explain, plan, fix, verify, record):

```sh
cp -r skills/opencraysec ~/.claude/skills/        # every project
cp -r skills/opencraysec .claude/skills/          # this project only
```

## Cursor

`.cursor/mcp.json` in the project (or `~/.cursor/mcp.json` for every project):

```json
{
  "mcpServers": {
    "opencraysec": { "command": "opencraysec", "args": ["mcp"] }
  }
}
```

## opencode

`opencode.json`:

```json
{
  "mcp": {
    "opencraysec": { "type": "local", "command": ["opencraysec", "mcp"], "enabled": true }
  }
}
```

## Codex

`~/.codex/config.toml`:

```toml
[mcp_servers.opencraysec]
command = "opencraysec"
args = ["mcp"]
```

## Any other client

Command `opencraysec`, arguments `["mcp"]`, transport stdio. Useful flags:

| Flag | Effect |
| --- | --- |
| `--workspace DIR` | The only directory the tools may scan. |
| `--offline` | No network at all: `update_db` is disabled, and ecosystems without local data are reported as not scanned. |
| `--no-log` | Do not write the activity log (the dashboard will have nothing to show). |
| `--data-dir DIR` | Where advisory data and the log live. |

## Check that it works

```sh
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | opencraysec mcp
```

The first line of the reply carries `serverInfo` and instructions for the model; the second lists
the tools. Nothing but protocol messages is ever written to standard output.

## Seeing what the assistant did

Every scan, plan, verification and recorded fix is logged locally. `opencraysec dashboard` shows
it as charts and lists; see [DASHBOARD.md](DASHBOARD.md).
