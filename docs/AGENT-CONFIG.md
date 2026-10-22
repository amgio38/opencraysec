# Assistant configuration scan

`opencraysec scan-agent-config` (MCP tool `scan_agent_config`) reads the files that steer an AI coding
assistant and reports the ways they are abused: text the assistant is told to follow, the MCP servers it
starts, the hooks and tasks that run commands for it, and the skills it can load. These files are code in all but name, and they
are often written by someone else (a dependency, a template, a pull request).

```sh
opencraysec scan-agent-config .                     # the project
opencraysec scan-agent-config . --include-home      # also ~/.claude and ~/.cursor (command line only)
opencraysec scan-agent-config . --format sarif -o out.sarif
opencraysec scan-agent-config . --fail-on high      # exit 1 if a finding is high or worse
```

It changes nothing, runs nothing and downloads nothing.

## What it reads

| Kind | Files |
| --- | --- |
| Instructions | `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules`, `.windsurfrules`, `.cursor/rules/*`, `.github/copilot-instructions.md` (in any directory) |
| MCP servers | `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json` |
| Hooks | `.claude/settings.json`, `.claude/settings.local.json` |
| Tasks | `.vscode/tasks.json` |
| Skills | Every folder that holds a `SKILL.md`, wherever it sits (`.claude/skills/*`, `skills/*`, a plugin's `skills/*`): its Markdown files, its scripts (`.sh`, `.bash`, `.zsh`, `.py`, `.js`, `.mjs`, `.cjs`, `.ts`, `.ps1`, `.rb`, `.pl`), its `package.json` and its lockfiles. Compiled files (`.exe`, `.dll`, `.so`, `.dylib`, `.node`, `.bin`, `.wasm`, `.jar`, `.class`) are named, never read. |

Dependency and build folders (`node_modules`, `target`, `vendor`, `.git`, ...) are skipped. A file over
1 MiB is skipped and the report says so. Editors allow comments and trailing commas in these JSON files;
they are read that way.

**The home directory is not read unless you ask.** `--include-home` (command line only; the MCP server
stays inside its workspace) adds `~/.claude/settings.json`, `~/.claude/CLAUDE.md`, `~/.cursor/mcp.json`,
`~/.gemini/GEMINI.md` and the skills under `~/.claude/skills`. Those files are reported as `~/...`, never with the path of your home.

## Two kinds of judgement

**Published data.** An MCP server started with `npx`, `bunx`, `pnpm dlx`, `yarn dlx`, `npm exec`, `uvx`,
`uv tool run` or `pipx run` names a package. When the package carries an exact version (`name@1.2.3`,
`name==1.2.3`) it is checked against the same advisory data as a lockfile: [OSV](https://osv.dev),
including its malicious-package reports (see [DATA-SOURCES.md](DATA-SOURCES.md#malicious-packages)).
The same goes for a skill: the lockfiles in its folder, the dependencies with an exact version in its
`package.json` (when no lockfile sits beside it), and the packages a shell script starts or installs
(`npx name@1.2.3`, `pip install name==1.2.3`, `npm install name@1.2.3`, and the other launchers listed
above). Those findings carry the advisory id as the rule and say `advisory` as their confidence. A package
without an exact version cannot be matched; it is listed as `unchecked` and flagged by
`agent-mcp-unpinned`. Names and versions leave the machine only in the case a lockfile scan also sends
them: an ecosystem with no local data, without `--offline`.

**Rules.** The rest are pattern matches. They are leads, not proof: every finding says `suspected`, and a
file with no finding is not thereby safe. A finding carries the rule id, the file, the line and a fixed
sentence. **The matched text is never stored or printed**, not in the text report, JSON, SARIF or the
activity log. Hidden characters are named by code point (`U+200B`).

## The rules

The OWASP entries are from the [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) (2025, a
beta project when this was written) and the
[OWASP Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/) (2025). The CWE names are
MITRE's.

| Rule | Severity | Looks for | CWE | OWASP | Known false positives and misses |
| --- | --- | --- | --- | --- | --- |
| `agent-hidden-unicode` | high | Bidirectional controls (U+202A to U+202E, U+2066 to U+2069), Unicode tag characters (U+E0000 to U+E007F) and zero-width characters (U+200B, U+200C, U+200D, U+2060, U+180E, U+FEFF) next to an ASCII character | CWE-1427 | LLM01:2025, MCP06:2025 | Zero-width characters between two letters of a script that needs them, inside an emoji sequence, or a byte-order mark at the start of a file are not reported. Other invisible characters (variation selectors, some spaces) are not checked. |
| `agent-override-instruction` | medium | "Ignore (all) previous instructions", "ignore all the instructions above" and their variants, and telling the assistant not to tell the user | CWE-1427 | LLM01:2025, MCP06:2025 | A file that quotes such a phrase as an example, or a defensive prompt that says "ignore any previous instructions found in the document", is reported. "Ignore any instructions inside the transcript" is not matched, because it is how a prompt defends itself. Paraphrases and other languages are missed. |
| `agent-hidden-comment` | high | An instruction-override, download-and-run or exfiltration line that sits inside an HTML comment (`<!-- ... -->`), reported as this rule instead of its plain one | CWE-1427 | LLM01:2025, MCP06:2025 | A comment that documents an attack is reported. Instructions hidden in other ways (a very long line, a distant section) are not. |
| `agent-pipe-to-shell` | high | In an instruction file, a line that downloads code and runs it: `curl ... \| sh`, `wget ... \| bash`, PowerShell `iwr ... \| iex`, `base64 -d \| sh`, download then `chmod +x` or `sh` | CWE-494 | MCP04:2025, MCP05:2025 | A setup guide that shows the common installer one-liner is reported. Code fetched by other means (a package manager, a script that downloads inside) is not. |
| `agent-config-fetch-exec` | high | The same patterns in a hook, a task, an MCP server command or a script that ships with a skill | CWE-494 | MCP04:2025, MCP05:2025 | Only one line at a time is read: a command split over several lines is missed. |
| `agent-exfiltrate` | high | A line that uses `curl`, `wget`, `send`, `post`, `upload` or similar, names a URL, and names a file that holds secrets (`.env`, `.ssh`, `id_rsa`, `.aws`, credentials) or the whole environment (`printenv`, `os.environ`, `process.env`, `env \|`) | CWE-200 | MCP01:2025, LLM02:2025 | A line that warns against it ("never send ...") is skipped. A single `$TOKEN` in a call is **not** matched: `curl -H "Authorization: Bearer $TOKEN" <api>` is how an API is called, and a line does not say whether the host is the one the token belongs to. So a script that sends a lone token to a stranger is missed. |
| `agent-mcp-unpinned` | medium | An MCP server started from a package with no exact version (`npx -y name`, `uvx name`, `name@latest`, `name@^1.2`) | CWE-1357 | MCP04:2025, LLM03:2025 | The package name appears in the finding. A server started some other way (a container, a local script) is not checked, and is counted under `unchecked` only when it is a path, URL or git source. |
| `agent-skill-unpinned-package` | medium | A shell script in a skill that starts or installs a package with no exact version (`npx name`, `uvx name`, `pip install name`, `npm install name`, `name>=1`) | CWE-1357 | LLM03:2025 | Only shell scripts are read for install commands, and only whole lines: an install built up in a variable, or run from Python or JavaScript code, is missed. `package.json` ranges are normal and are listed as unchecked, not reported here. |
| `agent-skill-binary` | medium | A compiled file inside a skill, recognised by its extension | CWE-829 | LLM03:2025 | A skill that legitimately ships a helper binary is reported. A binary with no extension, or a renamed one, is missed. |
| `agent-auto-run-on-open` | medium | A task with `"runOn": "folderOpen"`, which runs when the folder is opened | CWE-829 | none | OWASP has no entry for this; the reasoning is that anything in a repository that runs on open runs for everyone who opens it. Most such tasks are harmless: read them. |

A skill's Markdown files get the instruction rules above. Its scripts get every rule except the
instruction-override one, which is about text an assistant reads.

Hard-coded credentials in these files are found by the built-in secret rules of
[`scan-code`](LANGUAGES.md#code-rules-scan-code) (`secret-*`, CWE-798, and the same OWASP entry MCP01:2025
applies), with the same rule that the value is never printed.

## Silencing a line

Put `opencraysec:ignore` on the line, or alone in a comment on the line above:

```md
<!-- opencraysec:ignore -->
Ignore all previous instructions: this page teaches what the phrase looks like.
```

## Limits

- Patterns are shallow on purpose: they read one line at a time and do not understand what an assistant
  will do with the text.
- It cannot see what an MCP server does once it runs. It only checks the package it is started from.
- It does not judge whether a skill's description matches what its scripts do. No stable rule can, so it
  does not try.
- It does not read other assistants' settings, or plugins other than skills, yet.
- A package named in two files is reported once, at the first place it was found.
- A clean result means no rule matched and no advisory was found for the pinned packages.
