# Security

opencraysec reads your project's lockfiles and source, downloads public vulnerability data, and can
serve a report of what it found. This page describes what it protects and what it does not.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.** Report it privately through GitHub's
private vulnerability reporting for [`amgio38/opencraysec`](https://github.com/amgio38/opencraysec)
(Security tab, *Report a vulnerability*). Include what you ran, what you expected, what happened, and a
minimal reproduction if you can.

We aim to acknowledge a report within 7 days and to tell you our assessment and plan within 14 days. We
will credit you in the advisory unless you prefer not to be named.

Reports we especially want:

- a tool path that escapes `--workspace`;
- a lockfile or archive that makes a parser misbehave (crash, huge allocation, wrong package);
- a way to make opencraysec modify your project (it is designed never to);
- a dataset download that is not checked well enough, or any way for data to leave the machine other than
  the documented requests;
- a way to read the dashboard without its token, to make it write anything, or to inject script into the
  page;
- anything in the installer or the release archive that lets an unverified or malformed asset reach
  `bin/`.

Enabling private vulnerability reporting is a one-time maintainer action after the first public push
(see [docs/RELEASING.md](docs/RELEASING.md)); until then, contact the maintainers through the repository.

## Trust model

Everything runs as **your user**. opencraysec trusts the processes that run as you and the MCP client
that launched it. It is not a sandbox against a hostile program running as your user.

- **It never edits your project.** `plan_fix` prints commands; `record_fix` appends to the activity log.
  The only files it writes are under its own data directory (the advisory cache, the log, snapshots, and
  scratch space for external scanner reports).
- **Workspace boundary.** Every path a tool is asked about is resolved with `canonicalize` (which follows
  symlinks) and must land inside `--workspace`; otherwise the tool answers that it is outside the
  workspace. Lockfile and source discovery do not follow symlinks.
- **No code execution.** Parsers read text. opencraysec does not run package managers, build scripts or
  your code. External scanners (`gitleaks`, `semgrep`) run only when you ask for them, with fixed
  arguments and the path confined to the workspace.
- **Bounded inputs.** Lockfiles (64 MiB), source files (1 MiB), MCP messages (4 MiB), downloads (2 GiB)
  and the number of files read all have limits.
- **Secrets.** Secret-like findings never include the matched value, in any output or in the log.

## What leaves your machine

Only what [docs/CONFIGURATION.md](docs/CONFIGURATION.md#network-use) lists: dataset downloads, package
names and versions to `api.osv.dev` when an ecosystem has no local data (unless `--offline`), and CVE ids
to NVD with `--enrich-nvd`. Never source code. `--offline` forbids all of it.

## Downloads

Datasets come over HTTPS from the publishers (OSV, CISA, FIRST, MITRE, NVD). Release archives are
installed only after their SHA-256 matches, are limited to the program and its licence files, and the
installer refuses path traversal and symlinked licence files. Build the binary yourself if you need to
verify it independently; `make release-static` reproduces the release build.

## The dashboard

`opencraysec dashboard` is **read-only** but exposes your vulnerability list. It listens on every network
interface by default (`0.0.0.0:1787`) and prints a warning when it does. Use `--host 127.0.0.1` to keep it
local or `--token` to require a secret (compared in constant time). It has no TLS: put it behind a
reverse proxy beyond a trusted network. It serves only `GET`, bounds request size and connections, inserts
all third-party text with `textContent`, and sends a restrictive Content-Security-Policy, `nosniff`,
`no-referrer`, `X-Frame-Options: DENY` and `no-store`. Chart.js is loaded from a CDN at a pinned version
with an integrity hash (the page falls back to tables).

## Untrusted repositories

Scanning a repository you do not trust is safe in the sense that nothing in it is executed, but its
lockfile and sources are parsed and a crafted file could try to exhaust resources; the limits above bound
that. Do not point an external scanner's config at rules you do not trust.

## Our own dependencies

`cargo deny` (licences, bans, advisories, sources) runs on every push, `cargo audit` runs weekly and on
every tag, and Dependabot proposes updates. A tool that reports other people's vulnerable dependencies
should not ship its own.
