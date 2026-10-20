# Troubleshooting

## The scan says an ecosystem was "NOT scanned"

`scan --offline` (or an MCP server started with `--offline`) never uses the network, and that
ecosystem has no local data. Run `opencraysec update ECOSYSTEM` (for example `update go`), or drop
`--offline` so the OSV API is asked about the exact package versions.

## "package names and versions were sent to api.osv.dev"

That is the fallback for an ecosystem with no local data. To avoid it, download the data with
`opencraysec update --for .` and/or pass `--offline`.

## `update npm` is huge

The npm advisory dump is several hundred MB. Run `update` for the ecosystems you need
(`update --for .`), not `--all`. Without the dump, `scan` still works through the OSV API.

## "No supported lockfile found"

opencraysec reads lockfiles, not manifests (`package.json`, `Cargo.toml`, `composer.json`). Install
or lock first (`npm install`, `cargo generate-lockfile`, `composer install`, `go mod tidy`,
`poetry lock`) and scan again. See [LANGUAGES.md](LANGUAGES.md) for the supported files. A
`requirements.txt` needs exact `==` pins.

## A finding is missing that another tool reports

Check, in order: the package version in the lockfile (`explain ID` shows the affected ranges),
whether it is a dev dependency and you passed `--no-dev`, whether the ecosystem was limited with
`--ecosystem`, and whether the advisory is `unmaintained`/`notice` (omitted). Advisory data can differ
between databases; `opencraysec status` shows when yours was updated.

## Findings are unscored (severity `unknown`)

The advisory has no CVSS v3 vector and no severity label. Run again with `--enrich-nvd` (CLI) or
`enrich_nvd: true` (MCP) to look the CVE up on NVD; results are cached. Without `NVD_API_KEY` NVD
allows about one request every 6.5 seconds, so a scan looks up at most 15 per run.

## "Symbol-level usage checks need the dataset layout v2"

The local Go or Rust data was downloaded by an older version. Run `opencraysec update go rust` again.

## `not_found` but the package is clearly used

Usage evidence only reads your own source. A package used by *another dependency* is `not_found`
here. Go additionally needs the module path to match the import path. See
[LANGUAGES.md](LANGUAGES.md#usage-evidence-reachability) for what each ecosystem checks.

## `verify_fix` says `trustworthy: false`

Part of the project could not be checked, so "resolved" would prove nothing: no lockfile was found, a
lockfile could not be read (`skipped`), an ecosystem has no local data and the scan was offline, or
some requirement lines are not exact `==` pins (`unchecked`). Fix the cause named in `notes` and run it
again.

## `verify_fix` lists an id under `unknown`

`resolved` needs proof that the finding was here before. Only ids that an earlier `scan` of the same
path reported (and that is in the activity log) can be resolved. Run `scan` first, fix, then verify; make
sure logging is on (`OPENCRAYSEC_LOG`, `--no-log`) and the path is the same one you scanned.

## `scan --fail-on` exits 3

A pass would mean nothing. Read the `data`, `skipped`, `unchecked` and `note` lines: usually the
ecosystem has no advisory data offline (run `opencraysec update`), no lockfile was found under the
path, or `requirements.txt` has no exact `==` pins (use a lockfile or `pip-compile`).

## The dashboard is empty

The log is empty: run a scan first, or check that logging is not off (`OPENCRAYSEC_LOG`, `--no-log`).
Make sure the dashboard and the scans use the same data directory (`--data-dir`, `OPENCRAYSEC_HOME`).

## The dashboard has no charts

The page loads Chart.js from `cdn.jsdelivr.net`. Without access to it the page shows tables instead.

## I cannot reach the dashboard from another machine

Check `--host` (a loopback address is local only), the port (`--port`, default 1787), a firewall, and
the token (`?token=...`).

## The MCP server does not start in my client

Run `opencraysec mcp` in a terminal: it should wait silently for input (type nothing; press Ctrl-D).
Check that `opencraysec` is on the `PATH` the client uses (clients often start with a smaller
`PATH` than your shell; use the absolute path in the configuration). Messages from the server go to
standard error; standard output carries only protocol messages.

## A tool answers "is outside the workspace"

Paths must stay inside `--workspace`. Start the server with the project's root as `--workspace`, or
pass a path below it.

## Still stuck

Open an issue with the output of `opencraysec --version` and `opencraysec status`, the exact command
or tool call, and the smallest lockfile that shows it. Do not paste secrets or unpublished
vulnerability details.
