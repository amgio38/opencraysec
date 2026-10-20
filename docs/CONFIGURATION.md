# Configuration

opencraysec has no configuration file. Behaviour is set by command-line flags and a few environment
variables.

## Where data lives

The data directory is, in order: `--data-dir`, `$OPENCRAYSEC_HOME`, `$XDG_DATA_HOME/opencraysec`,
`~/.local/share/opencraysec`.

| Path under the data directory | What it holds |
| --- | --- |
| `osv/<ecosystem>.jsonl`, `osv/<ecosystem>.meta.json` | Advisories per ecosystem and when they were downloaded. |
| `kev.json` | CISA Known Exploited Vulnerabilities (CVE ids). |
| `epss.tsv` | EPSS scores, one `CVE<TAB>score` per line. |
| `cwe.tsv` | MITRE CWE names and descriptions. |
| `nvd/<CVE>.json` | Cached NVD answers (valid 30 days). |
| `osv-online/<id>.json` | Advisories fetched from the OSV API when an ecosystem has no local data. |
| `log/events.jsonl` | The activity log, one JSON object per line. |
| `log/snapshots/` | Dependency snapshots used to measure what a fix changed (the last 12 per project). |
| `tmp/` | Scratch space for external scanner reports. |

Everything can be deleted at any time; it is downloaded again on demand. The advisory files are a
cache of public data. The log is the only thing that is *yours*.

## Environment variables

| Variable | Effect |
| --- | --- |
| `OPENCRAYSEC_HOME` | Data directory (see above). |
| `OPENCRAYSEC_LOG` | `off`, `0`, `false` or `no` disables the activity log. |
| `OPENCRAYSEC_DASHBOARD_TOKEN` | Token the dashboard requires (same as `--token`). |
| `NVD_API_KEY` | Lets `--enrich-nvd` run faster (0.7 s between requests instead of 6.5 s). |
| `OPENCRAYSEC_OSV_DUMP_URL` | Base URL of the OSV per-ecosystem dumps (`<base>/<ecosystem>/all.zip`). |
| `OPENCRAYSEC_OSV_API_URL` | Base URL of the OSV API (`<base>/querybatch`, `<base>/vulns/<id>`). |
| `OPENCRAYSEC_KEV_URL`, `OPENCRAYSEC_EPSS_URL`, `OPENCRAYSEC_CWE_URL`, `OPENCRAYSEC_NVD_URL` | Mirrors for the other sources. |

The URL variables exist for mirrors and air-gapped setups. Empty values are ignored.

## Global flags

| Flag | Effect |
| --- | --- |
| `--data-dir DIR` | Data directory. |
| `--no-log` | Do not write the activity log for this run. |

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success. |
| 1 | `scan`/`scan-code` found something at or above `--fail-on`; `verify-fix` found a remaining finding, an `unknown` id, or could not be trusted. |
| 2 | Bad arguments. |
| 3 | `scan --fail-on` found nothing at or above the threshold, but a pass would prove nothing: no lockfile was found, a lockfile was unreadable, an ecosystem has no advisory data, or the only dependencies were requirement lines that cannot be matched (no exact `==` pin). Unmatched requirement lines next to dependencies that were checked do not fail the gate; they are listed in the report, which then says it is incomplete. |
| 4 | The command could not complete (unreadable path, network failure, ...); the message says why. |

## Limits

| What | Limit |
| --- | --- |
| Lockfile size | 64 MiB each (larger ones are reported as skipped) |
| Lockfile search depth | 8 directories |
| Usage evidence | 20,000 source files per lockfile directory, 1 MiB each |
| Code scan | 30,000 files, 1 MiB each, 500 findings |
| NVD lookups | 15 per scan (the rest are reported, not dropped) |
| MCP message size | 4 MiB per line |
| Findings returned by `scan_dependencies` | 50 by default (`limit`) |
| Activity log | Not rotated: delete `log/` to start over |

## Network use

| When | What is sent | Where |
| --- | --- | --- |
| `update` | Nothing but the request | OSV dumps, CISA, FIRST, MITRE |
| `scan`/`plan-fix`/`verify-fix`, an ecosystem has no local data and `--offline` was not given | Package names and versions | `api.osv.dev` |
| `--enrich-nvd` | CVE ids | `services.nvd.nist.gov` |
| `semgrep --semgrep-config p/...` | Whatever semgrep sends to fetch rules | `semgrep.dev` |

Your source code is never sent anywhere by opencraysec. `--offline` (CLI) and `opencraysec mcp
--offline` forbid all of it.
