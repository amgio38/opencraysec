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
| `nvd/<CVE>.json` | Cached NVD scores and CWEs (valid 30 days). |
| `nvd/cpe-<product>-<version>.json` | Cached NVD answers for `scan-runtime --nvd` (valid 12 hours). |
| `runtime/endoflife.json` | Release lines, end-of-life dates, latest patch releases and CPE names of about 480 products (from endoflife.date). |
| `runtime/vendor-php.json` | The newest PHP patch release per line (from php.net). |
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
| `NVD_API_KEY` | Lets `--enrich-nvd` and `scan-runtime --nvd` run faster (0.7 s between requests instead of 6.5 s). |
| `OPENCRAYSEC_OSV_DUMP_URL` | Base URL of the OSV per-ecosystem dumps (`<base>/<ecosystem>/all.zip`). |
| `OPENCRAYSEC_OSV_API_URL` | Base URL of the OSV API (`<base>/querybatch`, `<base>/vulns/<id>`). |
| `OPENCRAYSEC_KEV_URL`, `OPENCRAYSEC_EPSS_URL`, `OPENCRAYSEC_CWE_URL`, `OPENCRAYSEC_NVD_URL` | Mirrors for the other sources. |
| `OPENCRAYSEC_EOL_URL` | The endoflife.date products feed (`/api/v1/products/full`). |
| `OPENCRAYSEC_PHP_RELEASES_URL` | The php.net active release lines (`releases/active.php`). |

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
| 1 | `scan`/`scan-code` found something at or above `--fail-on`; `verify-fix` found a remaining finding, an `unknown` id, or could not be trusted; `scan-runtime` found a product that is end of life or behind its newest patch release, or (with `--nvd`) a CVE. |
| 2 | Bad arguments. |
| 3 | `scan --fail-on` found nothing at or above the threshold, but a pass would prove nothing: no lockfile was found, a lockfile was unreadable, an ecosystem has no advisory data, or the only dependencies were requirement lines that cannot be matched (no exact `==` pin). Unmatched requirement lines next to dependencies that were checked do not fail the gate; they are listed in the report, which then says it is incomplete. |
| 3 (also) | `scan-runtime` could not judge anything: nothing was detected, no release data is stored, or every product was `unknown`. |
| 4 | The command could not complete (unreadable path, network failure, ...); the message says why. |

## Limits

| What | Limit |
| --- | --- |
| Lockfile size | 64 MiB each (larger ones are reported as skipped) |
| Lockfile search depth | 8 directories |
| Usage evidence | 20,000 source files per lockfile directory, 1 MiB each |
| Code scan | 30,000 files, 1 MiB each, 500 findings |
| NVD lookups | 15 per scan with `--enrich-nvd`, 10 products per scan with `scan-runtime --nvd` (the rest are reported, not dropped) |
| Version commands (`scan-runtime`) | 5 seconds each, 16 KiB of output read |
| MCP message size | 4 MiB per line |
| Findings returned by `scan_dependencies` | 50 by default (`limit`) |
| Activity log | Not rotated: delete `log/` to start over |

## Network use

| When | What is sent | Where |
| --- | --- | --- |
| `update` | Nothing but the request | OSV dumps, CISA, FIRST, MITRE, endoflife.date, php.net |
| `scan`/`plan-fix`/`verify-fix`, an ecosystem has no local data and `--offline` was not given | Package names and versions | `api.osv.dev` |
| `--enrich-nvd` | CVE ids | `services.nvd.nist.gov` |
| `scan-runtime --nvd` | A product's CPE name and version, such as `cpe:2.3:a:php:php` at `8.4.26` | `services.nvd.nist.gov` |
| `semgrep --semgrep-config p/...` | Whatever semgrep sends to fetch rules | `semgrep.dev` |

Your source code is never sent anywhere by opencraysec. `--offline` (CLI) and `opencraysec mcp
--offline` forbid all of it.
