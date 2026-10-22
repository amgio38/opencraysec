# MCP tools

`opencraysec mcp` exposes these tools. Every result is JSON in `structuredContent` (and as text in
`content`), and a failed call has `isError: true` with an `error` message. Paths are relative to
`--workspace` and may not leave it.

Common scan arguments (`scan_dependencies`, `plan_fix`, `verify_fix`):

| Argument | Type | Meaning |
| --- | --- | --- |
| `path` | string | Directory or lockfile to check. Default: the workspace root. |
| `ecosystems` | string[] | Limit to `rust`, `js`, `php`, `go`, `python` (or `crates.io`, `npm`, `Packagist`, `Go`, `PyPI`). |
| `include_dev` | boolean | Include development-only dependencies. Default `true`. |
| `offline` | boolean | Never use the network. Ecosystems without local data are reported as not scanned. |
| `min_severity` | string | `low`, `medium`, `high` or `critical`. |
| `reachability` | boolean | Check whether your source uses each vulnerable package. Default `true`. |
| `enrich_nvd` | boolean | Look up missing CVSS scores and CWEs on NVD (network, at most 15 per scan). Default `false`. |

## scan_dependencies

Checks the lockfiles against current advisories. `path` may also be a CycloneDX or SPDX JSON file (see
[LANGUAGES.md](LANGUAGES.md#sbom-files)); components that are not libraries of a supported ecosystem are
listed in `notes` as not checked. Extra argument: `limit` (default 50) caps the findings returned.

Result: `lockfiles`, `skipped`, `packages_checked`, `data_sources` (per ecosystem: `local`, `online` or
`none`, and when the data was updated), `notes`, `informational_omitted`, `findings_total`,
`findings_returned`, `by_severity`, and `findings`, most urgent first (malicious packages, then exploited
in the wild, then code that uses the package, then a meaningful EPSS, then CVSS). Each finding has `id`,
`aliases`, `package`, `summary`, `severity`, `cvss`, `cwes`, `known_exploited`, `epss`, `fixed_in`,
`references` and `reachability`, and `malicious: true` when the advisory reports malicious code in the
package itself (an OSV `MAL-` report, see [DATA-SOURCES.md](DATA-SOURCES.md#malicious-packages)); the field
is absent otherwise. A malicious finding is `critical`, has no `reachability`, and is fixed by removing the
package, not by upgrading. `data_sources` entries also carry `malicious_records`, the number of such
reports in the local dataset, when it was counted. `install_scripts` lists the packages whose lockfile
entry says an install step runs code (`name`, `version`, `source`, `dev`), cut to `limit` with the full
count in `install_scripts_total`; `install_scripts_checked` names the lockfiles that record this and
`install_scripts_unknown` the ones that cannot say, with why (see
[LANGUAGES.md](LANGUAGES.md#install-time-code)). It is not a vulnerability list. **Read `notes`**: it says
what was not scanned.

## scan_code

Suspected weaknesses in the project's own source (see [LANGUAGES.md](LANGUAGES.md#code-rules-scan-code)).
Arguments: `path`, `external` (`["gitleaks"]`, `["semgrep"]`), `semgrep_config`, `limit` (default 100).
Result: `files_scanned`, `findings` (`rule`, `title`, `cwe`, `severity`, `file`, `line`, `snippet`,
`confidence: "suspected"`, `advice`, `source`), `external` (how each external scanner went), `notes`.

## scan_agent_config

The files that steer an AI coding assistant in the project: rule files, MCP server settings, hooks,
auto-run tasks and skills (see [AGENT-CONFIG.md](AGENT-CONFIG.md) for the files and every rule). Arguments: `path`,
`limit` (default 100). It stays inside the workspace and **never reads the home directory**; there is no
argument for it (the command line has `--include-home`).

Result: `files_scanned`, `findings` (`rule`, `title`, `cwe`, `severity`, `file`, `line`, `confidence`,
`advice`, `source`), `packages_checked` (packages with an exact version, from an MCP server or a skill, that
were checked against advisory data), `unchecked` (files that name packages which could not be checked, and why),
`home_scanned` and `notes`. A finding from a rule says `suspected` and `builtin`; one from published data
says `advisory` and `osv`, with the advisory id as its `rule` (a malicious package is `critical`). The
matched text is never returned, and `snippet` is always empty. The call is recorded in the activity log
(kind `scan_agent_config`).

## explain_advisory

`id` (`GHSA-...`, `CVE-...`, `RUSTSEC-...`, `GO-...`), optional `offline`. Result: `summary`, `details`,
`severity`, `cvss`, `cwes` (name, description and MITRE link), `known_exploited`, `epss`, `affected`,
`references` and `source` (`local` or `online`).

## plan_fix

Scans, then returns the minimal upgrade steps: `steps` (`package`, `from`, `to`, `bump`, `findings`,
`lockfile`, `commands`, `needs_confirmation`, `note`), `unfixable` (findings with no published fix),
`caveats`, `notes` and `after_you_apply_it`. Extra argument: `id` limits the plan to one advisory id or
package. **Nothing is modified.** Ask the user before steps with `needs_confirmation: true`.

## verify_fix

`ids` (required): advisory ids that should be gone. Re-scans the **whole project** and returns
`resolved`, `unknown`, `remaining`, `total_findings_now`, `trustworthy` and `notes`.

- The `ecosystems`, `include_dev` and `min_severity` arguments are accepted but **ignored** here, so a
  display filter can never hide a finding that is still there. `offline`, `reachability` and
  `enrich_nvd` still apply.
- An id is `resolved` only when an earlier `scan_dependencies` of the same path (from the activity log)
  reported it and the re-scan no longer does. An id that no earlier scan reported is `unknown`: a typo,
  an advisory that never applied to this project, or no scan was logged. Scan before you fix, and keep
  logging on.
- When `trustworthy` is false part of the project could not be checked (no lockfile, an unreadable
  lockfile, an ecosystem with no advisory data, or requirement lines that cannot be matched) and
  `resolved` proves nothing.

## record_fix

Like a commit message, after the assistant changed the project. Optional but recommended.

| Argument | Meaning |
| --- | --- |
| `ids` (required) | Advisory ids the change addresses. |
| `summary` (required) | What was changed. |
| `reason` | Why: the vulnerability, how it affects the project, why this fix. |
| `files`, `commands` | Files edited and commands run. |
| `commit` | Git commit hash, if any. |
| `path` | Project directory. |

Result: `recorded`, `recorded_at`, `lockfile_changes_detected` (measured by comparing dependency
snapshots, not taken from the caller), `baseline_found`, `ids_not_in_last_scan`. The caller's text is
stored as AI-reported. Fails when logging is off.

## scan_runtime

Checks the interpreters, servers and databases the application runs on (PHP, nginx, Node.js, MySQL,
...). No lockfile lists these, so a flaw in PHP itself is invisible to `scan_dependencies`. This tool
judges release lines: `eol` means upstream no longer fixes that line, `outdated` means a newer patch
release exists, `current` means neither, `unknown` means the data could not say. With `nvd: true` it also
lists the CVEs NVD records for each product at its version, which is what finds a flaw in PHP itself. See
[DATA-SOURCES.md](DATA-SOURCES.md#runtime-products).

Arguments: `nvd` (boolean, default `false`) and `products`, a list of `product@version` strings (`php@8.2.30`, `nodejs@20.11.0`). Without it
the tool runs a fixed set of version commands on this machine (`php --version`, `nginx -v`, `node
--version`, ...); with it nothing is executed, which is how to check a container or another machine.
Release data is read from the local store (run `update_db` once to download it). The network is used only
for `nvd: true`: answers are cached for 12 hours, NVD allows 5 requests per 30 s without `NVD_API_KEY`, at
most 10 products are asked per call, and offline mode refuses it.

Result: `scanned_at`, `data` (when the end-of-life data and each vendor feed were downloaded),
`results` (per product: `product`, `version`, `source`, `status`, `cycle`, `eol_from`, `latest`,
`patches_behind`, `advice`, and with `nvd` an `nvd` object) and `notes`. The `nvd` object has `cves`
(most urgent first: `id`, `published`, `summary`, `cvss`, `cwes`, `affects`, `known_exploited`, `epss`),
`all_versions_omitted` (old entries that name every version of the product, counted but not listed),
`truncated` and `error` (why NVD was not asked or failed). Every call is recorded in the activity log
(kind `scan_runtime`, under the workspace the server was started for), so the dashboard shows it. **Read `notes`**: it says what was not looked at and why a
distribution's older version number may already be patched.

## update_db

Downloads or refreshes advisory data. Arguments: `ecosystems` (default: those already downloaded) and
`enrich` (default `true`: also CISA KEV, EPSS, the MITRE CWE catalog and the runtime release data). npm is several hundred MB.
Disabled with `--offline`. Result: one entry per source with its record count or error.

## db_status

Which data is stored and how old it is.
