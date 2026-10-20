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

Checks the lockfiles against current advisories. Extra argument: `limit` (default 50) caps the
findings returned.

Result: `lockfiles`, `skipped`, `packages_checked`, `data_sources` (per ecosystem: `local`, `online` or
`none`, and when the data was updated), `notes`, `informational_omitted`, `findings_total`,
`findings_returned`, `by_severity`, and `findings`, most urgent first (exploited in the wild, then code
that uses the package, then a meaningful EPSS, then CVSS). Each finding has `id`, `aliases`, `package`,
`summary`, `severity`, `cvss`, `cwes`, `known_exploited`, `epss`, `fixed_in`, `references` and
`reachability`. **Read `notes`**: it says what was not scanned.

## scan_code

Suspected weaknesses in the project's own source (see [LANGUAGES.md](LANGUAGES.md#code-rules-scan-code)).
Arguments: `path`, `external` (`["gitleaks"]`, `["semgrep"]`), `semgrep_config`, `limit` (default 100).
Result: `files_scanned`, `findings` (`rule`, `title`, `cwe`, `severity`, `file`, `line`, `snippet`,
`confidence: "suspected"`, `advice`, `source`), `external` (how each external scanner went), `notes`.

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

## update_db

Downloads or refreshes advisory data. Arguments: `ecosystems` (default: those already downloaded) and
`enrich` (default `true`: also CISA KEV, EPSS and the MITRE CWE catalog). npm is several hundred MB.
Disabled with `--offline`. Result: one entry per source with its record count or error.

## db_status

Which data is stored and how old it is.
