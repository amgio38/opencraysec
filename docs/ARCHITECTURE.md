# Architecture

## Data flow

```
lockfiles ──► lockfile::discover ──► Vec<Package>
                                        │
        local store (OSV JSONL) ◄───────┤  (per ecosystem; else api.osv.dev if online is allowed)
                                        ▼
                      core::osv::OsvRecord::affects  ──►  Finding
                                        │
        CISA KEV + EPSS  ───────────────┤  enrich + rank
                                        ▼
                     merge same-issue advisories  ──►  ScanReport
                                        │
                     text / json / SARIF / CycloneDX / MCP
```

## Decisions

- **Own matcher over OSV data.** Version ranges are evaluated in `core::osv` with a per-ecosystem
  ordering in `core::version` (semver, a PEP 440 subset, Composer stability ranks). We do not use NVD CPE
  strings for matching: they do not carry package coordinates, so they produce both false positives and
  false negatives for libraries.
- **Offline first.** `update` stores one JSONL file per ecosystem; each line is prefixed with the
  normalised package names it affects so a scan skips unrelated advisories without parsing them.
- **Same issue, one finding.** GHSA, RustSec and Go ids that share an alias for the same package are merged.
  When sources disagree on the fixed version, the strictest one wins.
- **Only the range holding the installed version names a fix.** Other ranges describe other release
  branches.
- **Never edits the project.** `plan_fix` returns commands; `verify_fix` re-scans and reports whether the
  result can be trusted (`trustworthy` is false if any ecosystem was not scanned).
- **Ranking.** Known-exploited, then EPSS of 10% or more, then CVSS, then raw EPSS. Tiny EPSS differences
  are noise and never outrank a higher CVSS.

## Usage evidence (`engine::reach`)

For each finding the engine reads the source files below the lockfile's directory (skipping
dependency and build directories) and reports one of: `used_symbol` (Rust/Go: a file that uses the
package also names an affected function), `imported`, `not_found` (the project's own code does not
import it) or `unknown` (the evidence cannot be matched, for example PHP without `vendor/` or a Python
import name that differs from the distribution name). Symbol data comes from the advisories
(`ecosystem_specific`), which the dataset keeps in trimmed form. Evidence is text-level: it does not
resolve types, renamed dependencies or use by other dependencies, and every result says so.

## Code rules (`engine::code`)

A small table of line-level regex rules, each with a CWE and a severity. Hits are labelled
`suspected`; secret-like hits never include the matched text. External scanners (gitleaks, semgrep)
run only when requested and installed; their output is parsed into the same finding shape.

## NVD (`db::nvd`)

Only used to fill a missing score or CWE for a CVE. Answers are cached for 30 days, requests are
spaced to respect NVD's limits (faster with `NVD_API_KEY`), and a scan makes at most 15 per run.

## Activity log and report (`log`, `web`)

Events (`scan`, `scan_code`, `plan_fix`, `verify_fix`, `record_fix`) are appended as JSON lines; there
is no database, so the log can be read with `grep`/`jq` and copied around. Each scan also stores a
snapshot of every dependency it found (all ecosystems, whatever the scan options), kept for the last
few states per project. `record_fix` compares the current lockfiles with the newest *different*
snapshot, which is how "what changed" is measured instead of trusted. `summarize` turns the events
into the numbers the report shows; a fix counts as *confirmed* only when a later trustworthy
`verify_fix` resolved its ids.

The dashboard is a hand-written HTTP/1.1 `GET` server (no framework): bounded request size, read and
write timeouts, a connection cap, an optional token compared in constant time, and
`Content-Security-Policy`, `X-Frame-Options`, `nosniff` and `no-referrer` on every response. The page
inserts data with `textContent` only; the exported HTML embeds data with `<` escaped so it cannot
close the script element.

## Adding an ecosystem

1. Add a variant to `core::model::Ecosystem` (OSV name, aliases, name normalisation).
2. Add its ordering to `core::version::compare`.
3. Add a parser in `crates/lockfile` and register the file name in `kind_of` / `parse_text`.
4. Add the fix commands in `engine::fix::commands`, and the purl in `engine::report::purl`.
