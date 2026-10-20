# Changelog

All notable changes are recorded here. Versions are `0.YYYYMMDD.N` (the release date and a counter).
The release workflow refuses a tag whose version has no `## [version]` section.

## [Unreleased]

## [0.20261021.1] - 2026-10-21

Documentation only; no behaviour changed.

- `docs/INSTALL.md`: the Windows row had been cut out of the platform table by the macOS note above it
  and rendered as stray text after the table. It is back inside the table, and that note now follows it.
- `README.md`: the bundled Agent Skill also shows the project-local install (a skills directory inside
  the repository) next to the user-level one that applies it to every project.
- `README.md`, `docs/ARCHITECTURE.md`: `verify_fix` no longer reads as proof that an advisory is gone. An
  id is `resolved` only when an earlier scan of the same path reported it; an id no earlier scan
  reported is `unknown`, and that proves nothing.
- `README.md`: `scan --fail-on` documents exit 3, for the case where a pass would prove nothing.
- `README.md`: a release badge, and a line saying which releases carry the prebuilt binaries and the
  `.sha256` file beside each.

## [0.20261020.1] - 2026-10-20

First public release.

- Lockfile scanning for Rust, JavaScript/TypeScript, PHP, Go and Python against OSV, ranked by CISA KEV,
  EPSS and CVSS. Output as text, JSON, SARIF and CycloneDX.
- A scan never reports a clean result it did not earn: lockfiles that could not be read, requirement lines
  that are not exact pins, and ecosystems with no advisory data are listed, and `scan --fail-on` exits 3
  when nothing could be trusted.
- Usage evidence for every finding: whether your source imports the vulnerable package and, for Rust and
  Go, calls an affected function. Findings your code does not import rank lower.
- `scan-code` / `scan_code`: a built-in rule pack (secrets, injection patterns, disabled TLS, unsafe
  deserialization) with CWE ids, plus optional gitleaks and semgrep adapters.
- `--enrich-nvd`: fills in missing CVSS scores (v3.x and v4.0) and CWEs from NVD, cached and rate limited.
  The full MITRE CWE catalog backs `explain`.
- `plan_fix` / `verify_fix` / `record_fix`: the exact upgrade commands, a re-scan that only calls an id
  resolved when an earlier scan of the same path reported it, and a record of what was changed and why.
- A local activity log (`log/events.jsonl`; `--no-log` or `OPENCRAYSEC_LOG=off` disables it), a read-only
  dashboard (`opencraysec dashboard`, optional token) and a single-file report (`opencraysec report`).
- An MCP server (`opencraysec mcp`) and an Agent Skill for AI assistants.
- One-line installer with prebuilt binaries for Linux (x86-64, aarch64) and macOS (Apple Silicon, Intel),
  SHA-256 verified; an uninstaller; Windows through WSL2.
- Every crate and every source file is at 90% line coverage or better.
