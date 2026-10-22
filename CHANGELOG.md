# Changelog

All notable changes are recorded here. Versions are `0.YYYYMMDD.N` (the release date and a counter).
The release workflow refuses a tag whose version has no `## [version]` section.

## [Unreleased]

### Fixed

- `scan-code` named a file with the platform's own separator, so on Windows a finding in a workflow was
  `.github\workflows\ci.yml` where Linux and macOS print `.github/workflows/ci.yml`. Every scanner now
  writes `/` on every platform, including paths read from `gitleaks` and `semgrep` reports.

## [0.20261022.3] - 2026-10-22

### Added

- `update` (and the MCP tool `update_db`) now print how many malicious-package reports each ecosystem
  holds. A scan against a dataset downloaded before they were counted says it cannot tell whether a
  malicious package is among the results, instead of staying silent.
- GitHub Actions. A workflow in `.github/workflows` is read for its `uses:` lines, and each action is
  checked against the OSV `GitHub Actions` data (the GitHub Advisory Database): `update actions`, or
  `update --for .` in a project with workflows, downloads it (about 100 KB). A full release tag is
  matched, by repository and without regard to case. A commit SHA, a floating tag and a branch name no
  release, so they are listed as `actions not checked` in the text report, the JSON, SARIF and CycloneDX
  notes, the activity log and the dashboard and HTML export, and, unlike an unpinned requirement, they do
  not make a result incomplete. A fix is words for a person (change `uses:` to the fixed tag or its SHA),
  never a command. `--ecosystem actions` limits a scan to them.
- `scan-code` rules for workflows (`gha-script-injection`, `gha-pwn-request`, `gha-workflow-run-artifact`,
  `gha-unpinned-action`, `gha-broad-permissions`), each with its CWE, the OWASP CI/CD Top 10 entry that fits
  it, and the GitHub guidance or GitHub Security Lab article it rests on, summarised in
  `docs/LANGUAGES.md` together with what each rule misses. A test keeps every rule documented.
- `scan-code` rules for code that talks to an AI model, each with a CWE and, where there is one, the
  OWASP Top 10 for LLM Applications (2025) entry: provider keys (`secret-anthropic-key`,
  `secret-huggingface-token`, `secret-google-api-key`; prefixes from the providers' own documentation,
  and none for OpenAI, whose documentation does not state a format), a model's answer passed on the same
  line to `eval`, a shell, SQL or an HTML sink (`ai-output-eval`, `ai-output-shell`, `ai-output-sql`,
  `ai-output-html`; JavaScript, TypeScript and Python), and a prompt or system message built from a
  request's input (`ai-prompt-concat`, `ai-system-prompt-user-input`). Key hits are never printed. The
  rules live in their own file, and a test keeps every rule documented.
- Skills. `scan-agent-config` also reads every folder that holds a `SKILL.md` (wherever it sits, and
  `~/.claude/skills` with `--include-home`): the Markdown gets the instruction rules, a script gets the
  hidden-character, download-and-run and exfiltration rules and the secret rules, a shell script's
  `npx`/`uvx`/`pip install`/`npm install` commands are read for the packages they name, and the
  lockfiles and `package.json` in the folder are checked against advisory and malicious-package data
  like any lockfile (a `pyproject.toml` too: exact `==` pins are matched, other specifications are
  listed as unchecked, and Python, JavaScript, TypeScript, Ruby, Perl and PowerShell scripts are read for
  installs as well). Two new rules: `agent-skill-unpinned-package` and `agent-skill-binary` (a compiled
  file shipped in a skill, by extension; never read).
- `scan-code`: a documented example credential (`AKIAIOSFODNN7EXAMPLE`, `YOUR_KEY_HERE`) is not reported
  by any secret rule any more; the placeholder check used to cover one of them.
- `scan-agent-config` (MCP tool `scan_agent_config`): checks the files that steer an AI coding assistant
  (`CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules`, `.cursor/rules`, `copilot-instructions.md`,
  `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `.claude/settings.json`, `.vscode/tasks.json`).
  Eight rules, each with a CWE and the OWASP MCP Top 10 or LLM Top 10 entry behind it: invisible and
  bidirectional characters, instruction-override phrases, instructions hidden in HTML comments, lines
  that download and run code (in instruction files and in hooks, tasks and server commands), lines that
  send secrets to a URL, MCP servers started from unpinned packages and tasks that run when a folder
  is opened, plus the secret rules of `scan-code`. The packages an MCP server starts with an exact
  version are checked against the advisory and malicious-package data like a lockfile entry.
  Findings from rules are `suspected`. The matched text is never stored or printed (hidden characters
  are named by code point), and the home directory is read only with `--include-home`, which the MCP
  server does not offer. The result is in the dashboard and the HTML export (a panel and a number), and
  the activity log (kind `scan_agent_config`). See `docs/AGENT-CONFIG.md`.
- A malicious package started by an MCP server counts in the dashboard's "Malicious packages" number.
- Install-time code. `scan` lists the packages whose lockfile entry says an install step runs code (npm
  `hasInstallScript`, lockfileVersion 2 and 3; pnpm `requiresBuild`, lockfileVersion 5 and 6) apart from
  the vulnerabilities: in the text report, as
  `install_scripts` in JSON and MCP, in SARIF run properties, as a property on each CycloneDX component,
  and in the dashboard and the HTML export (a number and a table). It is not a vulnerability and never
  changes `--fail-on`; a malicious package that also runs an install script says so.
- A lockfile that cannot say (npm lockfileVersion 1, pnpm lockfileVersion 9 and later, yarn, Cargo,
  Composer, Go, the Python lockfiles, an SBOM) is named as such in every format, and "none" is only
  claimed for lockfiles that do record it. pnpm stopped writing `requiresBuild` with lockfileVersion 9.
- `pnpm-lock.yaml` lockfileVersion 5 keys with a peer suffix (`/react-dom/18.2.0_react@18.2.0`) were read
  with the wrong package name; they are now read as `react-dom` 18.2.0.
- Malicious packages. An OSV `MAL-` report (OpenSSF Malicious Packages) is now a finding of its own kind:
  `malicious: true`, severity `critical`, listed before every other finding, and marked `MALICIOUS` in the
  text report, SARIF (rule properties and tags) and CycloneDX (rating method `other`, a property and a
  recommendation). The data was already in the downloaded dumps, where such a package used to appear
  as an `unknown` finding that sank below the rest when your code did not import it.
- Usage evidence is not assessed for a malicious package, so it can never be demoted. A malicious package
  is removed, never upgraded: `plan_fix` gives it no step and lists it as `unfixable` with
  `malicious: true`, and the `fix:` line of every report format says to remove it, check whether its
  install scripts already ran and rotate secrets. That holds for a compromised release of an honest
  package too: a release the advisory does not list is shown as information (`clean_releases`), because
  moving to it does not undo what the affected release already ran.
- `update` counts the `MAL-` reports per ecosystem (`malicious` in the dataset metadata, `malicious_records`
  in `data_sources`). A dataset that holds none now says so in `notes` instead of looking clean.
- The dashboard has a "Malicious packages" number and a `MALICIOUS` tag in the findings table; scan events
  in the activity log carry `malicious`.

### Fixed

- The `opencraysec:ignore` marker alone in a `/* */` or `<!-- -->` comment on the line above now silences
  the next line in `scan-code` too (only `//` and `#` worked), and `scan-code`, the workflow rules and
  `scan-agent-config` share one rule for it instead of three that disagreed.

## [0.20261022.2] - 2026-10-22

Completes `scan-runtime`, which 0.20261022.1 shipped without a place in the report: a runtime scan was not
written to the activity log, so the dashboard and the HTML report never showed it.

### Added

- Every `scan-runtime` run and every `scan_runtime` call is recorded in the activity log (kind
  `scan_runtime`) under the project it ran for: the CLI's current directory, or the MCP server's workspace.
  `--no-log` and `OPENCRAYSEC_LOG=off` still turn it off, like every other scan.
- The dashboard and the HTML export have a **Runtime products** panel and a "Runtime products to review"
  number. The panel shows, per product and version, whether the release line is end of life or behind its
  newest patch and, when NVD was asked, the CVEs NVD lists with CVSS, CISA's exploited flag and the
  affected range. All runtime scans of a project count: the newest verdict for each product and version
  is shown, and a CVE list from an earlier scan is kept when a later one did not ask NVD.

### Fixed

- A CVSS or EPSS score in `scan-runtime --format json`, in the MCP result and in the log could print as
  `9.800000190734863`. Scores are now written as `9.8` and `0.4`.
- With `--nvd`, the notes under a runtime scan said "This checks release lines, not CVEs" next to a list of
  CVEs. The note now says what each verdict means and that the listed CVEs are NVD's.

### Documentation

- `README.md` listed only OSV, CISA, FIRST and MITRE as download sources and `--enrich-nvd` as the only NVD
  use; it now also names endoflife.date, php.net and `scan-runtime --nvd`.
- `docs/DASHBOARD.md`, `docs/ARCHITECTURE.md` and `docs/TOOLS.md` describe the new event and panel.

## [0.20261022.1] - 2026-10-22

Adds checks for what no lockfile lists: the interpreter and servers an application runs on (a flaw in PHP
itself, such as CVE-2026-109618 and CVE-2026-109619, was invisible to every earlier scan), and SBOMs.

### Added

- `scan-runtime` (MCP tool `scan_runtime`): checks the interpreters, servers and databases an application
  runs on (PHP, nginx, Node.js, MySQL and others) against release and end-of-life data. These products are
  in no lockfile, so a flaw in PHP itself was invisible to every earlier scan. The verdicts are `eol`,
  `outdated`, `current` and `unknown`; they describe release lines, not CVEs, and the report says so.
- `update` (and `update_db`) also download the end-of-life data (endoflife.date) and the newest PHP patch
  releases (php.net). A scan reads them without the network. The php.net feed is there because aggregators
  lag a vendor by a day or more; if it fails, the update still succeeds.
- `scan-runtime --nvd` (and `scan_runtime` with `nvd: true`) asks NVD which CVEs apply to each product at
  its version, by CPE name, and ranks them with the local CISA KEV and EPSS data. The version ranges are
  evaluated locally; old entries that name every version of a product are counted, not listed; an entry
  whose range cannot be read is kept and flagged. Answers are cached for 12 hours. On 2026-10-22 this is
  what lists CVE-2026-109618 and CVE-2026-109619 for PHP 8.4.26 while OSV had neither.
- Versions come from a fixed table of version commands or from `product@version` arguments, which is how
  to check a container or another machine. Nothing in the downloaded data is ever executed.
- New crate `opencraysec-runtime` (a leaf, no network), registered in the layering rules.
- `scan` / `scan_dependencies` accept a CycloneDX or SPDX JSON file as the path. This is how to check an
  inventory that has no lockfile: a container image's package list, or another machine's. Components are
  matched by purl for the five supported ecosystems; operating-system packages, container images and
  components with no purl or version are listed under `unchecked`, never dropped. An SBOM is only read
  when named, so a directory scan does not pick up one lying next to a project.

### Changed

- `update` (and `update_db`) also download the runtime release data. A failing endoflife.date download
  makes `update` exit 4 after the other sources were refreshed; a failing php.net download is only a
  warning, because it is an optional, fresher source.
- `docs/DATA-SOURCES.md` no longer says NVD never decides whether something is affected: that holds for
  libraries, where a CPE name does not identify a package, and not for runtime products, where it does.
- The NVD score and weakness reader is shared by `--enrich-nvd` and `--nvd`; no behaviour change.

### Security

- `rustls-webpki` 0.103.15 to 0.103.16 (RUSTSEC-2026-0382, certificate verification could accept distrusted
  intermediates) and `webpki-roots` 1.0.9 to 1.0.10 (RUSTSEC-2026-0381, a distrusted emSign root). Both
  are reached through the HTTPS client used for the dataset downloads; the lockfile moved within the same
  compatible versions, and `cargo deny` passes again.

### Documentation

- `SECURITY.md` says what `scan-runtime` runs (a fixed list of version commands, no shell, a time limit and
  an output cap, never anything from downloaded data), what it sends to NVD, and which new sources it
  downloads from.
- `docs/CONFIGURATION.md` lists the new data files, the `OPENCRAYSEC_EOL_URL` and
  `OPENCRAYSEC_PHP_RELEASES_URL` mirrors, `NVD_API_KEY` for `--nvd`, the new limits, network use and exit
  codes. `docs/TROUBLESHOOTING.md` covers `unknown` runtime verdicts, backported distribution packages, slow NVD
  lookups and SBOM components that were not checked.
- `README.md`, `CONTRIBUTING.md`, `docs/CLIENTS.md`, `docs/TOOLS.md`, `docs/LANGUAGES.md`,
  `docs/ARCHITECTURE.md` and the bundled Agent Skill describe the new crate, tool and SBOM input.

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
