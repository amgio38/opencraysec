---
name: opencraysec
description: Check a project for known vulnerable dependencies against today's public advisories (OSV, CISA KEV, EPSS) across Rust, JS/TS, PHP, Go and Python, then plan and verify fixes. Use when asked about security, CVEs, vulnerable or outdated dependencies, `npm audit`/`cargo audit` style checks, before releases, or after adding dependencies.
---

# opencraysec

Your training data is months old; advisories are published daily. Use the `opencraysec` tools (MCP) or
CLI to get current facts instead of guessing.

## Workflow

1. `scan_dependencies` on the project root (add `min_severity: "medium"` on big projects).
   - Read `notes` first: it lists ecosystems that were **not** scanned and missing enrichment data. If findings are unscored, call again with `enrich_nvd: true`.
   - Findings are ranked: `known_exploited`, then code that uses the package, then high `epss`, then `cvss`. Work top-down.
2. `explain_advisory` for anything you will act on or report: what the weakness is (CWE), whether it is
   exploited in the wild, links.
3. Decide whether it matters here. Each finding has `reachability`: `used_symbol` (your code names an
   affected function: treat as urgent), `imported` (imported, usage not checked), `not_found` (your own
   code does not import it; another dependency may), `unknown`. This is source-text evidence, not a call
   graph: never say "not exploitable" because of `not_found`. For Go, `govulncheck` gives a proof.
4. `plan_fix`, then run the commands. Ask the user before any step with `needs_confirmation: true`
   (major version or `0.x` minor bump) and before touching lockfiles in a way they did not ask for.
5. Run the project's tests/build. If the upgrade breaks them, report it instead of forcing it.
6. `verify_fix` with the advisory ids. Only say a vulnerability is fixed if `resolved` contains it
   **and** `trustworthy` is true. An id under `unknown` was never reported by a `scan_dependencies` of
   this path, so it is not proven fixed: scan first, then fix, then verify.
7. `record_fix` (recommended, like a commit message): give the advisory ids, a short `summary` of what you
   changed, the `reason` (the vulnerability, how it affects this project, why this fix), the `files`, the
   `commands` and the `commit` if you made one. The user's report (`opencraysec dashboard`) shows it. Be
   accurate: lockfile changes are measured separately and your text is labelled as AI-reported.

## Your own code

`scan_code` flags suspected weaknesses in the project's source (secrets, injection patterns, disabled
TLS verification, unsafe deserialization). Every hit is a lead: open the file, trace the data, and only
report what you can show. Never repeat a secret's value; say where it is and that it must be rotated.
Pass `external: ["gitleaks"]` for a deeper secret scan if it is installed.

## Rules

- A clean scan means no known advisory matched the lockfile versions. It is not proof of security. Say
  what was scanned and what was not (`lockfiles`, `data_sources`, `notes`).
- Never publish vulnerability details (public issues, public PR text) before the fix is released.
- If `data_sources[].mode` is `online`, package names and versions were sent to api.osv.dev. Mention this
  once if the project is confidential, and offer `update_db` for offline scans.
- Unfixable findings (`unfixable`): propose mitigation (pin, replace the dependency, disable the feature)
  and say that no fix exists.

## Beyond dependencies: a logic review checklist

Scanners cannot see flaws in the project's own logic. When asked for a security review, walk these
areas, and for each finding give: file and line, the CWE class, **evidence** (the code path) and
**reproduction steps**. If you cannot reproduce it, label it "suspected" and say what would confirm it.
Do not report guesses as vulnerabilities.

| Area | Look for | CWE |
|---|---|---|
| Authentication | endpoints missing auth, tokens in URLs/logs, weak session or reset flows | 287, 306, 384 |
| Authorization | object ids taken from the request without an owner check (IDOR), role checks done only in the UI | 639, 862, 863 |
| Injection | string-built SQL, shell commands, templates, LDAP/NoSQL queries from request data | 89, 78, 94, 943 |
| Paths and files | user-controlled paths, archive extraction, uploads served from the web root | 22, 434 |
| Outbound requests | fetching a user-supplied URL (SSRF), open redirects | 918, 601 |
| Deserialization | pickle/unserialize/YAML load/`eval` on untrusted data | 502 |
| Secrets | keys in source, `.env` committed, secrets in logs or error pages | 798, 200 |
| Crypto | home-made crypto, MD5/SHA-1 for passwords, fixed IV, `verify=False` | 327, 295 |
| Web | CSRF on state-changing requests, XSS from unescaped output, permissive CORS, missing cookie flags | 352, 79 |
| Concurrency and money | check-then-act races on balances, coupons, stock; replayable requests | 362 |
| Agent surface (for AI tools) | tool arguments reaching a shell/path/URL without validation; prompt-injectable data reaching privileged tools | 77, 22, 918 |

Report format per item: `title | CWE | file:line | evidence | reproduction | suggested fix | confidence
(confirmed/suspected)`.
