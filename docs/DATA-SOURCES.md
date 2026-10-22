# Data sources

opencraysec does not maintain a vulnerability database. It downloads public data, matches it locally
and reports where each fact came from. The data is not part of this software and stays under its
publishers' terms; check them before redistributing it. opencraysec is not endorsed or certified by NIST
or the NVD, by CISA, by FIRST, by MITRE, by endoflife.date or by php.net.

| Source | Used for | How it is fetched |
| --- | --- | --- |
| [OSV](https://osv.dev) | Which package versions are affected, fixed versions, severity vectors, CWE ids, affected functions | Per-ecosystem dumps (`osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip`) with `update`; the OSV API (`api.osv.dev`) when an ecosystem has no local data |
| GitHub Advisory Database, RustSec, Go vulnerability database, PHP security advisories, PyPA | The advisories OSV aggregates | Through OSV (not queried separately) |
| OSV `GitHub Actions` ecosystem | Which releases of an action are affected, from the GitHub Advisory Database (CC-BY 4.0) | The same per-ecosystem dump as the others: `update actions`, or `update --for .` in a project with workflows |
| [OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages) (Apache-2.0) | Packages reported to contain malicious code (ids `MAL-...`) | Through OSV: the same per-ecosystem dumps carry them, so `update` needs no extra download |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Whether a CVE is exploited in the wild (ranks first) | `update` |
| [FIRST EPSS](https://www.first.org/epss/) | Probability of exploitation in the next 30 days (ranks next) | `update` |
| [MITRE CWE](https://cwe.mitre.org) | Names and descriptions of weakness classes for `explain` | `update` |
| [endoflife.date](https://endoflife.date) | Release lines, end-of-life dates and the latest patch release of about 480 products, for `scan-runtime` | `update`, one request (`/api/v1/products/full`) |
| [php.net](https://www.php.net/releases/) | The newest PHP patch release per line, which php.net publishes before aggregators have it | `update` (`releases/active.php`); a failure here does not fail the update |
| [NVD](https://nvd.nist.gov) | A CVSS score (v3.x or v4.0) and CWEs for findings the advisories left unscored | `--enrich-nvd`, per CVE, cached for 30 days |
| [NVD](https://nvd.nist.gov) by CPE | The CVEs that apply to a runtime product at a version (PHP, nginx, a database), with their version ranges | `scan-runtime --nvd`, per product and version, cached for 12 hours |

## Why OSV does the matching

OSV records affected versions against package coordinates (`npm/lodash@4.17.4`), so a lockfile can be
matched exactly. NVD describes products with CPE strings, which do not map reliably to package
names, so it produces both false positives and false negatives for libraries. For libraries NVD is
therefore used only to add a score, never to decide whether a package is affected. Runtime products are
the exception, because there a CPE (`cpe:2.3:a:php:php`) *is* the product's name; see below.

## Runtime products

Lockfiles describe a project's libraries. The interpreter and servers underneath it (PHP, nginx, Node.js,
a database) are in no lockfile, and the OSV data above is keyed by package coordinates, so a flaw in PHP
itself never matches anything. `scan-runtime` covers that gap with a different, smaller question: *is this
version's release line still supported, and is it on the newest patch release?* It needs no advisory for
the flaw, so it works the day a fix ships, before any CVE database has the entry.

- The version comes from a fixed table of version commands (`php --version`, `nginx -v`, ...) or from
  `product@version` arguments. The commands are compiled in; the `versionCommand` text in the
  endoflife.date feed is free-form (shell pipelines, `cat /etc/os-release`) and is never executed.
- The latest patch is the newer of the endoflife.date value and, for PHP, the php.net value. On
  2026-10-22 endoflife.date still listed PHP 8.4.26 while php.net had published 8.4.27.
- End of life is decided from the line's date and today's date, so a dataset downloaded before the date
  passed still gives the right answer.

With `--nvd` it also asks NVD which CVEs apply to each product at its version. The CPE names come from
the endoflife.date feed, and the version ranges are evaluated here rather than trusted: NVD's own filter
also returns old entries that name every version of a product, which say nothing about a particular
version. Those are counted and reported as left out. On 2026-10-22 NVD listed CVE-2026-109618 and
CVE-2026-109619 for `php@8.4.26` (and not for `php@8.4.27`) while OSV did not have either yet. NVD answers
are cached for 12 hours; unauthenticated NVD access allows 5 requests per 30 seconds, so set
`NVD_API_KEY` if you scan many products.

What it cannot tell you: without `--nvd`, whether a CVE affects the version. Distributions backport fixes
without changing the upstream version number (an older `8.2.x` from your OS vendor may be patched), and an
end-of-life line can still be patched by a vendor. NVD can lag a disclosure and its ranges can be wrong.
The result says so in `notes` and never reports a clean bill of health.

## Malicious packages

A vulnerability is a flaw in code its author meant to be honest. A malicious package is hostile code
published on purpose, often under a name close to a popular one. The OpenSSF Malicious Packages project
collects reports of them and OSV republishes them with ids that start with `MAL-`. They arrive in the
dumps `update` already downloads, so there is no separate feed and no setting to turn on.

- A `MAL-` finding is marked `malicious`, rated `critical` (there is no CVSS score for it) and listed
  before everything else, including exploited vulnerabilities.
- Its usage evidence is not assessed. A package that your code never imports can still have run its
  install step on the machine or in CI, so "not imported" would only mislead.
- Upgrading is never the answer. `plan_fix` gives a malicious package no step: it is listed under
  `unfixable`, and every report format says to remove it, check whether its install scripts already ran,
  and rotate any secret that machine could reach. This also holds when the report names only some
  releases of a package (an honest package with one release taken over). The release the advisory does
  not list is shown as information (`clean_releases`, and in the `fix:` line), not as a fix: moving to it
  does not undo what the affected release already ran.
- Coverage differs a lot by registry. On 2026-10-21 the dumps held about 222,000 reports for npm,
  12,000 for PyPI, and a few dozen or fewer for crates.io, Go and Packagist. A low count
  reflects what has been reported, so do not read a quiet result as proof that a registry is free of
  them. `update` counts the reports per
  ecosystem and prints the count; if a dataset holds none, or was downloaded before they were counted,
  the scan says so in `notes` instead of looking clean (run `update` again to get the count).
- This does not apply to GitHub Actions: an action is not a registry package, so no report of malicious
  code is expected there and an empty count says nothing.
- A report is evidence that someone filed it, not a verdict on your copy. Check the references on the
  finding before you act, and tell the maintainers of the data if a report is wrong.

## GitHub Actions

An action in a workflow is a dependency, and OSV publishes the advisories for them as an ecosystem of
their own, `GitHub Actions`, filled from the GitHub Advisory Database (whose entries are CC-BY 4.0; OSV's
data page lists the licence of each source). The dump is small: on 2026-10-22 it held 56 advisories, about
100 KB, so it is one of the cheap ones to download.

- The package name is `owner/repo`. OSV keeps the case it was given and GitHub does not distinguish case,
  so names are compared in lower case. A few entries name a subfolder or are a whole URL (OSV's data is not
  uniform there); a workflow is matched by repository, so those are missed.
- Versions are mostly `X.Y.Z`, or `0` for "from the start". Some ranges use a bare major (`5` to `6`),
  which is read as `5.0.0` to `6.0.0`. Two entries on that day used commit hashes (a `GIT` range), which a
  release tag cannot be compared with, so they never match.
- A workflow names its action by a tag, a commit SHA or a branch. Only a full release tag (`v4.1.2`) is a
  version. The others are listed as not checked: see [LANGUAGES.md](LANGUAGES.md#github-actions-workflows).
- This is thin coverage compared with npm or PyPI: advisories exist only for actions someone reported. No
  advisory means none is known, not that an action is safe.

The dangerous-pattern rules for workflows are not data. Their basis is GitHub's security hardening guide,
GitHub Security Lab's articles on untrusted input and pwn requests, and the
[OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/); see
[LANGUAGES.md](LANGUAGES.md#github-actions-workflows).

## Assistant configuration

`scan-agent-config` ([AGENT-CONFIG.md](AGENT-CONFIG.md)) uses published data for one thing: the packages an
MCP server is started from. A package with an exact version is matched against the OSV data above (and its
malicious-package reports), exactly like a lockfile entry. Everything else it reports comes from rules,
which are patterns, not data. Each rule names the CWE and the entry of the
[OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) or the
[OWASP Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/) (both 2025) that motivates it;
those lists are the reasoning behind a rule, not something the tool downloads.

## How findings are ordered

1. Malicious packages (OSV `MAL-` reports).
2. Exploited in the wild (CISA KEV).
3. Code the project does not import sinks (only when usage evidence was checked); malicious and
   exploited ones always stay on top.
4. An EPSS of 10% or more.
5. CVSS base score (computed from v3.0/v3.1 vectors; v4.0 scores come from NVD with `--enrich-nvd`).
6. The raw EPSS value, as a tie-breaker.

Advisories for the same package that share an id or alias (GHSA, RUSTSEC, GO, CVE) are merged into
one finding; when sources disagree about the fixed version the highest of the lowest fixes wins, so the
suggested version is one every source agrees is safe.

## What the data cannot tell you

- A clean result means no *known* advisory matched the lockfile versions. It says nothing about
  unknown vulnerabilities or about your own code.
- Advisory databases lag behind disclosure, and ranges can be wrong. If a result looks wrong, check the
  advisory with `opencraysec explain ID` and report the source if it is mistaken.
- RustSec notices that are not vulnerabilities (`unmaintained`, `notice`) are omitted and counted in
  `informational_omitted`.
