# Data sources

opencraysec does not maintain a vulnerability database. It downloads public data, matches it locally
and reports where each fact came from. The data is not part of this software and stays under its
publishers' terms; check them before redistributing it.

| Source | Used for | How it is fetched |
| --- | --- | --- |
| [OSV](https://osv.dev) | Which package versions are affected, fixed versions, severity vectors, CWE ids, affected functions | Per-ecosystem dumps (`osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip`) with `update`; the OSV API (`api.osv.dev`) when an ecosystem has no local data |
| GitHub Advisory Database, RustSec, Go vulnerability database, PHP security advisories, PyPA | The advisories OSV aggregates | Through OSV (not queried separately) |
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

## How findings are ordered

1. Exploited in the wild (CISA KEV).
2. Code the project does not import sinks (only when usage evidence was checked); exploited ones always
   stay on top.
3. An EPSS of 10% or more.
4. CVSS base score (computed from v3.0/v3.1 vectors; v4.0 scores come from NVD with `--enrich-nvd`).
5. The raw EPSS value, as a tie-breaker.

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
