# The report dashboard

```sh
opencraysec dashboard                       # http://localhost:1787
opencraysec dashboard --host 127.0.0.1      # this machine only
opencraysec dashboard --port 8080 --token "$(openssl rand -hex 16)"
opencraysec report -o report.html           # the same report as one file
```

The dashboard is **read-only**. It reads the activity log and answers `GET` requests; it cannot scan,
fix or change anything.

## Who can see it

The default address is `0.0.0.0`, which listens on every network interface, and the report lists your
project's vulnerabilities. The command prints a warning when you do that. To restrict it:

- `--host 127.0.0.1` keeps it on this machine;
- `--token SECRET` (or `OPENCRAYSEC_DASHBOARD_TOKEN`) makes every request for your data carry the token,
  as `?token=SECRET` on the page or an `Authorization: Bearer SECRET` header. It is compared in constant
  time. Only `/healthz` and the page's own stylesheet and script (`/app.css`, `/app.js`, fixed files
  with no log data) answer without it.

There is no TLS: put it behind a reverse proxy if you expose it beyond a trusted network.

## What it shows

- Eight numbers: open findings, critical and high, exploited in the wild, used by your code, confirmed
  fixed, changes recorded, suspected code issues, scans.
- Charts: findings over time by severity, severity now, the riskiest packages, whether your code uses
  the vulnerable packages, and daily activity. Charts use Chart.js, loaded from a CDN at a pinned
  version and checked with an integrity hash; without network access the page shows tables instead.
- **What was changed, and why**: one card per recorded fix (summary, reason, lockfile changes, files,
  commands, commit, the advisories addressed with their references) and one per vulnerability a
  re-scan confirmed gone. "Recorded by AI" is the assistant's own account; "lockfile changes" are
  measured by comparing dependency snapshots; "verified by re-scan" means a later `verify_fix`
  confirmed the advisory was gone.
- The vulnerable dependencies (sortable, filterable, searchable) and the suspected code issues.
- A project selector when the log covers several projects.

## What is in the log

`log/events.jsonl` under the data directory (see [CONFIGURATION.md](CONFIGURATION.md)): one JSON object
per line with a time, the kind (`scan`, `scan_code`, `plan_fix`, `verify_fix`, `record_fix`), the
project path, the AI client's name and a payload. It holds package names, versions, advisory ids,
summaries, reference links and file paths. It never holds source code or secret values. Turn it off
with `--no-log` or `OPENCRAYSEC_LOG=off`; delete the file to start over. It is not rotated.

## The HTML export

`opencraysec report -o report.html [--workspace PATH]` writes a single file with the data embedded and
no server. It still loads Chart.js from the CDN when you open it. Share it with the same care as the
vulnerability list it contains.

## How it is protected

Only `GET` is served; request size, read and write times and the number of connections are bounded.
All text from advisories (third-party data) is inserted into the page with `textContent`, never as
HTML, and the data embedded in the export has `<` escaped. Responses carry a Content-Security-Policy
that allows scripts only from the server itself and the pinned Chart.js URL, plus `nosniff`,
`no-referrer`, `X-Frame-Options: DENY` and `no-store`.
