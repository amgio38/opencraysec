# Supported ecosystems and rules

## Lockfiles

`scan` finds lockfiles under the path you give (up to 8 directories deep, skipping `node_modules`,
`target`, `vendor`, `.git`, `dist`, `build`, virtualenvs and similar). A lockfile over 64 MiB is
reported as skipped rather than read.

| Ecosystem | Files read | Notes |
| --- | --- | --- |
| Rust (`crates.io`) | `Cargo.lock` | Registry crates only; path and git dependencies have no advisory identity. |
| JavaScript / TypeScript (`npm`) | `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock` (v1 and berry), `pnpm-lock.yaml` (v5 to v9) | Workspace packages and non-registry specs are skipped. |
| PHP (`Packagist`) | `composer.lock` | `packages` and `packages-dev`; `dev-` branch versions are skipped. |
| Go | `go.mod`, `go.sum` | `go.sum` is used only when there is no `go.mod` next to it, because it also lists versions that were never selected. |
| Python (`PyPI`) | `poetry.lock`, `uv.lock`, `Pipfile.lock`, `requirements*.txt` | `requirements*.txt` entries need an exact `==` pin; others (ranges, URLs, `-e` installs) cannot be matched and are reported as `unchecked` in the scan result (never silently dropped). A `-r other.txt` include is fine when that file is scanned too; `-c` constraint files add no dependencies. Local and editable packages are skipped. |

Every dependency found is recorded in the activity log's snapshot whatever `--ecosystem` narrows,
so a later `record_fix` can tell what really changed.

## SBOM files

`scan` and `scan_dependencies` also accept a CycloneDX or SPDX JSON file as the path, which is how to
check what has no lockfile you can read: a container image's inventory, or a list another tool wrote on
another machine.

- An SBOM is read only when it is named. A directory scan never picks one up, because an SBOM lying next
  to a project is not that project's dependency list.
- Components are matched by package URL (purl): `pkg:cargo`, `pkg:npm`, `pkg:composer`, `pkg:golang` and
  `pkg:pypi` become packages and go through the same matching as a lockfile. Anything else (`pkg:deb`,
  `pkg:apk`, container images, components with no purl or no version) is counted and listed under
  `unchecked` with its type. Nothing is dropped quietly.
- There is no source tree beside an SBOM, so usage evidence is `unknown` for these packages and their
  `source` reads `sbom:<file>`.
- Everything the tool exports as CycloneDX can be read back.

## Version ordering

Advisory ranges are evaluated with each ecosystem's own rules: semver for crates.io, npm and Go
(including Go pseudo-versions), a PEP 440 subset for PyPI (epochs, pre/post/dev releases, local
versions ignored), and Composer stability order for Packagist (`dev < alpha < beta < RC < stable <
patch`).

## Fix commands

`plan_fix` / `plan-fix` prints the lowest version that clears every fixable finding for a package
and the commands for the package manager the lockfile belongs to:

| Lockfile | Command |
| --- | --- |
| `Cargo.lock` | `cargo update -p NAME@FROM --precise TO` |
| `package-lock.json` | `npm install NAME@TO` |
| `yarn.lock` | `yarn upgrade NAME@TO` |
| `pnpm-lock.yaml` | `pnpm update NAME@TO -r` |
| `composer.lock` | `composer update NAME --with NAME:TO` |
| `go.mod` | `go get NAME@vTO` then `go mod tidy` |
| `poetry.lock` | `poetry add "NAME>=TO"` |
| `uv.lock` | `uv lock --upgrade-package NAME` |
| `Pipfile.lock` | `pipenv install "NAME>=TO"` |
| `requirements.txt` | `pip install "NAME>=TO"` and update the pin |

A step that crosses a major version (or a `0.x` minor version) is marked `needs_confirmation`.
opencraysec never runs these commands itself.

## Usage evidence (reachability)

For every finding, the project's own source below the lockfile's directory is read (dependency and
build directories skipped, files over 1 MiB and more than 20,000 files not read):

| Level | Meaning |
| --- | --- |
| `used_symbol` | Rust and Go: a file that uses the package also names a function the advisory lists as affected (matched by name). |
| `imported` | The package is imported or used. For packages where the advisory names no function, any use may matter. |
| `not_found` | The project's own code does not import it. Another dependency may still use it. |
| `unknown` | The evidence cannot be matched: PHP without `vendor/composer/installed.json`, or a Python import name that differs from the PyPI name. |

| Ecosystem | What is looked for |
| --- | --- |
| Go | `import` declarations (aliases and `/vN` suffixes handled), then `alias.Symbol` for the affected symbols, matched as a name on code with comments and string literals removed (not a call graph; a method call through another variable is not seen). |
| Rust | `use CRATE`, `extern crate CRATE` or `CRATE::` (dashes become underscores), then calls named like the affected functions. |
| JS / TS | `import ... from`, `import()` and `require()` of the package or a sub-path. |
| PHP | The package's PSR-0/PSR-4 namespaces from `vendor/composer/installed.json`. |
| Python | `import NAME` / `from NAME import` for the normalised distribution name. |

This is text-level evidence, not a call graph: it can miss dynamic use and cannot see use by other
dependencies. For Go, `govulncheck` gives a call-graph proof. `not_found` findings sort lower but
are never hidden; findings that are exploited in the wild always lead.

## Code rules (`scan-code`)

Pattern rules applied line by line to JS/TS (`js ts jsx tsx mjs cjs vue svelte`), Python, PHP, Go,
Rust, and, for the secret rules, common config files. Every hit is a **suspected** issue with a CWE;
secret hits never include the matched text. Silence a known-fine line with an `opencraysec:ignore`
comment on it or on the line above.

| Rule | Finds | CWE | Severity |
| --- | --- | --- | --- |
| `secret-private-key` | Private key block | CWE-798 | critical |
| `secret-aws-key` | AWS access key id | CWE-798 | high |
| `secret-github-token` | GitHub token | CWE-798 | high |
| `secret-slack-token` | Slack token | CWE-798 | high |
| `secret-assigned-literal` | `password`/`secret`/`api_key`/`token` assigned a literal (placeholders ignored) | CWE-798 | medium |
| `js-eval` | `eval(`, `new Function(` | CWE-95 | high |
| `js-exec-concat` | `exec`/`execSync` with a concatenated or templated string | CWE-78 | high |
| `js-innerhtml` | `innerHTML =`, `dangerouslySetInnerHTML`, `document.write(` | CWE-79 | medium |
| `js-tls-off` | `rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED=0` | CWE-295 | high |
| `py-eval` | `eval(` / `exec(` | CWE-95 | high |
| `py-pickle` | `pickle`/`marshal`/`dill` `load(s)` | CWE-502 | high |
| `py-yaml-load` | `yaml.load` without a safe loader | CWE-502 | high |
| `py-shell-true` | `subprocess.*(..., shell=True)` | CWE-78 | high |
| `py-os-system` | `os.system`, `os.popen` | CWE-78 | medium |
| `py-verify-false` | `verify=False` | CWE-295 | high |
| `py-sql-format` | `.execute(` with an f-string, `%` or `.format(` query | CWE-89 | high |
| `php-eval` | `eval(` | CWE-95 | high |
| `php-unserialize` | `unserialize($var)` | CWE-502 | high |
| `php-exec-var` | `exec`/`system`/`shell_exec`/... with a variable | CWE-78 | high |
| `php-include-request` | `include`/`require` of request data | CWE-98 | critical |
| `php-sql-request` | SQL query built with request data | CWE-89 | high |
| `php-extract-request` | `extract($_GET ...)` | CWE-621 | high |
| `php-curl-verify-off` | `CURLOPT_SSL_VERIFYPEER`/`HOST` off | CWE-295 | high |
| `go-tls-skip` | `InsecureSkipVerify: true` | CWE-295 | high |
| `go-shell` | `exec.Command("sh", "-c", ...)` | CWE-78 | medium |
| `go-sql-sprintf` | SQL built with `fmt.Sprintf` | CWE-89 | high |
| `go-weak-hash` | `md5`/`sha1` | CWE-327 | low |
| `rust-tls-off` | `danger_accept_invalid_certs(true)` | CWE-295 | high |
| `rust-shell` | `Command::new("sh")` | CWE-78 | medium |

Optional external scanners, run only when asked and installed:

- `gitleaks` (`--external gitleaks`): secret scanning; reports are redacted.
- `semgrep` (`--external semgrep --semgrep-config FILE`): needs a rules config. A local rules file
  runs offline; a registry pack such as `p/security-audit` downloads rules from semgrep.dev.

A missing scanner is reported in the output, not silently skipped.
