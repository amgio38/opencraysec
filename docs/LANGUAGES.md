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
| GitHub Actions | `.github/workflows/*.yml`, `.github/workflows/*.yaml` | The `uses: owner/repo@ref` lines, matched by repository. See [GitHub Actions](#github-actions-workflows). |
| Python (`PyPI`) | `poetry.lock`, `uv.lock`, `Pipfile.lock`, `requirements*.txt` | `requirements*.txt` entries need an exact `==` pin; others (ranges, URLs, `-e` installs) cannot be matched and are reported as `unchecked` in the scan result (never silently dropped). A `-r other.txt` include is fine when that file is scanned too; `-c` constraint files add no dependencies. Local and editable packages are skipped. |

Every dependency found is recorded in the activity log's snapshot whatever `--ecosystem` narrows,
so a later `record_fix` can tell what really changed.

## Install-time code

Some packages run code on the machine that installs them (an npm `postinstall` script, for example). It
is how most native modules build, and it is also how a malicious package runs, so `scan` lists them
apart from the vulnerabilities. It is not a vulnerability and never changes `--fail-on`.

The list comes from the lockfile itself, never from running or downloading anything, and only some
lockfiles record it:

| Lockfile | Install scripts |
| --- | --- |
| `package-lock.json` (lockfileVersion 2 and 3) | Listed: the entry says `hasInstallScript`. |
| `package-lock.json` (lockfileVersion 1) | **Cannot be told.** Its entries carry no install-script marker; regenerate it with a current npm. |
| `pnpm-lock.yaml` (lockfileVersion 5 and 6) | Listed: the entry says `requiresBuild: true`. |
| `pnpm-lock.yaml` (lockfileVersion 9 and later) | **Cannot be told.** pnpm's published lockfile types (`@pnpm/lockfile-types`) declare `requiresBuild` up to version 5.1.1 (2023) and no longer from version 6.0.0 (April 2024, the week before pnpm 9, which introduced lockfileVersion 9), so a missing marker means nothing. A file with no version line is treated the same way. |
| `yarn.lock`, `Cargo.lock`, `composer.lock`, `go.mod`, the Python lockfiles, an SBOM | **Cannot be told.** This scan does not read it from these formats, and it does not guess. `Cargo.lock` in particular does not say which crates have a `build.rs` or are procedural macros. |

A lockfile that cannot say is named in the report; its packages are not "free of install scripts", they
are unknown. "None" is only claimed for lockfiles that do record it. The same list appears in
`scan --format json` (`install_scripts`, `install_scripts_checked`, `install_scripts_unknown`), in SARIF
(run properties) and in CycloneDX (a property on each such component).

To stop them running, install with `npm ci --ignore-scripts`. opencraysec never changes your project or
your npm settings.

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

## GitHub Actions workflows

A workflow is code that runs with your repository's token, often on text that anyone can send: an issue,
a pull request, a branch name. Two things are checked, and they are kept apart.

**The actions it uses, from published data.** Each `uses: owner/repo@ref` is an action, and an action
is a dependency. A full release tag (`v4.1.2`) is matched against the
[OSV](https://osv.dev) `GitHub Actions` data, which republishes the GitHub Advisory Database entries for
actions (see [DATA-SOURCES.md](DATA-SOURCES.md#github-actions)). The match is by repository, so
`github/codeql-action/analyze@v3.25.0` is checked as `github/codeql-action` 3.25.0: a folder action and a
reusable workflow share the releases of their repository. An advisory that names only a subfolder is
missed. Names are compared without regard to case, as GitHub does.

Three kinds of reference name no release, so they **cannot be checked**, and each is listed in the report
(`actions not checked ...`), never dropped:

| Reference | Why it cannot be checked |
| --- | --- |
| A full commit SHA (`@0123...`) | It is the safest way to pin an action, but it names no version. |
| A floating tag (`@v4`, `@v4.1`) | It follows the newest release of its line, so it names no one release. |
| A branch (`@main`) | It moves with every push. |

These are kept out of the "unchecked" dependencies that make a result *incomplete*: pinning by SHA is the
recommended practice (GitHub's guide: "Pin references to actions to a commit SHA in your workflow files"),
and a project that follows it must not be told its scan is incomplete for that reason. They are disclosed
instead, in the text report, in the JSON, SARIF and CycloneDX notes, in the activity log, and in the
notes at the top of the dashboard and the HTML export. Local actions (`./...`) and container images
(`docker://...`) are not read.

**Dangerous patterns, from rules.** Five rules look at what a workflow does. They read one line at a time
and do not parse YAML, so every hit is **suspected**. Each names the entry of the
[OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/) that fits it
best (the list shows no edition year, so none is given); that choice of entry is ours.

| Rule | What it rests on | Known false positives and misses |
| --- | --- | --- |
| `gha-script-injection` (CWE-78, CICD-SEC-4) | GitHub Security Lab's article on [untrusted input](https://securitylab.github.com/resources/github-actions-untrusted-input/) lists the event data that an attacker can control, and recommends passing such a value to the script through an intermediate environment variable instead of writing the expression into the script. The rule uses that list of contexts: `github.event.issue.title` and `.body`, `github.event.pull_request.title`, `.body`, `.head.ref`, `.head.label` and `.head.repo.default_branch`, `github.event.comment.body`, `github.event.review.body`, `github.event.pages.*.page_name`, `github.event.commits.*.message`, `.author.email` and `.author.name`, `github.event.head_commit.message`, `.author.email` and `.author.name`, and `github.head_ref`. | Only a `run:` script is read, so the same expression in an `actions/github-script` script is missed. An expression wrapped in a function (`contains(...)`) is not matched, and neither is a value moved into a variable first. The finding names the context, never the rest of the line. |
| `gha-pwn-request` (CWE-829, CICD-SEC-4) | The [pwn requests](https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/) article explains that a `pull_request_target` workflow runs with the target repository's write access and secrets, unlike a plain `pull_request` workflow, so building or running the pull request's own code there hands that access to whoever wrote the pull request. The rule needs a `pull_request_target` or `workflow_run` trigger, an `actions/checkout` step, and a `ref:` or `repository:` that points at the pull request's head. | The trigger is found by its name in the file, outside a comment. A checkout of the pull request that is followed by no code from it is still reported. A checkout done any other way is missed. |
| `gha-workflow-run-artifact` (CWE-829, CICD-SEC-4) | The same article says that an artifact built from an untrusted pull request is itself untrusted, and that using it in the privileged `workflow_run` context is a vulnerability. | It cannot tell whether the artifact is only read as data, which is safe. Medium for that reason. Only `actions/download-artifact` and `dawidd6/action-download-artifact` are known. |
| `gha-unpinned-action` (CWE-1357, CICD-SEC-3) | GitHub's [security hardening guide](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions): "Pin references to actions to a commit SHA in your workflow files", which "helps mitigate the risk of a bad actor adding a backdoor to the action's repository". | Reported for every action by a tag or branch, including GitHub's own, so a workflow with many actions has many low findings. A project that locks its workflow dependencies some other way is still reported. |
| `gha-broad-permissions` (CWE-250, CICD-SEC-5) | The same guide: "make sure that the `GITHUB_TOKEN` is granted the minimum required permissions". | Only the literal `permissions: write-all`. A workflow with no `permissions:` key, or with a long list of write permissions, is not reported. |

The short quotations from GitHub's security hardening guide in this section are from GitHub's documentation, which is published under
[CC BY 4.0](https://github.com/github/docs/blob/main/LICENSE); the GitHub Security Lab articles are
summarised in our own words, because their pages state no licence.

The rules read only the files in `.github/workflows`. Put `opencraysec:ignore` on a line, or alone in a
comment on the line above, to silence a rule there. The ordinary secret rules of `scan-code` read these
files too.

## Rules for code that talks to an AI model

Three groups of rules in `scan-code` look at code that calls an AI provider. They are pattern matches on
one line, so every hit is **suspected**, and each of them misses code that is split across lines or
statements. `scan-agent-config` uses the same key rules for the files it reads.

**Provider keys.** A key is reported by the prefix its provider documents. The minimum lengths are this
project's own, chosen so that a prefix in ordinary text does not match; the providers do not document one.

| Provider | Prefix, and where it is documented | Rule |
| --- | --- | --- |
| Anthropic | `sk-ant-` for every key, with `sk-ant-api03-` for an API key, `sk-ant-admin01-` for an Admin API key and `sk-ant-api01-` for an Enterprise key: [Get your Claude API key](https://platform.claude.com/docs/en/get-api-key), [Create an Admin API key](https://platform.claude.com/docs/en/manage-claude/admin-api-keys) | `secret-anthropic-key` |
| Hugging Face | `hf_`, shown in the [User access tokens](https://huggingface.co/docs/hub/security-tokens) page's own example | `secret-huggingface-token` |
| Google | `AIza` followed by 35 characters, the shape of the example key in [API keys](https://docs.cloud.google.com/docs/authentication/api-keys); Google does not say every key looks like that | `secret-google-api-key` |
| OpenAI | **No rule.** OpenAI's documentation pages could not be read, and community posts are not a documented format | none |

`secret-google-api-key` is medium because a Firebase web key has the same shape and is meant to be in
client code, while a Gemini or Cloud key is not. Look at what the key is allowed to do before you act.
A line that says it is an example (`example`, `your`, `_here`, `placeholder`, ...) is skipped, like
every secret rule.

A test file that holds a key-shaped value is reported like any other file; put `opencraysec:ignore` on
the line when it is a fixture.

**A model's answer used as code.** The text of an answer, taken from the documented response shapes of
the common SDKs (`choices[0].message.content`, `choices[0].text`, `content[0].text`, `.output_text`,
and the dictionary form of the same JSON in Python), that is passed on the same line to `eval`, a shell
call, a SQL call or an HTML sink. This is OWASP LLM05:2025, Improper Output Handling. It misses an
answer kept in a variable first, a renamed field, another SDK's shape, and Go, Rust and PHP (there is no
rule for them). It does not match `.text` or `.text()` alone, because that is also the body of an HTTP
response. On a line where one of these rules matches, the ordinary rule for the same weakness (`js-eval`,
`py-eval`, `js-exec-concat`, `py-shell-true`, `py-os-system`, `py-sql-format`, `js-innerhtml`) is not
repeated; a different weakness on that line still is.

**User input in a prompt.** A variable whose name contains `prompt`, or a `system` message, built by
putting a request's input into a string with a template literal, an f-string, `+` or `.format(`. The
input is recognised by name: `req.body`, `req.query`, `req.params`, `request.json`, `request.form`,
`user_input`, `userMessage`, `input(`, `sys.argv` and the like. This is OWASP LLM01:2025, Prompt
Injection. Many products do put the user's words into a prompt on purpose, so `ai-prompt-concat` is low
and `ai-system-prompt-user-input` (the user's words inside the system message) is medium. A prompt built
in another function, or from input that is not named like one, is missed. There is no rule for Go, Rust or PHP.

The OWASP entries are from the [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/)
(2025). A leaked key is not one of the ten, so the key rules carry only their CWE.

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
| A workflow | No command: edit `uses: OWNER/REPO@...` to the tag or, better, the commit SHA of the fixed release |

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
comment on it, or alone in a comment on the line above (`//`, `#`, `/* */` or `<!-- -->`). A comment
that says anything else as well does not count. One rule is shared by `scan-code`, the workflow rules and
`scan-agent-config`.

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
| `secret-anthropic-key` | Anthropic API key (`sk-ant-api03-`, `sk-ant-admin01-`, `sk-ant-api01-`) | CWE-798 | high |
| `secret-huggingface-token` | Hugging Face access token (`hf_`) | CWE-798 | high |
| `secret-google-api-key` | Google API key (`AIza` and 35 more characters) | CWE-798 | medium |
| `ai-output-eval` | A model's answer inside `eval(` / `new Function(` (JS, TS) or `eval(` / `exec(` (Python), on the same line | CWE-95 | high |
| `ai-output-shell` | A model's answer inside a `child_process` call or `exec(` (JS, TS), or `os.system`, `subprocess.*`, `Popen` (Python) | CWE-78 | high |
| `ai-output-sql` | A model's answer inside `.query(` / `.execute(` / `.raw(` | CWE-89 | high |
| `ai-output-html` | A model's answer assigned to `innerHTML` / `outerHTML`, or inside `dangerouslySetInnerHTML`, `document.write(` (JS, TS) | CWE-79 | medium |
| `gha-script-injection` | In a workflow, a `run:` script with `${{ github.event.issue.title }}`, a pull request title or body, a branch name, a commit message or the like pasted into it | CWE-78 | high |
| `gha-pwn-request` | A `pull_request_target` or `workflow_run` workflow that checks out the pull request's own code | CWE-829 | high |
| `gha-workflow-run-artifact` | A `workflow_run` workflow that downloads an artifact | CWE-829 | medium |
| `gha-unpinned-action` | `uses:` an action by a tag or a branch instead of a full commit SHA | CWE-1357 | low |
| `gha-broad-permissions` | `permissions: write-all` | CWE-250 | medium |
| `ai-prompt-concat` | A variable named for a prompt built by putting `req.body`, `req.query`, `user_input`, `input(` and the like into a string (JS, TS, Python) | CWE-1427 | low |
| `ai-system-prompt-user-input` | A `role: "system"` message whose content is built from the same request input | CWE-1427 | medium |
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
