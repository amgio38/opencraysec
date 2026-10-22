# Contributing

Thanks for helping improve opencraysec. This project is Rust (edition 2024, MSRV 1.95) and builds with
Cargo.

## Layout

| Crate | What it owns |
| --- | --- |
| `opencraysec-core` | The package model, per-ecosystem version ordering, CVSS v3 scoring and OSV matching. No I/O. |
| `opencraysec-lockfile` | Finding lockfiles and parsing them (and SBOMs) into packages. |
| `opencraysec-runtime` | Runtime products: version detection, release and end-of-life verdicts, NVD answers. A leaf with no network. |
| `opencraysec-db` | The local store, dataset updates, the OSV and NVD clients, the CWE catalog, the release-data feeds. |
| `opencraysec-engine` | Scan, usage evidence, code rules, explain, fix planning and verification, report formats. |
| `opencraysec-log` | The activity log, dependency snapshots, report summaries. |
| `opencraysec-web` | The read-only dashboard server and the HTML export. |
| `opencraysec-mcp` | The MCP stdio server and its tools. |
| `opencraysec-cli` | The `opencraysec` binary. |

Dependencies point one way, from the shells down to the leaf:

```
core <- lockfile, db <- engine <- log <- web
core, db, engine, log <- mcp
everything <- cli
```

A crate may depend only on the workspace crates below it, in any dependency section. A dependency must
come from crates.io or from this workspace: a `path` dependency may only point at another crate in this
workspace, and a `git` dependency is never allowed. `scripts/check-layering.sh` enforces this (and
`scripts/check-layering.test.sh` proves it can fail); run it with `make layering`. For how the pieces fit
together and why, read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Building and testing

```sh
make check          # cargo check --workspace --all-targets
make fmt-check      # cargo fmt --all -- --check
make clippy         # cargo clippy --workspace --all-targets -- -D warnings
make test           # cargo test --workspace
make layering       # dependency-direction check
make licenses       # licence inventory vs Cargo.lock, release hygiene
make install-test   # the installer, with the network stubbed
make docs-check     # docs links, language, inline paths
make coverage       # every crate and every file at 90% line coverage or better
make ci             # fmt, clippy, tests, layering, docs, licences, installer, cargo deny
make preflight      # what CI runs, in CI order: run it before every push (docs/RELEASING.md)
```

`make release-static` builds a self-contained `dist/opencraysec`. It needs the
`x86_64-unknown-linux-musl` target and a musl C compiler and does not install them for you:

```sh
rustup target add x86_64-unknown-linux-musl
sudo apt install musl-tools
```

`make coverage` needs `cargo install cargo-llvm-cov --locked` and `rustup component add
llvm-tools-preview`. `make deny` needs `cargo install cargo-deny --locked`.

The machine this project is developed on may be shared, so builds are throttled (`JOBS=8`,
`RUST_TEST_THREADS=4`; override with `JOBS=...`). A plain `make test` runs the whole workspace.

## Test conventions

- **Never touch the real data directory or the network.** Tests use temporary directories and the mock
  HTTP server in `opencraysec_db::testutil` (behind the `testutil` feature), and pass endpoints through
  `Store::with_endpoints` instead of changing the process environment.
- **Test against real advisory shapes.** The matching logic has failed on exactly the awkward ones:
  pseudo-version fixes, several release branches, `last_affected`, `introduced: "0"`. When you change
  matching, run `opencraysec update` for a few ecosystems and compare with a native tool (`cargo audit`,
  `npm audit`, `composer audit`, `govulncheck`).
- **Fakes must not be more permissive than the real thing.** A mock that answers what a real service
  would refuse lets a bug pass.
- **Prove a test can fail.** When adding a test for a behaviour, break the behaviour temporarily and check
  the test goes red, then restore it.
- **Do not fix flakiness with sleeps.** Poll a condition with a timeout.
- **Coverage is a floor, not a goal.** The gate requires 90% line coverage per crate and per file; a test
  that exists only to move the number does not help.

## Adding an ecosystem or a lockfile format

1. Add the ecosystem to `crates/core/src/model.rs` (OSV name, aliases, name normalisation) and its
   ordering to `crates/core/src/version.rs`.
2. Add a parser in `crates/lockfile` and register the file name.
3. Add the fix commands in `crates/engine/src/fix.rs`, the purl in `crates/engine/src/report.rs` and
   usage evidence in `crates/engine/src/reach.rs`.
4. Update [docs/LANGUAGES.md](docs/LANGUAGES.md) and the README, and add the new OSV ecosystem name to
   `crates/db`.

## Submitting changes

- Keep changes scoped to one area; update the docs a change affects (`docs/`, `README.md`, and
  `docs/TOOLS.md` for MCP tools).
- Run `make preflight` before sending a change; CI runs the same list.
- Add a line to `CHANGELOG.md` under *Unreleased* for anything a user can see.
- Write commit messages in English that say what changed and why. They do not carry internal ticket
  numbers.
- No secrets, personal paths or unpublished vulnerability details in code, tests, docs or commit
  messages.
- Comments and documentation are in English (`scripts/check-docs.sh` enforces it).
- Never commit a vulnerability you found in another project to a public issue or PR before it is fixed
  and disclosed.

## Security issues

Report them privately; see [SECURITY.md](SECURITY.md).

## Code of conduct

By taking part you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
