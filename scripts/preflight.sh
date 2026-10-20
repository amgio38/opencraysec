#!/usr/bin/env bash
# Pre-push gate: runs, locally, what CI runs, in the order CI runs it.
#
# Why this exists: an open-source project cannot keep going red on `main`. The rule this script
# encodes is simple: nothing is pushed until the same commands CI will run have passed on the
# exact tree being pushed. "I ran the relevant checks" is how a red CI gets published.
#
#   bash scripts/preflight.sh      # everything CI runs
#   make preflight
#   PREFLIGHT_QUICK=1 bash scripts/preflight.sh   # skips only the (slow) coverage gate
#
# Machine caps: the defaults keep a shared host usable; override with CARGO_BUILD_JOBS /
# RUST_TEST_THREADS.
#
# Keep the steps below in the same order as .github/workflows/ci.yml; a step added to CI belongs
# here too (scripts/check-preflight-parity.sh fails when they drift).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

[ "$#" -eq 0 ] || { echo "usage: preflight.sh" >&2; exit 2; }

export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}"
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-4}"

steps=0
step() {
	steps=$((steps + 1))
	printf '\n== [%s] %s\n' "$steps" "$1"
}

step "working tree is committed (what passes is what gets pushed)"
dirty="$(git -c core.fileMode=false status --porcelain --untracked-files=all || true)"
if [ -n "$dirty" ]; then
	echo "preflight: the tree has uncommitted or untracked files; commit or remove them first:" >&2
	printf '%s\n' "$dirty" | head -20 >&2
	exit 1
fi
echo "  clean"

# CI calls most scripts directly (`scripts/foo.sh`), so a script committed as 100644 fails there
# with exit code 126 while passing locally, where the working-tree file is executable. Check what
# git will actually store. doc-files.sh is sourced, not run.
step "scripts are executable in git"
nonexec="$(git ls-files -s -- 'scripts/*.sh' 'scripts/*.py' | awk '$1 != "100755" {print $4}' | grep -v '^scripts/doc-files\.sh$' || true)"
if [ -n "$nonexec" ]; then
	echo "preflight: these scripts are not executable in git (git update-index --chmod=+x):" >&2
	printf '%s\n' "$nonexec" >&2
	exit 1
fi
echo "  all executable"

step "lockfile and workspace version agree"
cargo metadata --locked --offline --format-version 1 >/dev/null
version="$(sed -n '/^\[workspace\.package\]/,/^\[/{s/^version *= *"\(.*\)"/\1/p}' Cargo.toml | head -1)"
[ -n "$version" ] || { echo "preflight: no [workspace.package] version found" >&2; exit 1; }
echo "  workspace version $version"

step "cargo fmt --all -- --check"
cargo fmt --all -- --check

step "cargo clippy (default features)"
cargo clippy --workspace --all-targets --locked -- -D warnings

step "cargo clippy (all features)"
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

# The full suite, not a selection: a change in one crate can break another crate's tests.
step "cargo test"
cargo test --workspace --locked

step "layering check"
scripts/check-layering.sh
scripts/check-layering.test.sh

step "license and release hygiene check"
scripts/check-licenses.sh

step "third-party licence inventory is current"
python3 scripts/gen-third-party-licenses.py --check

step "installer tests (network stubbed)"
scripts/install-sh.test.sh

step "cargo deny (licenses, bans, advisories)"
command -v cargo-deny >/dev/null 2>&1 ||
	{ echo "preflight: cargo-deny is not installed (cargo install cargo-deny --locked); CI runs it, so preflight must too" >&2; exit 1; }
cargo deny --all-features check licenses bans advisories sources

step "documentation check"
scripts/check-docs.sh

step "preflight matches CI"
scripts/check-preflight-parity.sh
scripts/check-preflight-parity.test.sh

step "line coverage (every crate and file at 90% or better)"
if [ "${PREFLIGHT_QUICK:-0}" = 1 ]; then
	echo "  skipped (PREFLIGHT_QUICK=1); CI still runs it"
else
	command -v cargo-llvm-cov >/dev/null 2>&1 ||
		{ echo "preflight: cargo-llvm-cov is not installed (cargo install cargo-llvm-cov --locked, and rustup component add llvm-tools-preview); CI runs it, so preflight must too" >&2; exit 1; }
	scripts/check-coverage.sh
fi

printf '\npreflight: all %s steps passed for %s at %s\n' "$steps" "$version" "$(git rev-parse --short HEAD)"
