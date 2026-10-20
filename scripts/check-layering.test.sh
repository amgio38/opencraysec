#!/bin/sh
# Tests for check-layering.sh: the real tree passes, and each kind of violation is refused
# by name (a gate that cannot go red proves nothing).
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
checker="$here/check-layering.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM

fail=0
ok() { echo "  ok: $1"; }
bad() { echo "  FAIL: $1" >&2; fail=1; }

# A minimal fixture workspace: <crate> <dependency lines...>
mk() {
	root=$1
	shift
	mkdir -p "$root/crates"
	while [ $# -gt 0 ]; do
		name=$1 deps=$2
		shift 2
		mkdir -p "$root/crates/${name#opencraysec-}"
		{
			printf '[package]\nname = "%s"\nversion = "0.1.0"\n\n[dependencies]\n' "$name"
			printf '%b' "$deps"
		} > "$root/crates/${name#opencraysec-}/Cargo.toml"
	done
}

if sh "$checker" >/dev/null 2>&1; then
	ok "the real workspace passes"
else
	bad "the real workspace does not pass its own layering check"
fi

mk "$work/clean" \
	opencraysec-core 'serde.workspace = true\n' \
	opencraysec-db 'opencraysec-core.workspace = true\n' \
	opencraysec-engine 'opencraysec-core.workspace = true\nopencraysec-db.workspace = true\n'
if sh "$checker" --root "$work/clean" >/dev/null 2>&1; then
	ok "a downward dependency is accepted"
else
	bad "a clean fixture was refused"
fi

mk "$work/up" \
	opencraysec-core 'opencraysec-engine.workspace = true\n' \
	opencraysec-engine 'opencraysec-core.workspace = true\n'
if sh "$checker" --root "$work/up" >"$work/out" 2>&1; then
	bad "core depending on engine was accepted"
elif grep -q 'opencraysec-core depends on opencraysec-engine' "$work/out"; then
	ok "an upward dependency is named and refused"
else
	bad "refused, but without naming the edge"
fi

mk "$work/sideways" \
	opencraysec-core '' \
	opencraysec-db 'opencraysec-core.workspace = true\n' \
	opencraysec-lockfile 'opencraysec-db.workspace = true\n'
if sh "$checker" --root "$work/sideways" >"$work/out" 2>&1; then
	bad "lockfile depending on db was accepted"
elif grep -q 'opencraysec-lockfile depends on opencraysec-db' "$work/out"; then
	ok "a sideways dependency is refused"
else
	bad "sideways case refused without naming the edge"
fi

mk "$work/devup" \
	opencraysec-core '' \
	opencraysec-db 'opencraysec-core.workspace = true\n'
printf '\n[dev-dependencies]\nopencraysec-cli.workspace = true\n' >> "$work/devup/crates/db/Cargo.toml"
mkdir -p "$work/devup/crates/cli"
printf '[package]\nname = "opencraysec-cli"\nversion = "0.1.0"\n' > "$work/devup/crates/cli/Cargo.toml"
if sh "$checker" --root "$work/devup" >"$work/out" 2>&1; then
	bad "a dev-dependency pointing upward was accepted"
elif grep -q 'opencraysec-db depends on opencraysec-cli (dev-dependencies)' "$work/out"; then
	ok "dev-dependencies are held to the same rule"
else
	bad "dev-dependency case refused without naming the edge"
fi

mk "$work/git" opencraysec-core 'thing = { git = "https://example.com/thing" }\n'
if sh "$checker" --root "$work/git" >"$work/out" 2>&1; then
	bad "a git dependency was accepted"
elif grep -q 'git dependency' "$work/out"; then
	ok "a git dependency is refused"
else
	bad "git case refused without saying why"
fi

mk "$work/outside" opencraysec-core 'thing = { path = "../../../elsewhere" }\n'
if sh "$checker" --root "$work/outside" >"$work/out" 2>&1; then
	bad "a path dependency outside the workspace was accepted"
elif grep -q 'outside the workspace' "$work/out"; then
	ok "a path dependency outside the workspace is refused"
else
	bad "path case refused without saying why"
fi

if sh "$checker" --root "$work/missing-dir" >/dev/null 2>&1; then
	bad "a root without crates/ was accepted"
else
	ok "a root without crates/ is an error"
fi

[ "$fail" -eq 0 ] || { echo "check-layering.test: FAILED" >&2; exit 1; }
echo "check-layering.test: passed"
