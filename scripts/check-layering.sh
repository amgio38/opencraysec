#!/bin/sh
# Enforce the dependency rules of the workspace.
#
# The crates form layers, and a crate may depend on workspace crates below it only:
#
#   core                                  (leaf: package model, versions, OSV matching)
#   runtime                               (leaf: runtime products, release and end-of-life data)
#   lockfile                              -> core
#   db                                    -> core, runtime
#   engine                                -> core, lockfile, db, runtime
#   log                                   -> core, lockfile, db, engine
#   web                                   -> log
#   mcp                                   -> core, db, engine, log
#   cli                                   -> core, lockfile, db, engine, log, web, mcp, runtime
#
# Rules:
#   R1  a crate depends on workspace crates from its own row above and no others, in any
#       dependency section (a dev-dependency that points the wrong way is still a cycle
#       waiting to happen);
#   R2  every dependency must come from crates.io or from this workspace: a `path`
#       dependency may only point at another crate in this workspace, and a `git`
#       dependency is never allowed. Dependencies on an external project make the build
#       depend on a checkout that is not published.
#
# Reads Cargo.toml directly (no cargo invocation), so it works on a fixture tree too.
# Usage: check-layering.sh [--root DIR]
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
while [ $# -gt 0 ]; do
	case "$1" in
		--root) root=$2; shift 2 ;;
		-h|--help) echo "usage: check-layering.sh [--root DIR]"; exit 0 ;;
		*) echo "unknown argument: $1" >&2; exit 2 ;;
	esac
done

crates_dir="$root/crates"
if [ ! -d "$crates_dir" ]; then
	echo "error: no crates/ directory under $root" >&2
	exit 2
fi

# What each crate may depend on inside the workspace. A crate that is not listed here may not
# depend on any workspace crate, which makes a new crate fail loudly until it is placed.
allowed() {
	case "$1" in
		opencraysec-core) echo "" ;;
		opencraysec-runtime) echo "" ;;
		opencraysec-lockfile) echo "opencraysec-core" ;;
		opencraysec-db) echo "opencraysec-core opencraysec-runtime" ;;
		opencraysec-engine) echo "opencraysec-core opencraysec-lockfile opencraysec-db opencraysec-runtime" ;;
		opencraysec-log) echo "opencraysec-core opencraysec-lockfile opencraysec-db opencraysec-engine" ;;
		opencraysec-web) echo "opencraysec-log" ;;
		opencraysec-mcp) echo "opencraysec-core opencraysec-db opencraysec-engine opencraysec-log" ;;
		opencraysec-cli) echo "opencraysec-core opencraysec-lockfile opencraysec-db opencraysec-engine opencraysec-log opencraysec-web opencraysec-mcp opencraysec-runtime" ;;
		*) echo "" ;;
	esac
}

# Emits "<package>\t<dependency>\t<section>\t<kind>\t<value>\t<crate dir>" for every
# dependency edge. `<kind>` is `path`, `git`, or empty; `<value>` is the path or URL.
edges() {
	for manifest in "$crates_dir"/*/Cargo.toml; do
		[ -f "$manifest" ] || continue
		awk '
			/^\[package\]/                    { section = "package"; next }
			/^\[dependencies\]/               { section = "dependencies"; next }
			/^\[dev-dependencies\]/           { section = "dev-dependencies"; next }
			/^\[build-dependencies\]/         { section = "build-dependencies"; next }
			/^\[/                             { section = ""; next }
			section == "package" && /^[[:space:]]*name[[:space:]]*=/ {
				name = $0; sub(/^[^=]*=[[:space:]]*/, "", name); gsub(/["[:space:]]/, "", name)
				next
			}
			(section == "dependencies" || section == "dev-dependencies" || section == "build-dependencies") \
				&& /^[[:space:]]*[A-Za-z0-9_.-]+[[:space:]]*=/ {
				line = $0
				dep = line; sub(/[[:space:]]*=.*/, "", dep); gsub(/^[[:space:]]+/, "", dep)
				sub(/\.workspace$/, "", dep)
				kind = ""; value = ""
				if (match(line, /path[[:space:]]*=[[:space:]]*"[^"]*"/)) {
					value = substr(line, RSTART, RLENGTH)
					sub(/^path[[:space:]]*=[[:space:]]*"/, "", value); sub(/"$/, "", value)
					kind = "path"
				} else if (match(line, /git[[:space:]]*=[[:space:]]*"[^"]*"/)) {
					value = substr(line, RSTART, RLENGTH)
					sub(/^git[[:space:]]*=[[:space:]]*"/, "", value); sub(/"$/, "", value)
					kind = "git"
				}
				crate_dir = FILENAME
				sub(/\/Cargo\.toml$/, "", crate_dir)
				printf "%s\t%s\t%s\t%s\t%s\t%s\n", name, dep, section, kind, value, crate_dir
			}
		' "$manifest"
	done
}

# Workspace crate names, taken from each package's own `name`.
workspace_names() {
	for manifest in "$crates_dir"/*/Cargo.toml; do
		[ -f "$manifest" ] || continue
		awk -F'=' '/^\[package\]/{p=1;next} /^\[/{p=0} p && $1 ~ /^[[:space:]]*name[[:space:]]*$/ {gsub(/["[:space:]]/,"",$2); print $2}' "$manifest"
	done
}

violations=0
report() {
	violations=$((violations + 1))
	printf 'layering violation: %s\n' "$1" >&2
}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM

ws=$(workspace_names | tr '\n' ' ')
edges > "$work/edges"

# R1: workspace dependencies stay inside the crate's own row.
while IFS='	' read -r pkg dep section kind value crate_dir; do
	[ -n "$dep" ] || continue
	case " $ws " in *" $dep "*) ;; *) continue ;; esac
	[ "$pkg" != "$dep" ] || continue
	case " $(allowed "$pkg") " in
		*" $dep "*) ;;
		*) echo "$pkg depends on $dep ($section)" ;;
	esac
done < "$work/edges" > "$work/r1"
while IFS= read -r line; do
	[ -n "$line" ] || continue
	report "$line (rule R1: a crate may only depend on the workspace crates below it; see the table in scripts/check-layering.sh)"
done < "$work/r1"

# R2: only crates.io or workspace crates.
while IFS='	' read -r pkg dep section kind value crate_dir; do
	[ -n "$dep" ] || continue
	case "$kind" in
		git)
			echo "$pkg -> $dep via git dependency $value ($section)" ;;
		path)
			case "$value" in
				/*) target=$value ;;
				*) target=$crate_dir/$value ;;
			esac
			resolved=$(realpath -m -- "$target" 2>/dev/null || printf '%s' "$target")
			case "$resolved" in
				"$crates_dir"/*)
					# Under crates/, but it still has to be a crate: a path into an empty
					# or foreign directory is not a workspace crate.
					[ -f "$resolved/Cargo.toml" ] || \
						echo "$pkg -> $dep via path dependency $value ($section, not a crate of this workspace)" ;;
				*) echo "$pkg -> $dep via path dependency $value ($section, outside the workspace)" ;;
			esac ;;
	esac
done < "$work/edges" > "$work/r2"
while IFS= read -r line; do
	[ -n "$line" ] || continue
	report "$line (rule R2: dependencies must be crates.io packages or crates of this workspace, not a path or git dependency on an external project)"
done < "$work/r2"

if [ "$violations" -ne 0 ]; then
	echo "layering check failed with $violations violation(s)" >&2
	exit 1
fi
echo "layering check passed"
