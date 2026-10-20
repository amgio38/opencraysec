#!/usr/bin/env bash
# Line-coverage gate: every library crate must stay at or above its floor.
#
#   every crate: 90% line coverage, and no single source file below 90%.
#
# Needs cargo-llvm-cov and the llvm-tools component. Test code, mocks and main.rs are not counted.
set -euo pipefail
cd "$(dirname "$0")/.."
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-8}" RUST_TEST_THREADS="${RUST_TEST_THREADS:-4}"

json="$(mktemp)"
trap 'rm -f "$json"' EXIT
cargo llvm-cov --workspace --all-targets \
  --ignore-filename-regex '(/tests/|\.cargo/registry|main\.rs|testutil\.rs)' \
  --json --summary-only --output-path "$json" >/dev/null

python3 - "$json" <<'PY'
import json, sys, collections
FLOOR = 90
crates = ["core", "lockfile", "db", "engine", "log", "web", "mcp", "cli"]
data = json.load(open(sys.argv[1]))["data"][0]["files"]
tot = collections.defaultdict(lambda: [0, 0])
bad = False
for f in data:
    parts = f["filename"].split("/crates/")
    if len(parts) < 2:
        continue
    crate, rest = parts[1].split("/", 1)
    lines = f["summary"]["lines"]
    tot[crate][0] += lines["covered"]
    tot[crate][1] += lines["count"]
    if lines["count"] and lines["percent"] < FLOOR:
        print(f"  file below {FLOOR}%: crates/{parts[1]} {lines['percent']:.2f}%")
        bad = True
for crate in crates:
    covered, count = tot[crate]
    pct = 100.0 * covered / count if count else 0.0
    ok = pct >= FLOOR
    bad |= not ok
    print(f"{crate:9s} {pct:6.2f}%  (floor {FLOOR}%)  {'ok' if ok else 'BELOW FLOOR'}")
sys.exit(1 if bad else 0)
PY
