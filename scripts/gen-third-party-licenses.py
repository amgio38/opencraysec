#!/usr/bin/env python3
"""Regenerate licenses/deps.tsv and THIRD-PARTY-LICENSES.md from `cargo metadata`.

Usage (repository root):  python3 scripts/gen-third-party-licenses.py [--check]

Every crates.io package in Cargo.lock is listed, so the inventory can be checked against the
lockfile exactly. The Markdown table marks the ones reachable from the workspace members through
normal (non-dev, non-build) dependency edges: those are compiled into the binary. For every
package the script records the licence expression the crate declares and the licence this
project relies on ("elected"):

  * `A OR B`   one of the alternatives is taken, in the order MIT, Apache-2.0, ISC,
               BSD-3-Clause, Zlib, Unicode-3.0, 0BSD, Unlicense, CDLA-Permissive-2.0;
  * `A AND B`  every part applies, so every part is recorded;
  * `WITH LLVM-exception` is recorded as the base licence (the exception only widens it).

--check regenerates in memory and fails when the files on disk differ, so CI can tell a
stale inventory from a current one without touching the tree.
"""
import json
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PREFERENCE = ["MIT", "Apache-2.0", "ISC", "BSD-3-Clause", "Zlib", "Unicode-3.0", "0BSD",
              "Unlicense", "CDLA-Permissive-2.0"]
TEXT_DIR = ROOT / "licenses"


def metadata():
    out = subprocess.check_output(
        ["cargo", "metadata", "--format-version", "1", "--locked", "--offline"],
        cwd=ROOT, stderr=subprocess.DEVNULL)
    return json.loads(out)


def all_packages(meta):
    """Every package in the resolve graph except workspace members, and the set that is compiled in."""
    by_id = {p["id"]: p for p in meta["packages"]}
    members = set(meta["workspace_members"])
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    seen, stack = set(), list(members)
    while stack:
        i = stack.pop()
        if i in seen:
            continue
        seen.add(i)
        for dep in nodes[i]["deps"]:
            if any(k.get("kind") is None for k in dep["dep_kinds"]):
                stack.append(dep["pkg"])
    everything = sorted((by_id[i] for i in nodes if i not in members), key=lambda p: (p["name"], p["version"]))
    compiled = {(by_id[i]["name"], by_id[i]["version"]) for i in seen if i not in members}
    return everything, compiled


def tokenize(expr):
    out, cur = [], ""
    for ch in expr.replace("/", " OR "):
        if ch in "()":
            if cur.strip():
                out.append(cur.strip())
            out.append(ch)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    words = []
    for chunk in out:
        words.extend([chunk] if chunk in "()" else chunk.split())
    return words


def parse(words):
    """Returns a tree: ('id', name) | ('and', [..]) | ('or', [..])."""
    pos = 0

    def atom():
        nonlocal pos
        tok = words[pos]
        if tok == "(":
            pos += 1
            node = or_expr()
            pos += 1  # ")"
            return node
        pos += 1
        node = ("id", tok)
        if pos + 1 < len(words) and words[pos] == "WITH":
            pos += 2  # the exception only widens the base licence
        return node

    def and_expr():
        nonlocal pos
        items = [atom()]
        while pos < len(words) and words[pos] == "AND":
            pos += 1
            items.append(atom())
        return items[0] if len(items) == 1 else ("and", items)

    def or_expr():
        nonlocal pos
        items = [and_expr()]
        while pos < len(words) and words[pos] == "OR":
            pos += 1
            items.append(and_expr())
        return items[0] if len(items) == 1 else ("or", items)

    return or_expr()


def rank(node):
    names = ids(node)
    return max(PREFERENCE.index(n) if n in PREFERENCE else len(PREFERENCE) for n in names)


def ids(node):
    if node[0] == "id":
        return [node[1]]
    return [n for child in node[1] for n in ids(child)]


def elect(node):
    if node[0] == "id":
        return [node[1]]
    if node[0] == "and":
        out = []
        for child in node[1]:
            for n in elect(child):
                if n not in out:
                    out.append(n)
        return out
    return min((elect(child) for child in node[1]), key=lambda e: (rank(("and", [("id", n) for n in e])), len(e)))


def row(pkg):
    expr = (pkg.get("license") or "").strip()
    if not expr:
        return pkg["name"], pkg["version"], "unknown", "unknown", ""
    elected = elect(parse(tokenize(expr)))
    texts = ",".join(f"licenses/{n}.txt" for n in elected)
    return pkg["name"], pkg["version"], expr, " AND ".join(elected), texts


def render(rows, repos, compiled):
    tsv = "# name\tversion\tlicense-expression\telected\ttexts-required\n"
    tsv += "".join("\t".join(r) + "\n" for r in rows)
    groups = defaultdict(list)
    for r in rows:
        groups[r[3]].append(r)
    md = ["# Third-party licenses", "",
          "<!-- Generated by scripts/gen-third-party-licenses.py; do not edit by hand. -->", "",
          "opencraysec is released under the MIT License (see [LICENSE](LICENSE)). The binary is built",
          "from the crates.io packages below. This file lists each one, the licence it declares and the",
          "licence this project relies on. The full texts are in [`licenses/`](licenses/), and a copy",
          "of this file and of those texts is installed next to the binary (`share/doc/opencraysec`).", "",
          "The same inventory in machine-readable form is [`licenses/deps.tsv`](licenses/deps.tsv); ",
          "`scripts/check-licenses.sh` fails when it disagrees with `Cargo.lock`.", "",
          "Every crate in `Cargo.lock` is listed, %d in total. The last column says whether the crate is" % len(rows),
          "compiled into the binary (reachable through normal dependency edges from the workspace crates);",
          "the others are development or build-time tools that are not distributed.", "",
          "## Summary", "", "| Licence relied on | Packages |", "| --- | ---: |"]
    for name in sorted(groups):
        md.append(f"| {name} | {len(groups[name])} |")
    md += ["", "## Packages", "", "| Package | Version | Declares | Relied on | In the binary | Repository |", "| --- | --- | --- | --- | --- | --- |"]
    for r in rows:
        repo = repos.get((r[0], r[1])) or ""
        link = f"<{repo}>" if repo else ""
        inside = "yes" if (r[0], r[1]) in compiled else "no"
        md.append(f"| {r[0]} | {r[1]} | {r[2].replace('|', '/')} | {r[3]} | {inside} | {link} |")
    md.append("")
    return tsv, "\n".join(md)


def main():
    meta = metadata()
    pkgs, compiled = all_packages(meta)
    rows = [row(p) for p in pkgs]
    repos = {(p["name"], p["version"]): p.get("repository") for p in pkgs}
    tsv, md = render(rows, repos, compiled)
    missing = sorted({t for r in rows for t in r[4].split(",") if t and not (ROOT / t).is_file()})
    if missing:
        sys.exit("missing licence texts: " + ", ".join(missing))
    unknown = [f"{r[0]} {r[1]}" for r in rows if r[2] == "unknown"]
    if unknown:
        sys.exit("packages without a declared licence: " + ", ".join(unknown))
    targets = {ROOT / "licenses" / "deps.tsv": tsv, ROOT / "THIRD-PARTY-LICENSES.md": md}
    if "--check" in sys.argv[1:]:
        stale = [str(p.relative_to(ROOT)) for p, text in targets.items()
                 if not p.is_file() or p.read_text(encoding="utf-8") != text]
        if stale:
            sys.exit("out of date (run scripts/gen-third-party-licenses.py): " + ", ".join(stale))
        print("third-party licence inventory is current")
        return
    for path, text in targets.items():
        path.write_text(text, encoding="utf-8")
    print(f"wrote {len(rows)} packages")


if __name__ == "__main__":
    main()
