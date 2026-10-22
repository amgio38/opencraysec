//! Source-level usage evidence for vulnerable dependencies.
//!
//! This answers "does this project's own code import the vulnerable package, and for Rust and Go
//! does it name an affected function?" It is a text-level check, not a call graph: it can miss
//! dynamic use and it cannot see use by *other* dependencies. Every result says so.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use opencraysec_core::osv::SymbolRef;
use opencraysec_core::{Ecosystem, Finding, Reachability};
use regex::Regex;

const SKIP_DIRS: &[&str] = &[
    "node_modules",
    "target",
    "vendor",
    ".git",
    "dist",
    "build",
    ".venv",
    "venv",
    "__pycache__",
    ".tox",
    ".next",
    "third_party",
];
const MAX_FILES: usize = 20_000;
const MAX_FILE_BYTES: u64 = 1024 * 1024;
const MAX_EVIDENCE: usize = 3;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Lang {
    Go,
    Rust,
    Js,
    Php,
    Python,
}

fn lang_of(path: &Path) -> Option<Lang> {
    match path.extension()?.to_str()? {
        "go" => Some(Lang::Go),
        "rs" => Some(Lang::Rust),
        "js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx" | "mts" | "cts" | "vue" | "svelte" => {
            Some(Lang::Js)
        }
        "php" => Some(Lang::Php),
        "py" => Some(Lang::Python),
        _ => None,
    }
}

struct SrcFile {
    rel: String,
    lang: Lang,
    text: String,
}

struct Tree {
    files: Vec<SrcFile>,
    truncated: bool,
    dir: PathBuf,
}

fn walk(dir: &Path, base: &Path, depth: usize, out: &mut Tree) {
    if depth > 12 || out.truncated {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = entries.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let Ok(ft) = e.file_type() else { continue };
        if ft.is_symlink() {
            continue;
        }
        let path = e.path();
        let name = e.file_name().to_string_lossy().into_owned();
        if ft.is_dir() {
            if !SKIP_DIRS.contains(&name.as_str()) && !name.starts_with('.') {
                walk(&path, base, depth + 1, out);
            }
        } else if let Some(lang) = lang_of(&path) {
            if out.files.len() >= MAX_FILES {
                out.truncated = true;
                return;
            }
            if e.metadata()
                .map(|m| m.len() > MAX_FILE_BYTES)
                .unwrap_or(true)
            {
                continue;
            }
            if let Ok(text) = fs::read_to_string(&path) {
                let rel = opencraysec_lockfile::relative_name(&path, base);
                out.files.push(SrcFile { rel, lang, text });
            }
        }
    }
}

fn load(dir: &Path, base: &Path) -> Tree {
    let mut t = Tree {
        files: Vec::new(),
        truncated: false,
        dir: dir.to_path_buf(),
    };
    walk(dir, base, 0, &mut t);
    t
}

fn result(level: &str, evidence: Vec<String>, note: impl Into<String>) -> Reachability {
    Reachability {
        level: level.into(),
        evidence,
        note: note.into(),
    }
}

const TRANSITIVE: &str =
    "Only this project's own source was checked; another dependency may still use it.";

/// Go: import paths of one file, as (alias, path, line).
fn go_imports(text: &str) -> Vec<(Option<String>, String, usize)> {
    let mut out = Vec::new();
    let mut in_block = false;
    for (i, raw) in text.lines().enumerate() {
        let line = raw.split("//").next().unwrap_or("").trim();
        let spec = if in_block {
            if line.starts_with(')') {
                in_block = false;
                continue;
            }
            line
        } else if let Some(rest) = line.strip_prefix("import") {
            let rest = rest.trim();
            if rest.starts_with('(') {
                in_block = true;
                continue;
            }
            rest
        } else {
            continue;
        };
        let (alias, quoted) = match spec.split_once('"') {
            Some((a, q)) => (a.trim(), q),
            None => continue,
        };
        let Some(path) = quoted.split('"').next() else {
            continue;
        };
        let alias = (!alias.is_empty() && alias != "_" && alias != ".").then(|| alias.to_string());
        out.push((alias, path.to_string(), i + 1));
    }
    out
}

fn go_name_candidates(path: &str, alias: Option<&str>) -> Vec<String> {
    if let Some(a) = alias {
        return vec![a.to_string()];
    }
    let mut parts: Vec<&str> = path.split('/').collect();
    let mut out = Vec::new();
    if let Some(last) = parts.pop() {
        let is_version = last.len() > 1
            && last.starts_with('v')
            && last[1..].chars().all(|c| c.is_ascii_digit());
        let base = if is_version {
            parts.pop().unwrap_or(last)
        } else {
            last
        };
        let base = base.split(".v").next().unwrap_or(base);
        out.push(base.replace('-', "_"));
        out.push(base.trim_start_matches("go-").replace('-', "_"));
    }
    out.dedup();
    out
}

/// Go source with comments and the contents of string, raw-string and rune literals replaced by
/// spaces, one entry per line, so `rand.Perm` in a comment or a string is not taken for a call.
/// Line numbers and columns are preserved.
fn go_code_lines(text: &str) -> Vec<String> {
    #[derive(Clone, Copy, PartialEq)]
    enum S {
        Code,
        Line,
        Block,
        Str,
        Raw,
        Rune,
    }
    let mut st = S::Code;
    let mut out = Vec::new();
    for line in text.lines() {
        let chars: Vec<char> = line.chars().collect();
        let mut buf = String::with_capacity(line.len());
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            let next = chars.get(i + 1).copied();
            let (keep, advance) = match st {
                S::Code => match (c, next) {
                    ('/', Some('/')) => {
                        st = S::Line;
                        (' ', 2)
                    }
                    ('/', Some('*')) => {
                        st = S::Block;
                        (' ', 2)
                    }
                    ('"', _) => {
                        st = S::Str;
                        (' ', 1)
                    }
                    ('`', _) => {
                        st = S::Raw;
                        (' ', 1)
                    }
                    ('\'', _) => {
                        st = S::Rune;
                        (' ', 1)
                    }
                    _ => (c, 1),
                },
                S::Line => (' ', 1),
                S::Block => {
                    if c == '*' && next == Some('/') {
                        st = S::Code;
                        (' ', 2)
                    } else {
                        (' ', 1)
                    }
                }
                S::Str | S::Rune => {
                    let close = if st == S::Str { '"' } else { '\'' };
                    if c == '\\' {
                        (' ', 2)
                    } else {
                        if c == close {
                            st = S::Code;
                        }
                        (' ', 1)
                    }
                }
                S::Raw => {
                    if c == '`' {
                        st = S::Code;
                    }
                    (' ', 1)
                }
            };
            for _ in 0..advance.min(chars.len() - i) {
                buf.push(keep);
            }
            i += advance;
        }
        // Line comments and unterminated strings and runes end with the line.
        if matches!(st, S::Line | S::Str | S::Rune) {
            st = S::Code;
        }
        out.push(buf);
    }
    out
}

/// True when `needle` (`pkg.Func`) occurs in `code` as its own token sequence: the character
/// before must not continue an identifier or a selector (`myrand.Perm`, `x.rand.Perm`) and the
/// one after must not continue the name.
fn contains_symbol(code: &str, needle: &str) -> bool {
    let ident = |c: char| c.is_alphanumeric() || c == '_';
    code.match_indices(needle).any(|(pos, _)| {
        let before_ok = !code[..pos].ends_with(|c: char| ident(c) || c == '.');
        let after_ok = !code[pos + needle.len()..].starts_with(ident);
        before_ok && after_ok
    })
}

fn go_check(tree: &Tree, module: &str, refs: &[SymbolRef]) -> Reachability {
    let in_module =
        |p: &str| p == module || p.strip_prefix(module).is_some_and(|r| r.starts_with('/'));
    let mut imported_any: Vec<String> = Vec::new();
    let mut imported_affected: Vec<String> = Vec::new();
    let mut used: Vec<String> = Vec::new();
    for f in tree.files.iter().filter(|f| f.lang == Lang::Go) {
        let code = go_code_lines(&f.text);
        for (alias, path, line) in go_imports(&f.text) {
            if !in_module(&path) {
                continue;
            }
            imported_any.push(format!("{}:{line}", f.rel));
            let affected: Vec<&SymbolRef> = refs.iter().filter(|r| r.path == path).collect();
            if refs.is_empty() || !affected.is_empty() {
                imported_affected.push(format!("{}:{line}", f.rel));
            }
            for r in affected {
                for cand in go_name_candidates(&path, alias.as_deref()) {
                    for sym in &r.symbols {
                        let needle = format!("{cand}.{sym}");
                        for (i, l) in code.iter().enumerate() {
                            if contains_symbol(l, &needle) {
                                used.push(format!("{}:{} ({needle})", f.rel, i + 1));
                            }
                        }
                    }
                }
            }
        }
    }
    used.truncate(MAX_EVIDENCE);
    imported_affected.truncate(MAX_EVIDENCE);
    imported_any.truncate(MAX_EVIDENCE);
    if !used.is_empty() {
        return result(
            "used_symbol",
            used,
            "The project calls a function the advisory names (matched by name; run govulncheck for a call-graph proof).",
        );
    }
    if !imported_affected.is_empty() {
        let note = if refs.is_empty() {
            "The module is imported. The advisory names no specific function, so any use may matter."
        } else {
            "The affected package is imported but none of the named functions were found being called directly."
        };
        return result("imported", imported_affected, note);
    }
    if !imported_any.is_empty() {
        return result(
            "not_found",
            imported_any,
            format!(
                "The project imports other packages of this module but not the affected one. {TRANSITIVE}"
            ),
        );
    }
    result(
        "not_found",
        vec![],
        format!("No import of this module in the project's Go source. {TRANSITIVE}"),
    )
}

fn rust_check(tree: &Tree, name: &str, refs: &[SymbolRef]) -> Reachability {
    let krate = name.replace('-', "_");
    let uses = Regex::new(&format!(
        r"(?m)(?:\buse\s+{k}\b|\bextern\s+crate\s+{k}\b|\b{k}::)",
        k = regex::escape(&krate)
    ));
    let Ok(uses) = uses else {
        return result(
            "unknown",
            vec![],
            "Could not build a matcher for this crate name.",
        );
    };
    let mut imported: Vec<String> = Vec::new();
    let mut called: Vec<String> = Vec::new();
    for f in tree.files.iter().filter(|f| f.lang == Lang::Rust) {
        if !f.text.contains(&krate) {
            continue;
        }
        let Some(m) = uses.find(&f.text) else {
            continue;
        };
        let line = f.text[..m.start()].matches('\n').count() + 1;
        imported.push(format!("{}:{line}", f.rel));
        for sym in refs.iter().flat_map(|r| r.symbols.iter()) {
            for (i, l) in f.text.lines().enumerate() {
                let hit = l.contains(&format!(".{sym}("))
                    || l.contains(&format!("::{sym}("))
                    || l.contains(&format!("::{sym}::<"));
                if hit {
                    called.push(format!("{}:{} ({sym})", f.rel, i + 1));
                }
            }
        }
    }
    called.truncate(MAX_EVIDENCE);
    imported.truncate(MAX_EVIDENCE);
    if !called.is_empty() {
        return result(
            "used_symbol",
            called,
            "A file that uses this crate also calls a function the advisory names (matched by method name only, types are not resolved).",
        );
    }
    if !imported.is_empty() {
        let note = if refs.is_empty() {
            "The crate is used. The advisory names no specific function, so any use may matter."
        } else {
            "The crate is used but none of the named functions were found being called."
        };
        return result("imported", imported, note);
    }
    result(
        "not_found",
        vec![],
        format!(
            "No `use {krate}` or `{krate}::` path in the project's Rust source (renamed dependencies are not resolved). {TRANSITIVE}"
        ),
    )
}

fn js_check(tree: &Tree, name: &str) -> Reachability {
    let spec = Regex::new(r#"(?:\bfrom|\bimport|\brequire)\s*\(?\s*['"]([^'"]+)['"]"#);
    let Ok(spec) = spec else {
        return result("unknown", vec![], "Internal matcher error.");
    };
    let mut found = Vec::new();
    for f in tree.files.iter().filter(|f| f.lang == Lang::Js) {
        if !f.text.contains(name) {
            continue;
        }
        for cap in spec.captures_iter(&f.text) {
            let s = &cap[1];
            if s == name || s.strip_prefix(name).is_some_and(|r| r.starts_with('/')) {
                let start = cap.get(0).map_or(0, |m| m.start());
                found.push(format!(
                    "{}:{}",
                    f.rel,
                    f.text[..start].matches('\n').count() + 1
                ));
                break;
            }
        }
    }
    found.truncate(MAX_EVIDENCE);
    if found.is_empty() {
        result(
            "not_found",
            vec![],
            format!(
                "No import or require of this package in the project's JS/TS source. {TRANSITIVE}"
            ),
        )
    } else {
        result(
            "imported",
            found,
            "The package is imported. Which of its functions are used was not checked.",
        )
    }
}

fn php_namespaces(dir: &Path, package: &str) -> Option<Vec<String>> {
    let text = fs::read_to_string(dir.join("vendor/composer/installed.json")).ok()?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    let list = v
        .get("packages")
        .and_then(|p| p.as_array())
        .or_else(|| v.as_array())?;
    let pkg = list.iter().find(|p| {
        p.get("name")
            .and_then(|n| n.as_str())
            .is_some_and(|n| n.eq_ignore_ascii_case(package))
    })?;
    let mut out = Vec::new();
    for key in ["psr-4", "psr-0"] {
        if let Some(map) = pkg
            .get("autoload")
            .and_then(|a| a.get(key))
            .and_then(|m| m.as_object())
        {
            out.extend(
                map.keys()
                    .map(|k| k.trim_end_matches('\\').to_string())
                    .filter(|k| !k.is_empty()),
            );
        }
    }
    Some(out)
}

fn php_check(tree: &Tree, name: &str) -> Reachability {
    let Some(namespaces) = php_namespaces(&tree.dir, name) else {
        return result(
            "unknown",
            vec![],
            "Composer namespaces are unknown because vendor/composer/installed.json is missing; run `composer install` for a usage check.",
        );
    };
    if namespaces.is_empty() {
        return result(
            "unknown",
            vec![],
            "The package declares no PSR-0/PSR-4 namespace (classmap or files autoload), so usage cannot be matched.",
        );
    }
    let mut found = Vec::new();
    for f in tree.files.iter().filter(|f| f.lang == Lang::Php) {
        for ns in &namespaces {
            if let Some(pos) = f.text.find(ns.as_str()) {
                found.push(format!(
                    "{}:{}",
                    f.rel,
                    f.text[..pos].matches('\n').count() + 1
                ));
                break;
            }
        }
    }
    found.truncate(MAX_EVIDENCE);
    if found.is_empty() {
        result(
            "not_found",
            vec![],
            format!(
                "No reference to this package's namespaces in the project's PHP source. {TRANSITIVE}"
            ),
        )
    } else {
        result(
            "imported",
            found,
            "A namespace of the package is referenced. Which classes are used was not checked.",
        )
    }
}

fn python_check(tree: &Tree, name: &str) -> Reachability {
    let module = name.replace('-', "_");
    let re = Regex::new(&format!(
        r"(?m)^\s*(?:import|from)\s+{}\b",
        regex::escape(&module)
    ));
    let Ok(re) = re else {
        return result("unknown", vec![], "Internal matcher error.");
    };
    let mut found = Vec::new();
    for f in tree.files.iter().filter(|f| f.lang == Lang::Python) {
        if let Some(m) = re.find(&f.text) {
            found.push(format!(
                "{}:{}",
                f.rel,
                f.text[..m.start()].matches('\n').count() + 1
            ));
        }
    }
    found.truncate(MAX_EVIDENCE);
    if found.is_empty() {
        result(
            "unknown",
            vec![],
            "No import matching the distribution name was found, but the import name can differ from the PyPI name (for example PyYAML is imported as `yaml`), so this is not evidence of non-use.",
        )
    } else {
        result(
            "imported",
            found,
            "A module with this name is imported. Which functions are used was not checked.",
        )
    }
}

/// Adds [`Reachability`] to every finding. `base` is the directory lockfile paths are relative to.
pub fn annotate(base: &Path, findings: &mut [Finding], notes: &mut Vec<String>) {
    let mut trees: HashMap<PathBuf, Tree> = HashMap::new();
    let mut truncated = false;
    for f in findings.iter_mut() {
        // Usage is beside the point for a malicious package: its install step may have run
        // whether or not the project's code imports it.
        if f.malicious {
            continue;
        }
        if f.package
            .source
            .starts_with(opencraysec_lockfile::SBOM_SOURCE_PREFIX)
        {
            f.reachability = Some(Reachability {
                level: "unknown".into(),
                evidence: vec![],
                note: "The package comes from an SBOM, which has no source tree beside it, so usage was not checked.".into(),
            });
            continue;
        }
        let dir = base.join(
            Path::new(&f.package.source)
                .parent()
                .unwrap_or(Path::new("")),
        );
        let tree = trees.entry(dir.clone()).or_insert_with(|| load(&dir, base));
        truncated |= tree.truncated;
        let name = &f.package.name;
        let r = match f.package.ecosystem {
            Ecosystem::Go => go_check(tree, name, &f.symbol_refs),
            Ecosystem::CratesIo => rust_check(tree, name, &f.symbol_refs),
            Ecosystem::Npm => js_check(tree, name),
            Ecosystem::Packagist => php_check(tree, &f.package.name),
            Ecosystem::PyPI => python_check(tree, name),
            Ecosystem::GitHubActions => Reachability {
                level: "unknown".into(),
                evidence: vec![],
                note:
                    "A GitHub Action runs when its workflow does; there is no import to look for."
                        .into(),
            },
        };
        f.reachability = Some(r);
    }
    if truncated {
        notes.push(format!("Reachability: more than {MAX_FILES} source files; only the first {MAX_FILES} were read."));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opencraysec_core::{Package, Severity};

    fn tree(files: &[(&str, &str)]) -> Tree {
        Tree {
            files: files
                .iter()
                .map(|(rel, text)| SrcFile {
                    rel: rel.to_string(),
                    lang: lang_of(Path::new(rel)).expect("lang"),
                    text: text.to_string(),
                })
                .collect(),
            truncated: false,
            dir: PathBuf::from("/nonexistent"),
        }
    }

    fn refs(path: &str, syms: &[&str]) -> Vec<SymbolRef> {
        vec![SymbolRef {
            path: path.into(),
            symbols: syms.iter().map(|s| s.to_string()).collect(),
        }]
    }

    #[test]
    fn go_symbol_match_ignores_comments_strings_and_lookalike_names() {
        let level = |body: &str| {
            let src = format!("package main\nimport \"math/rand\"\nfunc f() {{\n{body}\n}}\n");
            let t = tree(&[("main.go", &src)]);
            go_check(&t, "math/rand", &refs("math/rand", &["Perm"])).level
        };
        assert_eq!(level("\t_ = rand.Perm(3)"), "used_symbol");
        assert_eq!(
            level("\tx := []int{1}; _ = append(x, rand.Perm(3)...)"),
            "used_symbol"
        );
        assert_eq!(level("\t// see rand.Perm in the docs"), "imported");
        assert_eq!(level("\t/* rand.Perm */ _ = 1"), "imported");
        assert_eq!(level("\t/*\n\trand.Perm(3)\n\t*/"), "imported");
        assert_eq!(level("\t_ = \"rand.Perm(3)\""), "imported");
        assert_eq!(level("\t_ = `\nrand.Perm(3)\n`"), "imported");
        assert_eq!(level("\t_ = \"say \\\"hi\\\" rand.Perm\""), "imported");
        assert_eq!(level("\t_ = myrand.Perm(3)"), "imported");
        assert_eq!(level("\t_ = s.rand.Perm(3)"), "imported");
        assert_eq!(level("\t_ = rand.Permute(3)"), "imported");
        assert_eq!(level("\t_ = '\"'; _ = rand.Perm(3)"), "used_symbol");
    }

    #[test]
    fn go_levels() {
        let src = "package main\nimport (\n\t\"fmt\"\n\th \"golang.org/x/net/html\"\n)\nfunc f() { h.Parse(nil) }\n";
        let t = tree(&[("main.go", src)]);
        let r = go_check(
            &t,
            "golang.org/x/net",
            &refs("golang.org/x/net/html", &["Parse"]),
        );
        assert_eq!(r.level, "used_symbol");
        assert!(r.evidence[0].starts_with("main.go:6"));
        let r = go_check(
            &t,
            "golang.org/x/net",
            &refs("golang.org/x/net/html", &["Other"]),
        );
        assert_eq!(r.level, "imported");
        let r = go_check(
            &t,
            "golang.org/x/net",
            &refs("golang.org/x/net/http2", &["Serve"]),
        );
        assert_eq!(r.level, "not_found");
        assert!(r.note.contains("other packages"));
        assert_eq!(go_check(&t, "golang.org/x/net", &[]).level, "imported");
        assert_eq!(go_check(&t, "github.com/other/mod", &[]).level, "not_found");
        let prefix_trap = tree(&[("a.go", "package a\nimport \"golang.org/x/network\"\n")]);
        assert_eq!(
            go_check(&prefix_trap, "golang.org/x/net", &[]).level,
            "not_found"
        );
        let v2 = tree(&[(
            "a.go",
            "package a\nimport \"github.com/x/y/v2\"\nfunc f(){ y.Do() }\n",
        )]);
        assert_eq!(
            go_check(&v2, "github.com/x/y", &refs("github.com/x/y/v2", &["Do"])).level,
            "used_symbol"
        );
    }

    #[test]
    fn rust_levels() {
        let src =
            "use smallvec::SmallVec;\nfn f(v: &mut SmallVec<[u8; 4]>) { v.insert_many(0, [1]); }\n";
        let t = tree(&[("src/lib.rs", src)]);
        assert_eq!(
            rust_check(
                &t,
                "smallvec",
                &refs("smallvec::SmallVec", &["insert_many"])
            )
            .level,
            "used_symbol"
        );
        assert_eq!(
            rust_check(&t, "smallvec", &refs("smallvec::SmallVec", &["grow"])).level,
            "imported"
        );
        assert_eq!(rust_check(&t, "smallvec", &[]).level, "imported");
        assert_eq!(rust_check(&t, "time", &[]).level, "not_found");
        let dashed = tree(&[("a.rs", "fn f() { serde_json::to_string(&1); }\n")]);
        assert_eq!(rust_check(&dashed, "serde-json", &[]).level, "imported");
        let comment_only = tree(&[("a.rs", "// smallvec is great\nfn f() {}\n")]);
        assert_eq!(
            rust_check(&comment_only, "smallvec", &[]).level,
            "not_found"
        );
    }

    #[test]
    fn js_and_python_levels() {
        let t = tree(&[
            (
                "a.ts",
                "import _ from 'lodash';\nconst x = require(\"lodash/fp\");\n",
            ),
            ("b.js", "const y = require('lodash-es');\n"),
        ]);
        let r = js_check(&t, "lodash");
        assert_eq!(r.level, "imported");
        assert_eq!(r.evidence, vec!["a.ts:1"]);
        assert_eq!(js_check(&t, "minimist").level, "not_found");
        assert_eq!(
            js_check(
                &tree(&[("b.js", "const y = require('lodash-es');\n")]),
                "lodash"
            )
            .level,
            "not_found"
        );
        let py = tree(&[("app.py", "import os\nfrom django.db import models\n")]);
        assert_eq!(python_check(&py, "django").level, "imported");
        assert_eq!(python_check(&py, "pyyaml").level, "unknown");
    }

    #[test]
    fn php_needs_installed_json() {
        let dir = tempfile::tempdir().expect("tmp");
        let t = tree(&[(
            "a.php",
            "<?php\nuse Symfony\\Component\\HttpKernel\\Kernel;\n",
        )]);
        assert_eq!(php_check(&t, "symfony/http-kernel").level, "unknown");
        fs::create_dir_all(dir.path().join("vendor/composer")).expect("mkdir");
        fs::write(
            dir.path().join("vendor/composer/installed.json"),
            r#"{"packages":[{"name":"symfony/http-kernel","autoload":{"psr-4":{"Symfony\\Component\\HttpKernel\\":""}}}]}"#,
        )
        .expect("w");
        let mut t = t;
        t.dir = dir.path().to_path_buf();
        let r = php_check(&t, "symfony/http-kernel");
        assert_eq!(r.level, "imported");
        assert!(r.evidence[0].starts_with("a.php:2"));
        assert_eq!(
            php_check(&tree(&[("b.php", "<?php echo 1;")]), "x/y").level,
            "unknown"
        );
        t.files[0].text = "<?php echo 1;".into();
        assert_eq!(php_check(&t, "symfony/http-kernel").level, "not_found");
    }

    #[test]
    fn annotate_reads_the_filesystem_and_scopes_by_lockfile_dir() {
        let dir = tempfile::tempdir().expect("tmp");
        let base = dir.path();
        fs::create_dir_all(base.join("svc/src")).expect("mkdir");
        fs::create_dir_all(base.join("other")).expect("mkdir");
        fs::write(base.join("svc/src/main.rs"), "use smallvec::SmallVec;\n").expect("w");
        fs::write(base.join("other/x.rs"), "use time::now;\n").expect("w");
        let mk = |name: &str, source: &str| Finding {
            id: "X".into(),
            aliases: vec![],
            package: Package {
                ecosystem: Ecosystem::CratesIo,
                name: name.into(),
                version: "1".into(),
                source: source.into(),
                dev: false,
            },
            summary: String::new(),
            severity: Severity::High,
            cvss: None,
            cwes: vec![],
            known_exploited: false,
            malicious: false,
            epss: None,
            fixed_in: vec![],
            references: vec![],
            reachability: None,
            symbol_refs: vec![],
        };
        let mut fs_ = vec![
            mk("smallvec", "svc/Cargo.lock"),
            mk("time", "svc/Cargo.lock"),
        ];
        let mut notes = Vec::new();
        annotate(base, &mut fs_, &mut notes);
        assert_eq!(fs_[0].reachability.as_ref().expect("r").level, "imported");
        assert_eq!(
            fs_[0].reachability.as_ref().expect("r").evidence,
            vec!["svc/src/main.rs:1"]
        );
        assert_eq!(
            fs_[1].reachability.as_ref().expect("r").level,
            "not_found",
            "other/ is outside svc/"
        );
    }
}
