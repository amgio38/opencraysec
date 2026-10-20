//! Lockfile discovery and parsing. Each parser turns one lockfile into resolved [`Package`]s;
//! none of them touch the network or execute project code.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use opencraysec_core::{Ecosystem, Package};

mod go;
mod js;
mod php;
mod python;
mod rust;

/// Directories never descended into: dependency trees and build output.
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
];

/// Largest lockfile we will read (bytes); bigger files are reported as skipped.
pub const MAX_LOCKFILE_BYTES: u64 = 64 * 1024 * 1024;

/// How deep below the scan root we look for lockfiles.
const MAX_DEPTH: usize = 8;

/// Result of scanning a directory tree.
#[derive(Debug, Default)]
pub struct Discovery {
    /// Packages found (deduplicated).
    pub packages: Vec<Package>,
    /// Lockfiles that were parsed, relative to the root.
    pub parsed: Vec<String>,
    /// Lockfiles or manifests that could not be used, with the reason.
    pub skipped: Vec<(String, String)>,
    /// Lockfiles that were read but hold dependencies the scan cannot check (unpinned or
    /// included requirements), with how many and why.
    pub unchecked: Vec<(String, String)>,
}

/// Which parser handles a file name, if any.
fn kind_of(name: &str) -> Option<&'static str> {
    match name {
        "Cargo.lock" => Some("cargo"),
        "package-lock.json" | "npm-shrinkwrap.json" => Some("npm"),
        "yarn.lock" => Some("yarn"),
        "pnpm-lock.yaml" => Some("pnpm"),
        "composer.lock" => Some("composer"),
        "go.mod" => Some("gomod"),
        "go.sum" => Some("gosum"),
        "poetry.lock" => Some("poetry"),
        "uv.lock" => Some("uv"),
        "Pipfile.lock" => Some("pipfile"),
        n if n.starts_with("requirements") && n.ends_with(".txt") => Some("requirements"),
        _ => None,
    }
}

/// Parses a single lockfile's text by kind. `source` is the label stored on each package.
pub fn parse_text(kind: &str, text: &str, source: &str) -> Result<Vec<Package>, String> {
    match kind {
        "cargo" => rust::cargo_lock(text, source),
        "npm" => js::package_lock(text, source),
        "yarn" => Ok(js::yarn_lock(text, source)),
        "pnpm" => Ok(js::pnpm_lock(text, source)),
        "composer" => php::composer_lock(text, source),
        "gomod" => Ok(go::go_mod(text, source)),
        "gosum" => Ok(go::go_sum(text, source)),
        "poetry" | "uv" => python::toml_lock(text, source, kind == "uv"),
        "pipfile" => python::pipfile_lock(text, source),
        "requirements" => Ok(python::requirements(text, source)),
        other => Err(format!("unknown lockfile kind {other}")),
    }
}

fn walk(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = entries.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let Ok(ft) = e.file_type() else { continue };
        let name = e.file_name().to_string_lossy().into_owned();
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            if depth < MAX_DEPTH && !SKIP_DIRS.contains(&name.as_str()) {
                walk(&e.path(), depth + 1, out);
            }
        } else if kind_of(&name).is_some() {
            out.push(e.path());
        }
    }
}

/// Finds and parses every supported lockfile under `root`, optionally limited to some ecosystems.
///
/// `go.sum` is only used when no `go.mod` sits next to it, because `go.sum` also lists versions
/// that were never selected.
pub fn discover(root: &Path, only: Option<&[Ecosystem]>) -> Discovery {
    let mut files = Vec::new();
    if root.is_file() {
        files.push(root.to_path_buf());
    } else {
        walk(root, 0, &mut files);
    }
    let base = if root.is_file() {
        root.parent().unwrap_or(root)
    } else {
        root
    };
    let mut d = Discovery::default();
    let mut seen: BTreeSet<Package> = BTreeSet::new();
    // requirements files: (file, lines that cannot be matched, files it includes with `-r`).
    // Whether an include is covered depends on which files were parsed, so it is judged at the end.
    let mut requirement_files: Vec<(String, usize, Vec<String>)> = Vec::new();
    for path in files {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let Some(kind) = kind_of(&name) else { continue };
        let rel = relative_name(&path, base);
        if kind == "gosum" && path.with_file_name("go.mod").is_file() {
            continue;
        }
        match fs::metadata(&path) {
            Ok(m) if m.len() > MAX_LOCKFILE_BYTES => {
                d.skipped.push((rel, "file larger than 64 MiB".into()));
                continue;
            }
            Err(e) => {
                d.skipped.push((rel, e.to_string()));
                continue;
            }
            _ => {}
        }
        let text = match fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) => {
                d.skipped.push((rel, e.to_string()));
                continue;
            }
        };
        match parse_text(kind, &text, &rel) {
            Ok(pkgs) => {
                if kind == "requirements" {
                    requirement_files.push((
                        rel.clone(),
                        python::requirements_unchecked(&text),
                        python::requirements_includes(&text),
                    ));
                }
                d.parsed.push(rel);
                for p in pkgs {
                    if only.is_none_or(|o| o.contains(&p.ecosystem)) {
                        seen.insert(p);
                    }
                }
            }
            Err(e) => d.skipped.push((rel, e)),
        }
    }
    d.packages = seen.into_iter().collect();
    let scanned: BTreeSet<&str> = d.parsed.iter().map(String::as_str).collect();
    for (rel, unmatched, includes) in requirement_files {
        // `-r base.txt` is fine when base.txt was scanned too; otherwise its pins were not seen.
        let missing = includes
            .iter()
            .filter(|t| resolve_include(&rel, t).is_none_or(|p| !scanned.contains(p.as_str())))
            .count();
        let n = unmatched + missing;
        if n > 0 {
            d.unchecked.push((
                rel,
                format!("{n} requirement line(s) are not exact `==` pins (ranges, URLs, `-e` installs, or `-r` includes of files that were not scanned) and were not checked"),
            ));
        }
    }
    d
}

/// `path` relative to `base`, written with `/` on every platform, so a file is called the same
/// thing in a report whether the scan ran on Linux, macOS or Windows.
pub fn relative_name(path: &Path, base: &Path) -> String {
    path.strip_prefix(base)
        .unwrap_or(path)
        .components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

/// Where an `-r` target points, relative to the scan root and written the way [`discover`] names
/// files (`/`-separated, no `.` or `..`). `None` for an absolute path, a URL, or a path that leaves
/// the scan root: those cannot be one of the files that were scanned.
fn resolve_include(including: &str, target: &str) -> Option<String> {
    if target.starts_with('/') || target.contains("://") {
        return None;
    }
    let mut parts: Vec<&str> = including.split('/').collect();
    parts.pop();
    for part in target.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            p => parts.push(p),
        }
    }
    Some(parts.join("/"))
}

pub(crate) fn pkg(eco: Ecosystem, name: &str, version: &str, source: &str, dev: bool) -> Package {
    Package {
        ecosystem: eco,
        name: name.to_string(),
        version: version.to_string(),
        source: source.to_string(),
        dev,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(root: &Path, rel: &str, text: &str) {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
        fs::write(p, text).expect("write");
    }

    #[test]
    fn discovers_across_ecosystems_and_skips_dependency_dirs() {
        let dir = tempfile::tempdir().expect("tmp");
        let r = dir.path();
        write(
            r,
            "Cargo.lock",
            "[[package]]\nname = \"a\"\nversion = \"1.0.0\"\nsource = \"registry+x\"\n",
        );
        write(
            r,
            "web/package-lock.json",
            r#"{"packages":{"node_modules/b":{"version":"2.0.0"}}}"#,
        );
        write(
            r,
            "web/node_modules/c/package-lock.json",
            r#"{"packages":{"node_modules/z":{"version":"9.9.9"}}}"#,
        );
        write(r, "svc/go.mod", "module x\nrequire example.com/d v1.0.0\n");
        write(r, "svc/go.sum", "example.com/other v1.0.0 h1:x=\n");
        write(r, "py/requirements-dev.txt", "e==1.0\n");
        let d = discover(r, None);
        let names: Vec<_> = d.packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["a", "b", "example.com/d", "e"]);
        assert_eq!(
            d.parsed.len(),
            4,
            "go.sum next to go.mod and node_modules are skipped"
        );
        let only = discover(r, Some(&[Ecosystem::Go]));
        assert_eq!(only.packages.len(), 1);
        assert_eq!(only.packages[0].name, "example.com/d");
    }

    #[test]
    fn single_file_roots_and_bad_files() {
        let dir = tempfile::tempdir().expect("tmp");
        let r = dir.path();
        write(r, "composer.lock", "{ not json");
        write(
            r,
            "Cargo.lock",
            "[[package]]\nname = \"a\"\nversion = \"1.0.0\"\nsource = \"registry+x\"\n",
        );
        let d = discover(r, None);
        assert_eq!(d.packages.len(), 1);
        assert_eq!(d.skipped.len(), 1);
        assert!(d.skipped[0].0.ends_with("composer.lock"));
        let single = discover(&r.join("Cargo.lock"), None);
        assert_eq!(single.parsed, vec!["Cargo.lock"]);
        let missing = discover(&r.join("nothing"), None);
        assert!(missing.packages.is_empty());
    }

    #[test]
    fn oversized_lockfiles_are_skipped_not_read() {
        let dir = tempfile::tempdir().expect("tmp");
        let f = fs::File::create(dir.path().join("Cargo.lock")).expect("create");
        f.set_len(MAX_LOCKFILE_BYTES + 1).expect("sparse");
        let d = discover(dir.path(), None);
        assert!(d.parsed.is_empty());
        assert!(d.skipped[0].1.contains("larger than"));
    }

    #[test]
    fn parse_text_rejects_unknown_kinds() {
        assert!(parse_text("nope", "", "x").is_err());
        assert!(parse_text("gosum", "a/b v1.0.0 h1:x=\n", "go.sum").is_ok());
        assert_eq!(
            parse_text("pipfile", "{\"default\":{}}", "x")
                .expect("ok")
                .len(),
            0
        );
    }

    #[test]
    fn requirement_includes_are_covered_only_when_the_included_file_is_scanned() {
        let dir = tempfile::tempdir().expect("tmp");
        let r = dir.path();
        write(r, "requirements.txt", "flask==2.0.0\n");
        // The common layout: dev requirements include the base file, which is scanned as well.
        write(
            r,
            "requirements-dev.txt",
            "-r requirements.txt\n-c constraints.txt\npytest==8.0.0\n",
        );
        // Another directory reaches the base file with `..`.
        write(
            r,
            "svc/requirements.txt",
            "-r ../requirements.txt\nrequests==2.0.0\n",
        );
        // These point at files that were not scanned: a missing one, an absolute path, a URL, and
        // one that leaves the scan root.
        write(
            r,
            "other/requirements.txt",
            "-r base.in\n-r /etc/pins.txt\n-r https://x/y.txt\n-r ../../outside.txt\nurllib3==1.0\n",
        );
        let d = discover(r, None);
        let unchecked: Vec<&str> = d.unchecked.iter().map(|(f, _)| f.as_str()).collect();
        assert_eq!(
            unchecked,
            vec!["other/requirements.txt"],
            "{:?}",
            d.unchecked
        );
        assert!(
            d.unchecked[0].1.starts_with("4 requirement line(s)"),
            "{:?}",
            d.unchecked
        );
    }

    #[test]
    fn include_resolution_stays_inside_the_scan_root() {
        assert_eq!(
            resolve_include("a/b.txt", "c.txt").as_deref(),
            Some("a/c.txt")
        );
        assert_eq!(
            resolve_include("a/b.txt", "./c.txt").as_deref(),
            Some("a/c.txt")
        );
        assert_eq!(
            resolve_include("a/b.txt", "../c.txt").as_deref(),
            Some("c.txt")
        );
        assert_eq!(
            resolve_include("b.txt", "sub//c.txt").as_deref(),
            Some("sub/c.txt")
        );
        assert_eq!(resolve_include("b.txt", "../c.txt"), None);
        assert_eq!(resolve_include("b.txt", "/abs.txt"), None);
        assert_eq!(resolve_include("b.txt", "https://x/c.txt"), None);
    }

    #[test]
    fn relative_names_use_forward_slashes() {
        let base = Path::new("root");
        assert_eq!(
            relative_name(&base.join("a").join("b.txt"), base),
            "a/b.txt"
        );
        assert_eq!(relative_name(&base.join("b.txt"), base), "b.txt");
        // Outside the base it stays as given, still `/`-separated.
        assert_eq!(relative_name(&Path::new("x").join("y"), base), "x/y");
    }
}
