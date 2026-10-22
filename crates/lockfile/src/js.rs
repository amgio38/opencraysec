use std::collections::BTreeSet;

use opencraysec_core::{Ecosystem, Package};

use crate::pkg;

fn npm(name: &str, version: &str, source: &str, dev: bool) -> Package {
    pkg(Ecosystem::Npm, name, version, source, dev)
}

fn walk_v1(
    deps: &serde_json::Map<String, serde_json::Value>,
    source: &str,
    out: &mut Vec<Package>,
) {
    for (name, info) in deps {
        if let Some(v) = info.get("version").and_then(|x| x.as_str())
            && !v.contains(':')
            && !v.contains('/')
        {
            let dev = info.get("dev").and_then(|x| x.as_bool()).unwrap_or(false);
            out.push(npm(name, v, source, dev));
        }
        if let Some(sub) = info.get("dependencies").and_then(|x| x.as_object()) {
            walk_v1(sub, source, out);
        }
    }
}

/// What a `package-lock.json` yields.
pub struct NpmLock {
    /// Every registry package in the lockfile.
    pub packages: Vec<Package>,
    /// The packages whose entry says an install step runs code (`hasInstallScript`). `None` when the
    /// format cannot say: lockfileVersion 1 has no per-package record of it.
    pub install_scripts: Option<Vec<Package>>,
}

/// `package-lock.json` (lockfileVersion 1, 2 and 3).
pub fn package_lock(text: &str, source: &str) -> Result<Vec<Package>, String> {
    package_lock_full(text, source).map(|l| l.packages)
}

/// Like [`package_lock`], and also the packages that run code when installed.
pub fn package_lock_full(text: &str, source: &str) -> Result<NpmLock, String> {
    let v: serde_json::Value =
        serde_json::from_str(text).map_err(|e| format!("invalid package-lock.json: {e}"))?;
    let mut out = Vec::new();
    let mut scripts = None;
    if let Some(pkgs) = v.get("packages").and_then(|x| x.as_object()) {
        let mut with_scripts = Vec::new();
        for (key, info) in pkgs {
            if key.is_empty() || info.get("link").and_then(|x| x.as_bool()) == Some(true) {
                continue;
            }
            let Some(idx) = key.rfind("node_modules/") else {
                continue;
            };
            let name = info
                .get("name")
                .and_then(|x| x.as_str())
                .unwrap_or(&key[idx + "node_modules/".len()..]);
            let Some(version) = info.get("version").and_then(|x| x.as_str()) else {
                continue;
            };
            let dev = info.get("dev").and_then(|x| x.as_bool()).unwrap_or(false);
            let p = npm(name, version, source, dev);
            if info.get("hasInstallScript").and_then(|x| x.as_bool()) == Some(true) {
                with_scripts.push(p.clone());
            }
            out.push(p);
        }
        scripts = Some(with_scripts);
    } else if let Some(deps) = v.get("dependencies").and_then(|x| x.as_object()) {
        walk_v1(deps, source, &mut out);
    }
    Ok(NpmLock {
        packages: out,
        install_scripts: scripts,
    })
}

fn unquote(s: &str) -> &str {
    s.trim().trim_matches(['"', '\''])
}

/// Splits `name@range` at the last `@` that is not the scope marker.
fn split_spec(spec: &str) -> Option<&str> {
    let spec = unquote(spec);
    let i = spec.rfind('@').filter(|i| *i > 0)?;
    Some(&spec[..i])
}

/// `yarn.lock` (classic v1 and berry).
pub fn yarn_lock(text: &str, source: &str) -> Vec<Package> {
    let mut seen = BTreeSet::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        if !line.starts_with(' ') {
            current = None;
            if let Some(head) = line.strip_suffix(':')
                && !head.starts_with("__metadata")
                && let Some(first) = head.split(',').next()
                && !first.contains("@workspace:")
            {
                current = split_spec(first).map(str::to_string);
            }
        } else if let Some(name) = &current {
            let t = line.trim();
            let v = t
                .strip_prefix("version ")
                .or_else(|| t.strip_prefix("version:"))
                .map(unquote);
            if let Some(v) = v {
                seen.insert((name.clone(), v.to_string()));
                current = None;
            }
        }
    }
    seen.into_iter()
        .map(|(n, v)| npm(&n, &v, source, false))
        .collect()
}

/// What a `pnpm-lock.yaml` yields.
pub struct PnpmLock {
    /// Every registry package in the `packages:` section.
    pub packages: Vec<Package>,
    /// The packages whose entry says `requiresBuild: true`, so an install step runs code. `None`
    /// when the file cannot say: pnpm's lockfile types declared `requiresBuild` up to lockfile
    /// version 6 and no longer declare it from version 9 on, so a newer file (or one with no version
    /// line) has no marker whose absence would mean anything.
    pub install_scripts: Option<Vec<Package>>,
}

/// The major part of the `lockfileVersion:` line (`5.4`, `'6.0'`, `'9.0'`), if the file has one.
fn pnpm_lockfile_major(text: &str) -> Option<u32> {
    text.lines()
        .take(5)
        .find_map(|l| l.strip_prefix("lockfileVersion:"))
        .and_then(|v| unquote(v.trim()).split('.').next()?.parse().ok())
}

/// `pnpm-lock.yaml`: keys of the `packages:` section (lockfile v5 to v9).
pub fn pnpm_lock(text: &str, source: &str) -> Vec<Package> {
    pnpm_lock_full(text, source).packages
}

/// Like [`pnpm_lock`], and also the packages that run a build step when installed (lockfile versions
/// 5 and 6, whose entries carry `requiresBuild`).
pub fn pnpm_lock_full(text: &str, source: &str) -> PnpmLock {
    let major = pnpm_lockfile_major(text);
    let readable = major.is_some_and(|m| m <= 8);
    let mut seen = BTreeSet::new();
    let mut builds = BTreeSet::new();
    let mut current: Option<(String, String)> = None;
    let mut in_packages = false;
    for line in text.lines() {
        if !line.starts_with(' ') && !line.trim().is_empty() {
            in_packages = line.trim_end() == "packages:";
            current = None;
            continue;
        }
        if !in_packages {
            continue;
        }
        if line.starts_with("    ") && !line.starts_with("     ") {
            if line.trim() == "requiresBuild: true"
                && let Some(entry) = &current
            {
                builds.insert(entry.clone());
            }
            continue;
        }
        if !line.starts_with("  ") || line.starts_with("   ") {
            continue;
        }
        current = None;
        let Some(key) = line.trim().strip_suffix(':') else {
            continue;
        };
        let key = unquote(key).trim_start_matches('/');
        let key = key.split('(').next().unwrap_or(key);
        let parsed = if major.is_some_and(|m| m <= 5) {
            // Lockfile v5 keys are paths, `name/version`, with a peer suffix after an underscore
            // (`react-dom/18.2.0_react@18.2.0`) that may itself hold an `@`.
            let segments: Vec<&str> = key.split('/').collect();
            let name_len = if key.starts_with('@') { 2 } else { 1 };
            (segments.len() > name_len).then(|| {
                let at = key.len() - segments[name_len..].join("/").len();
                (&key[..at.saturating_sub(1)], segments[name_len])
            })
        } else {
            match key.rfind('@').filter(|i| *i > 0) {
                Some(i) => Some((&key[..i], &key[i + 1..])),
                None => key.rsplit_once('/'),
            }
        };
        if let Some((name, version)) = parsed
            && version.starts_with(|c: char| c.is_ascii_digit())
        {
            let version = version.split('_').next().unwrap_or(version);
            let entry = (name.to_string(), version.to_string());
            seen.insert(entry.clone());
            current = Some(entry);
        }
    }
    let to_packages = |set: BTreeSet<(String, String)>| -> Vec<Package> {
        set.into_iter()
            .map(|(n, v)| npm(&n, &v, source, false))
            .collect()
    };
    PnpmLock {
        packages: to_packages(seen),
        install_scripts: readable.then(|| to_packages(builds)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_lock_v3_and_v1() {
        let v3 = r#"{"lockfileVersion":3,"packages":{"":{"name":"app"},
          "node_modules/lodash":{"version":"4.17.4"},
          "node_modules/a/node_modules/@s/b":{"version":"1.0.0","dev":true},
          "node_modules/ln":{"link":true,"resolved":"x"}}}"#;
        let p = package_lock(v3, "package-lock.json").expect("parses");
        assert_eq!(p.len(), 2);
        assert!(p.iter().any(|x| x.name == "@s/b" && x.dev));
        let v1 = r#"{"dependencies":{"a":{"version":"1.0.0","dependencies":{"b":{"version":"2.0.0"}}}}}"#;
        assert_eq!(package_lock(v1, "x").expect("parses").len(), 2);
    }

    #[test]
    fn yarn_classic_and_berry() {
        let classic = "# yarn lockfile v1\n\n\"@babel/core@^7.0.0\", \"@babel/core@^7.1.0\":\n  version \"7.2.0\"\n  resolved \"x\"\n\nlodash@^4.17.4:\n  version \"4.17.4\"\n";
        let p = yarn_lock(classic, "yarn.lock");
        assert_eq!(p.len(), 2);
        assert!(
            p.iter()
                .any(|x| x.name == "@babel/core" && x.version == "7.2.0")
        );
        let berry = "__metadata:\n  version: 6\n\n\"lodash@npm:^4.17.4\":\n  version: 4.17.4\n  resolution: \"lodash@npm:4.17.4\"\n\n\"app@workspace:.\":\n  version: 0.0.0-use.local\n";
        let p = yarn_lock(berry, "yarn.lock");
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].name, "lodash");
    }

    #[test]
    fn pnpm_variants() {
        let t = "lockfileVersion: '9.0'\n\nimporters:\n  .:\n    dependencies:\n      x:\n        version: 1.0.0\n\npackages:\n\n  '@scope/pkg@2.0.1':\n    resolution: {integrity: x}\n\n  lodash@4.17.4:\n    resolution: {integrity: y}\n\n  /react-dom@18.2.0(react@18.2.0):\n    dev: false\n\nsnapshots:\n  foo@1.0.0:\n";
        let p = pnpm_lock(t, "pnpm-lock.yaml");
        let names: Vec<_> = p
            .iter()
            .map(|x| (x.name.as_str(), x.version.as_str()))
            .collect();
        assert!(names.contains(&("@scope/pkg", "2.0.1")));
        assert!(names.contains(&("lodash", "4.17.4")));
        assert!(names.contains(&("react-dom", "18.2.0")));
        assert_eq!(p.len(), 3);
        let v5 = "packages:\n  /lodash/4.17.4:\n    dev: false\n  /@a/b/1.0.0:\n    dev: true\n";
        assert_eq!(pnpm_lock(v5, "x").len(), 2);
    }

    #[test]
    fn install_scripts_come_from_has_install_script_in_v2_and_v3() {
        let v3 = r#"{"lockfileVersion":3,"packages":{
          "":{"name":"app","hasInstallScript":true},
          "node_modules/native":{"version":"1.2.3","hasInstallScript":true},
          "node_modules/dev-native":{"version":"2.0.0","dev":true,"hasInstallScript":true},
          "node_modules/quiet":{"version":"3.0.0"},
          "node_modules/explicit-no":{"version":"4.0.0","hasInstallScript":false},
          "node_modules/ln":{"link":true,"hasInstallScript":true,"resolved":"x"},
          "node_modules/odd":{"version":"5.0.0","hasInstallScript":"yes"}}}"#;
        let l = package_lock_full(v3, "package-lock.json").expect("parses");
        assert_eq!(l.packages.len(), 5);
        let scripts = l.install_scripts.expect("v3 can say");
        let names: Vec<(&str, bool)> = scripts.iter().map(|p| (p.name.as_str(), p.dev)).collect();
        assert_eq!(
            names,
            vec![("dev-native", true), ("native", false)],
            "the root, links, false and non-boolean values are not install scripts"
        );
    }

    #[test]
    fn a_lockfile_that_cannot_say_reports_none_not_an_empty_list() {
        let v1 = r#"{"lockfileVersion":1,"dependencies":{"a":{"version":"1.0.0","requires":{}}}}"#;
        let l = package_lock_full(v1, "package-lock.json").expect("parses");
        assert_eq!(l.packages.len(), 1);
        assert!(l.install_scripts.is_none());
        let v3_none = r#"{"lockfileVersion":3,"packages":{"node_modules/a":{"version":"1.0.0"}}}"#;
        let l = package_lock_full(v3_none, "p").expect("parses");
        assert_eq!(l.install_scripts, Some(vec![]));
        assert!(package_lock_full("not json", "p").is_err());
    }

    const PNPM_V5: &str = "lockfileVersion: 5.4\n\nspecifiers:\n  native: 1.2.3\n\npackages:\n\n  /native/1.2.3:\n    resolution: {integrity: a}\n    requiresBuild: true\n    dev: false\n\n  /@scope/gyp/2.0.0_react@18.2.0:\n    resolution: {integrity: b}\n    dev: false\n    requiresBuild: true\n\n  /quiet/3.0.0:\n    resolution: {integrity: c}\n    dev: false\n\n  /explicit-no/4.0.0:\n    resolution: {integrity: d}\n    requiresBuild: false\n    dev: false\n\n  /react-dom/18.2.0_react@18.2.0:\n    resolution: {integrity: e}\n    dev: false\n";
    const PNPM_V6: &str = "lockfileVersion: '6.0'\n\npackages:\n\n  /native@1.2.3:\n    resolution: {integrity: a}\n    requiresBuild: true\n    dev: false\n\n  /@scope/gyp@2.0.0(react@18.2.0):\n    resolution: {integrity: b}\n    requiresBuild: true\n    dev: false\n\n  /quiet@3.0.0:\n    resolution: {integrity: c}\n    dev: false\n\n  /explicit-no@4.0.0:\n    requiresBuild: false\n    dev: false\n";
    const PNPM_V9: &str = "lockfileVersion: '9.0'\n\nimporters:\n  .:\n    dependencies:\n      native:\n        specifier: 1.2.3\n        version: 1.2.3\n\npackages:\n\n  native@1.2.3:\n    resolution: {integrity: a}\n    requiresBuild: true\n\n  quiet@3.0.0:\n    resolution: {integrity: c}\n\nsnapshots:\n\n  native@1.2.3: {}\n\n  quiet@3.0.0: {}\n";

    fn pnpm_names(l: &PnpmLock) -> Vec<(&str, &str)> {
        l.packages
            .iter()
            .map(|p| (p.name.as_str(), p.version.as_str()))
            .collect()
    }

    fn pnpm_builds(l: &PnpmLock) -> Option<Vec<(&str, &str)>> {
        l.install_scripts.as_ref().map(|v| {
            v.iter()
                .map(|p| (p.name.as_str(), p.version.as_str()))
                .collect()
        })
    }

    #[test]
    fn pnpm_lockfile_v5_names_the_packages_that_require_a_build() {
        let l = pnpm_lock_full(PNPM_V5, "pnpm-lock.yaml");
        assert_eq!(
            pnpm_names(&l),
            vec![
                ("@scope/gyp", "2.0.0"),
                ("explicit-no", "4.0.0"),
                ("native", "1.2.3"),
                ("quiet", "3.0.0"),
                ("react-dom", "18.2.0")
            ],
            "a peer suffix after the underscore is not part of the version, and its @ is not the separator"
        );
        assert_eq!(
            pnpm_builds(&l),
            Some(vec![("@scope/gyp", "2.0.0"), ("native", "1.2.3")]),
            "requiresBuild: false and no marker are not builds"
        );
    }

    #[test]
    fn pnpm_lockfile_v6_names_the_packages_that_require_a_build() {
        let l = pnpm_lock_full(PNPM_V6, "pnpm-lock.yaml");
        assert_eq!(
            pnpm_names(&l),
            vec![
                ("@scope/gyp", "2.0.0"),
                ("explicit-no", "4.0.0"),
                ("native", "1.2.3"),
                ("quiet", "3.0.0")
            ]
        );
        assert_eq!(
            pnpm_builds(&l),
            Some(vec![("@scope/gyp", "2.0.0"), ("native", "1.2.3")])
        );
    }

    #[test]
    fn pnpm_lockfile_v9_cannot_say_even_if_a_requires_build_line_is_there() {
        // pnpm's own lockfile types stopped declaring requiresBuild with version 9, so a missing
        // marker proves nothing and a stray one is not a list that can be trusted to be complete.
        let l = pnpm_lock_full(PNPM_V9, "pnpm-lock.yaml");
        assert_eq!(
            pnpm_names(&l),
            vec![("native", "1.2.3"), ("quiet", "3.0.0")]
        );
        assert_eq!(pnpm_builds(&l), None);
        let none = "packages:\n  /native/1.2.3:\n    requiresBuild: true\n";
        let l = pnpm_lock_full(none, "x");
        assert_eq!(pnpm_names(&l), vec![("native", "1.2.3")]);
        assert_eq!(pnpm_builds(&l), None, "no version line: unknown");
        assert_eq!(pnpm_lockfile_major("lockfileVersion: 'x'\n"), None);
        assert_eq!(pnpm_lockfile_major("lockfileVersion: 5.4\n"), Some(5));
        assert_eq!(pnpm_lockfile_major("\nlockfileVersion: \"6.1\"\n"), Some(6));
    }

    #[test]
    fn a_requires_build_line_belongs_to_the_entry_above_it_and_only_in_packages() {
        let t = "lockfileVersion: '6.0'\n\nimporters:\n  .:\n    dependencies:\n      a:\n        version: 1.0.0\n    requiresBuild: true\n\npackages:\n\n  /a@1.0.0:\n    resolution: {integrity: x}\n\n  /b@2.0.0:\n    resolution: {integrity: y}\n    requiresBuild: true\n\n  /c@3.0.0:\n    resolution: {integrity: z}\n\nsnapshots:\n  /d@4.0.0:\n    requiresBuild: true\n";
        let l = pnpm_lock_full(t, "x");
        assert_eq!(pnpm_builds(&l), Some(vec![("b", "2.0.0")]));
        // An indented line deeper than an entry's own properties is not a marker.
        let deep = "lockfileVersion: '6.0'\npackages:\n  /a@1.0.0:\n    resolution:\n      requiresBuild: true\n";
        assert_eq!(pnpm_builds(&pnpm_lock_full(deep, "x")), Some(vec![]));
    }
}
