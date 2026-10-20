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

/// `package-lock.json` (lockfileVersion 1, 2 and 3).
pub fn package_lock(text: &str, source: &str) -> Result<Vec<Package>, String> {
    let v: serde_json::Value =
        serde_json::from_str(text).map_err(|e| format!("invalid package-lock.json: {e}"))?;
    let mut out = Vec::new();
    if let Some(pkgs) = v.get("packages").and_then(|x| x.as_object()) {
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
            out.push(npm(name, version, source, dev));
        }
    } else if let Some(deps) = v.get("dependencies").and_then(|x| x.as_object()) {
        walk_v1(deps, source, &mut out);
    }
    Ok(out)
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

/// `pnpm-lock.yaml`: keys of the `packages:` section (lockfile v5 to v9).
pub fn pnpm_lock(text: &str, source: &str) -> Vec<Package> {
    let mut seen = BTreeSet::new();
    let mut in_packages = false;
    for line in text.lines() {
        if !line.starts_with(' ') && !line.trim().is_empty() {
            in_packages = line.trim_end() == "packages:";
            continue;
        }
        if !in_packages || !line.starts_with("  ") || line.starts_with("   ") {
            continue;
        }
        let Some(key) = line.trim().strip_suffix(':') else {
            continue;
        };
        let key = unquote(key).trim_start_matches('/');
        let key = key.split('(').next().unwrap_or(key);
        let parsed = match key.rfind('@').filter(|i| *i > 0) {
            Some(i) => Some((&key[..i], &key[i + 1..])),
            None => key.rsplit_once('/'),
        };
        if let Some((name, version)) = parsed
            && version.starts_with(|c: char| c.is_ascii_digit())
        {
            seen.insert((name.to_string(), version.to_string()));
        }
    }
    seen.into_iter()
        .map(|(n, v)| npm(&n, &v, source, false))
        .collect()
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
}
