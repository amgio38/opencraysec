use opencraysec_core::{Ecosystem, Package};

use crate::pkg;

/// `Cargo.lock`: registry crates only (path and git dependencies have no advisory identity).
pub fn cargo_lock(text: &str, source: &str) -> Result<Vec<Package>, String> {
    let v: toml::Value = toml::from_str(text).map_err(|e| format!("invalid Cargo.lock: {e}"))?;
    let mut out = Vec::new();
    for p in v
        .get("package")
        .and_then(|p| p.as_array())
        .into_iter()
        .flatten()
    {
        let (Some(name), Some(version)) = (
            p.get("name").and_then(|x| x.as_str()),
            p.get("version").and_then(|x| x.as_str()),
        ) else {
            continue;
        };
        let from_registry = p
            .get("source")
            .and_then(|s| s.as_str())
            .is_some_and(|s| s.starts_with("registry+"));
        if from_registry {
            out.push(pkg(Ecosystem::CratesIo, name, version, source, false));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_only() {
        let t = r#"
[[package]]
name = "me"
version = "0.1.0"
[[package]]
name = "time"
version = "0.1.43"
source = "registry+https://github.com/rust-lang/crates.io-index"
[[package]]
name = "g"
version = "1.0.0"
source = "git+https://example.com/g"
"#;
        let p = cargo_lock(t, "Cargo.lock").expect("parses");
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].name, "time");
        assert!(cargo_lock("not = [toml", "x").is_err());
    }
}
