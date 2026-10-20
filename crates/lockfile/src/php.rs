use opencraysec_core::{Ecosystem, Package};

use crate::pkg;

/// `composer.lock`: `packages` and `packages-dev`; `dev-` branch versions are skipped.
pub fn composer_lock(text: &str, source: &str) -> Result<Vec<Package>, String> {
    let v: serde_json::Value =
        serde_json::from_str(text).map_err(|e| format!("invalid composer.lock: {e}"))?;
    let mut out = Vec::new();
    for (key, dev) in [("packages", false), ("packages-dev", true)] {
        for p in v.get(key).and_then(|x| x.as_array()).into_iter().flatten() {
            let (Some(name), Some(version)) = (
                p.get("name").and_then(|x| x.as_str()),
                p.get("version").and_then(|x| x.as_str()),
            ) else {
                continue;
            };
            let version = version.trim_start_matches('v');
            if version.starts_with("dev-") || version.ends_with("-dev") {
                continue;
            }
            let name = Ecosystem::Packagist.normalize_name(name);
            out.push(pkg(Ecosystem::Packagist, &name, version, source, dev));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_both_sections() {
        let t = r#"{"packages":[{"name":"Symfony/Http-Kernel","version":"v6.4.1"},
            {"name":"a/b","version":"dev-main"}],
            "packages-dev":[{"name":"phpunit/phpunit","version":"10.5.0"}]}"#;
        let p = composer_lock(t, "composer.lock").expect("parses");
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].name, "symfony/http-kernel");
        assert_eq!(p[0].version, "6.4.1");
        assert!(p[1].dev);
        assert!(composer_lock("{", "x").is_err());
    }
}
