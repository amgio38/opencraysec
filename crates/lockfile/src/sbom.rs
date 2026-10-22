//! SBOM import: a CycloneDX or SPDX JSON document as a package list.
//!
//! This is how to scan what is not in a lockfile you can read: a container image's inventory, or a
//! list another tool produced on another machine. Only components with a package URL (purl) of a
//! supported ecosystem become packages. Everything else (operating-system packages, container
//! images, components with no purl) is counted and reported as not checked, never dropped quietly.

use std::collections::BTreeMap;

use opencraysec_core::{Ecosystem, Package};
use serde_json::Value;

use crate::pkg;

/// Prefix of [`Package::source`] for packages read from an SBOM. There is no source tree beside an
/// SBOM, so usage evidence is not looked for.
pub const SOURCE_PREFIX: &str = "sbom:";

/// Reads a CycloneDX or SPDX JSON document. The second value says what was not checked.
pub(crate) fn parse(text: &str, source: &str) -> Result<(Vec<Package>, Option<String>), String> {
    let doc: Value = serde_json::from_str(text).map_err(|e| format!("not valid JSON: {e}"))?;
    let (purls, mut skipped) = if doc.get("bomFormat").and_then(Value::as_str) == Some("CycloneDX")
    {
        cyclonedx(&doc)
    } else if doc
        .get("spdxVersion")
        .and_then(Value::as_str)
        .is_some_and(|v| v.starts_with("SPDX-"))
    {
        spdx(&doc)
    } else {
        return Err("not a CycloneDX or SPDX JSON document".into());
    };

    let label = format!("{SOURCE_PREFIX}{source}");
    let mut packages = Vec::new();
    for purl in purls {
        match from_purl(&purl, &label) {
            Ok(p) => packages.push(p),
            Err(kind) => *skipped.entry(kind).or_insert(0) += 1,
        }
    }
    let unchecked: usize = skipped.values().sum();
    let note = if unchecked > 0 {
        let parts: Vec<String> = skipped.iter().map(|(k, n)| format!("{k}: {n}")).collect();
        Some(format!(
            "{unchecked} component(s) were not checked because they are not libraries of a supported ecosystem (operating-system packages and container images are not matched yet) or have no usable package URL ({})",
            parts.join(", ")
        ))
    } else if packages.is_empty() {
        Some("the SBOM lists no components".into())
    } else {
        None
    };
    Ok((packages, note))
}

/// purls of every component (nested ones included) and a count of components with none.
fn cyclonedx(doc: &Value) -> (Vec<String>, BTreeMap<String, usize>) {
    fn walk(list: &Value, purls: &mut Vec<String>, none: &mut usize) {
        for c in list.as_array().into_iter().flatten() {
            match c.get("purl").and_then(Value::as_str) {
                Some(p) => purls.push(p.to_string()),
                None => *none += 1,
            }
            if let Some(inner) = c.get("components") {
                walk(inner, purls, none);
            }
        }
    }
    let (mut purls, mut none) = (Vec::new(), 0);
    if let Some(list) = doc.get("components") {
        walk(list, &mut purls, &mut none);
    }
    let mut skipped = BTreeMap::new();
    if none > 0 {
        skipped.insert("no purl".to_string(), none);
    }
    (purls, skipped)
}

/// purls from `externalRefs`, and a count of packages with none. The package that describes the
/// document itself (the root) is not a dependency and is not counted.
fn spdx(doc: &Value) -> (Vec<String>, BTreeMap<String, usize>) {
    let root = doc
        .get("documentDescribes")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>())
        .unwrap_or_default();
    let (mut purls, mut none) = (Vec::new(), 0);
    for p in doc
        .get("packages")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if p.get("SPDXID")
            .and_then(Value::as_str)
            .is_some_and(|id| root.contains(&id))
        {
            continue;
        }
        let found = p
            .get("externalRefs")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .find(|r| r.get("referenceType").and_then(Value::as_str) == Some("purl"))
            .and_then(|r| r.get("referenceLocator").and_then(Value::as_str));
        match found {
            Some(l) => purls.push(l.to_string()),
            None => none += 1,
        }
    }
    let mut skipped = BTreeMap::new();
    if none > 0 {
        skipped.insert("no purl".to_string(), none);
    }
    (purls, skipped)
}

/// Turns a package URL into a package of a supported ecosystem. The error is the label to count the
/// component under (`deb`, `oci`, `no version`, ...).
fn from_purl(purl: &str, source: &str) -> Result<Package, String> {
    let rest = purl
        .strip_prefix("pkg:")
        .ok_or_else(|| "not a purl".to_string())?;
    // Qualifiers and subpath do not change which package it is.
    let rest = rest.split(['?', '#']).next().unwrap_or(rest);
    let (kind, path) = rest
        .split_once('/')
        .ok_or_else(|| "not a purl".to_string())?;
    let kind = kind.to_ascii_lowercase();
    let eco = match kind.as_str() {
        "cargo" => Ecosystem::CratesIo,
        "npm" => Ecosystem::Npm,
        "composer" => Ecosystem::Packagist,
        "golang" => Ecosystem::Go,
        "pypi" => Ecosystem::PyPI,
        _ => return Err(kind),
    };
    let (name, version) = path
        .rsplit_once('@')
        .ok_or_else(|| "no version".to_string())?;
    let name = decode(name);
    let version = decode(version);
    if name.is_empty() || version.is_empty() {
        return Err("no version".into());
    }
    let version = if eco == Ecosystem::Go && !version.starts_with('v') {
        format!("v{version}")
    } else {
        version
    };
    Ok(pkg(eco, &name, &version, source, false))
}

/// Percent-decodes a purl component. Malformed escapes are kept as written.
fn decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = |b: u8| char::from(b).to_digit(16);
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2]))
        {
            out.push((h * 16 + l) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CDX: &str = r#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
        {"type":"library","name":"serde","version":"1.0.1","purl":"pkg:cargo/serde@1.0.1"},
        {"type":"library","name":"core","purl":"pkg:npm/%40babel/core@7.0.0",
         "components":[{"type":"library","purl":"pkg:pypi/django@3.2?extension=x#sub"}]},
        {"type":"library","purl":"pkg:composer/guzzlehttp/guzzle@6.5.8"},
        {"type":"library","purl":"pkg:golang/golang.org/x/net@0.1.0"},
        {"type":"operating-system","purl":"pkg:deb/debian/php8.2@8.2.20-1?arch=amd64"},
        {"type":"library","purl":"pkg:deb/debian/openssl@3.0.13"},
        {"type":"container","name":"app"},
        {"type":"library","purl":"pkg:npm/lodash"}]}"#;

    #[test]
    fn cyclonedx_libraries_become_packages_and_the_rest_is_counted() {
        let (p, note) = parse(CDX, "bom.json").expect("parses");
        let got: Vec<(Ecosystem, &str, &str)> = p
            .iter()
            .map(|x| (x.ecosystem, x.name.as_str(), x.version.as_str()))
            .collect();
        assert_eq!(
            got,
            vec![
                (Ecosystem::CratesIo, "serde", "1.0.1"),
                (Ecosystem::Npm, "@babel/core", "7.0.0"),
                (Ecosystem::PyPI, "django", "3.2"),
                (Ecosystem::Packagist, "guzzlehttp/guzzle", "6.5.8"),
                (Ecosystem::Go, "golang.org/x/net", "v0.1.0"),
            ]
        );
        assert!(p.iter().all(|x| x.source == "sbom:bom.json" && !x.dev));
        let note = note.expect("some were not checked");
        assert!(note.starts_with("4 component(s)"), "{note}");
        assert!(
            note.contains("deb: 2")
                && note.contains("no purl: 1")
                && note.contains("no version: 1"),
            "{note}"
        );
    }

    #[test]
    fn spdx_uses_purl_external_refs_and_skips_the_root_package() {
        let spdx = r#"{"spdxVersion":"SPDX-2.3","documentDescribes":["SPDXRef-root"],"packages":[
            {"SPDXID":"SPDXRef-root","name":"app"},
            {"SPDXID":"SPDXRef-a","externalRefs":[
                {"referenceType":"cpe23Type","referenceLocator":"cpe:2.3:a:x"},
                {"referenceType":"purl","referenceLocator":"pkg:npm/lodash@4.17.4"}]},
            {"SPDXID":"SPDXRef-b","name":"mystery"}]}"#;
        let (p, note) = parse(spdx, "app.spdx.json").expect("parses");
        assert_eq!(p.len(), 1);
        assert_eq!(
            (p[0].name.as_str(), p[0].version.as_str()),
            ("lodash", "4.17.4")
        );
        assert!(note.expect("one without purl").contains("no purl: 1"));
    }

    #[test]
    fn other_documents_are_refused_with_a_reason() {
        assert!(
            parse("{}", "x.json")
                .expect_err("not an sbom")
                .contains("CycloneDX or SPDX")
        );
        assert!(
            parse("[1,2", "x.json")
                .expect_err("bad json")
                .contains("not valid JSON")
        );
        let empty = parse(r#"{"bomFormat":"CycloneDX","components":[]}"#, "x.json").expect("ok");
        assert!(empty.0.is_empty());
        assert_eq!(empty.1.as_deref(), Some("the SBOM lists no components"));
    }

    #[test]
    fn percent_decoding_keeps_malformed_escapes() {
        assert_eq!(decode("%40babel"), "@babel");
        assert_eq!(decode("a%2Fb"), "a/b");
        assert_eq!(decode("100%"), "100%");
        assert_eq!(decode("%zz"), "%zz");
        assert_eq!(decode("%4"), "%4");
    }
}
