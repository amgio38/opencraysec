//! Report renderers: plain text for humans, SARIF 2.1.0 and CycloneDX 1.5 for tooling.

use std::fmt::Write;

use opencraysec_core::{Ecosystem, Package, Severity};
use serde_json::{Value, json};

use crate::code::CodeReport;
use crate::scan::ScanReport;

/// What to do about a malicious package that has no clean version: upgrading is not the fix.
pub const REMOVE_ADVICE: &str = "remove it; check whether its install scripts already ran and rotate secrets that machine could reach";

/// Percent-encodes the characters that are not allowed in a purl name segment.
fn enc(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || "-._~".contains(c) {
            out.push(c);
        } else {
            let mut buf = [0u8; 4];
            for b in c.encode_utf8(&mut buf).bytes() {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

/// Package URL (<https://github.com/package-url/purl-spec>) for a package.
pub fn purl(p: &Package) -> String {
    let version = enc(p.version.trim_start_matches('v').trim());
    match p.ecosystem {
        Ecosystem::CratesIo => format!("pkg:cargo/{}@{version}", enc(&p.name)),
        Ecosystem::Npm => {
            let name = match p.name.split_once('/') {
                Some((scope, rest)) => format!("{}/{}", enc(scope), enc(rest)),
                None => enc(&p.name),
            };
            format!("pkg:npm/{name}@{version}")
        }
        Ecosystem::Packagist => {
            let name = p.name.split('/').map(enc).collect::<Vec<_>>().join("/");
            format!("pkg:composer/{name}@{version}")
        }
        Ecosystem::Go => {
            let name = p.name.split('/').map(enc).collect::<Vec<_>>().join("/");
            format!("pkg:golang/{name}@v{version}")
        }
        Ecosystem::PyPI => format!("pkg:pypi/{}@{version}", enc(&p.name)),
    }
}

fn sarif_level(s: Severity) -> &'static str {
    match s {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        _ => "note",
    }
}

/// SARIF 2.1.0 log with one result per finding, located at the lockfile.
pub fn sarif(r: &ScanReport) -> Value {
    let mut rule_ids: Vec<&str> = r.findings.iter().map(|f| f.id.as_str()).collect();
    rule_ids.sort();
    rule_ids.dedup();
    let rules: Vec<Value> = rule_ids
        .iter()
        .filter_map(|id| r.findings.iter().find(|f| f.id == *id))
        .map(|f| {
            // Absent values are left out, never written as `null`: SARIF wants a string URI and a
            // string score there, and strict consumers reject anything else.
            let mut props = serde_json::Map::new();
            props.insert("cwe".into(), json!(f.cwes));
            props.insert("aliases".into(), json!(f.aliases));
            props.insert("knownExploited".into(), json!(f.known_exploited));
            if f.malicious {
                props.insert("malicious".into(), json!(true));
                props.insert("tags".into(), json!(["security", "malicious-package"]));
            }
            if let Some(c) = f.cvss {
                props.insert("cvss".into(), json!(c));
                props.insert("security-severity".into(), json!(format!("{c:.1}")));
            }
            if let Some(e) = f.epss {
                props.insert("epss".into(), json!(e));
            }
            let mut rule = json!({
                "id": f.id,
                "shortDescription": { "text": if f.summary.is_empty() { &f.id } else { &f.summary } },
                "properties": props,
            });
            if let Some(uri) = f.references.first() {
                rule["helpUri"] = json!(uri);
            }
            rule
        })
        .collect();
    let results: Vec<Value> = r
        .findings
        .iter()
        .map(|f| {
            let fix = if f.fixed_in.is_empty() && f.malicious {
                REMOVE_ADVICE.to_string()
            } else if f.fixed_in.is_empty() {
                "no fixed version published".to_string()
            } else {
                format!("fixed in {}", f.fixed_in.join(", "))
            };
            let what = if f.malicious {
                "is reported malicious"
            } else {
                "is affected"
            };
            json!({
                "ruleId": f.id,
                "level": sarif_level(f.severity),
                "message": { "text": format!("{} {} {what}: {} ({fix})", f.package.name, f.package.version, f.summary) },
                "locations": [{ "physicalLocation": { "artifactLocation": { "uri": f.package.source } } }],
                "properties": { "purl": purl(&f.package), "severity": f.severity.as_str() },
            })
        })
        .collect();
    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "opencraysec",
                "version": env!("CARGO_PKG_VERSION"),
                "informationUri": "https://github.com/amgio38/opencraysec",
                "rules": rules,
            }},
            "results": results,
            "invocations": [{
                "executionSuccessful": true,
                "toolExecutionNotifications": disclosure_lines(r).iter()
                    .map(|l| json!({ "level": "warning", "message": { "text": l } }))
                    .collect::<Vec<_>>(),
            }],
            "properties": disclosure(r),
        }],
    })
}

/// What the scan did not check and how fresh its data was: the part of a report that stops a
/// reader treating "0 findings" as "safe". Every machine format carries it.
fn disclosure(r: &ScanReport) -> Value {
    json!({
        "notes": r.notes,
        "skipped": r.skipped.iter().map(|(f, why)| json!({ "file": f, "reason": why })).collect::<Vec<_>>(),
        "unchecked": r.unchecked.iter().map(|(f, why)| json!({ "file": f, "reason": why })).collect::<Vec<_>>(),
        "lockfiles": r.lockfiles,
        "dataSources": r.data_sources.iter().map(|d| {
            let mut v = json!({ "ecosystem": d.ecosystem, "mode": d.mode, "packages": d.packages });
            if let Some(u) = &d.updated_at {
                v["updatedAt"] = json!(u);
            }
            v
        }).collect::<Vec<_>>(),
    })
}

/// The same disclosure as one sentence per item.
fn disclosure_lines(r: &ScanReport) -> Vec<String> {
    let mut out: Vec<String> = r.notes.clone();
    out.extend(
        r.skipped
            .iter()
            .map(|(f, why)| format!("skipped {f}: {why}")),
    );
    out.extend(
        r.unchecked
            .iter()
            .map(|(f, why)| format!("unchecked {f}: {why}")),
    );
    for d in &r.data_sources {
        out.push(match (d.mode.as_str(), &d.updated_at) {
            ("none", _) => format!(
                "{}: no advisory data, {} package(s) NOT checked",
                d.ecosystem, d.packages
            ),
            (mode, Some(u)) => format!("{}: {mode} advisory data, updated {u}", d.ecosystem),
            (mode, None) => format!("{}: {mode} advisory data", d.ecosystem),
        });
    }
    out
}

/// CycloneDX 1.5 SBOM listing every checked package and the vulnerabilities found.
pub fn cyclonedx(r: &ScanReport) -> Value {
    let components: Vec<Value> = r
        .packages
        .iter()
        .map(|p| {
            json!({
                "type": "library", "bom-ref": purl(p), "name": p.name,
                "version": p.version, "purl": purl(p),
            })
        })
        .collect();
    let vulns: Vec<Value> = r
        .findings
        .iter()
        .map(|f| {
            // A malicious package has no CVSS vector, so its rating says "other", not CVSS.
            let method = if f.malicious { "other" } else { "CVSSv31" };
            let mut rating = json!({ "severity": f.severity.as_str(), "method": method });
            if let Some(c) = f.cvss {
                rating["score"] = json!(c);
            }
            let mut v = json!({
                "id": f.id,
                "source": { "name": "OSV", "url": format!("https://osv.dev/vulnerability/{}", f.id) },
                "ratings": [rating],
                "cwes": f.cwes.iter().filter_map(|c| c.strip_prefix("CWE-").and_then(|n| n.parse::<u32>().ok())).collect::<Vec<_>>(),
                "description": f.summary,
                "affects": [{ "ref": purl(&f.package) }],
            });
            if let Some(fixed) = f.fixed_in.first() {
                v["recommendation"] = json!(format!("Upgrade to {fixed}"));
            } else if f.malicious {
                v["recommendation"] = json!(REMOVE_ADVICE);
            }
            if f.malicious {
                v["properties"] = json!([{ "name": "opencraysec:malicious", "value": "true" }]);
            }
            v
        })
        .collect();
    json!({
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "metadata": {
            "timestamp": r.scanned_at,
            "tools": { "components": [{
                "type": "application", "name": "opencraysec", "version": env!("CARGO_PKG_VERSION") }] },
            "properties": disclosure_lines(r).iter()
                .map(|l| json!({ "name": "opencraysec:disclosure", "value": l }))
                .collect::<Vec<_>>(),
        },
        "components": components, "vulnerabilities": vulns,
    })
}

/// Human-readable summary.
pub fn text(r: &ScanReport) -> String {
    let mut s = String::new();
    let _ = writeln!(
        s,
        "opencraysec: {} packages in {} lockfile(s), {} finding(s)",
        r.packages_checked,
        r.lockfiles.len(),
        r.findings.len()
    );
    for src in &r.data_sources {
        let _ = writeln!(
            s,
            "  data  {:<10} {:<6} {} ({} packages)",
            src.ecosystem,
            src.mode,
            src.updated_at.as_deref().unwrap_or("-"),
            src.packages
        );
    }
    for f in &r.findings {
        let flags = [
            f.malicious.then_some("MALICIOUS"),
            f.known_exploited.then_some("EXPLOITED"),
            f.epss.filter(|e| *e >= 0.1).map(|_| "likely-exploited"),
        ];
        let flags: Vec<&str> = flags.into_iter().flatten().collect();
        let _ = writeln!(
            s,
            "\n[{}{}] {} {}@{}  {}",
            f.severity.as_str().to_uppercase(),
            f.cvss.map(|c| format!(" {c:.1}")).unwrap_or_default(),
            f.id,
            f.package.name,
            f.package.version,
            if flags.is_empty() {
                String::new()
            } else {
                format!("<{}>", flags.join(","))
            }
        );
        if !f.summary.is_empty() {
            let _ = writeln!(s, "    {}", f.summary);
        }
        if !f.cwes.is_empty() {
            let _ = writeln!(s, "    weakness: {}", f.cwes.join(", "));
        }
        if let Some(r) = &f.reachability {
            let label = match r.level.as_str() {
                "used_symbol" => "YOUR CODE CALLS AN AFFECTED FUNCTION",
                "imported" => "your code imports it",
                "not_found" => "not imported by your code (may be used by another dependency)",
                _ => "usage unknown",
            };
            let ev = if r.evidence.is_empty() {
                String::new()
            } else {
                format!(" [{}]", r.evidence.join(", "))
            };
            let _ = writeln!(s, "    usage: {label}{ev}");
        }
        let _ = writeln!(
            s,
            "    fix: {}   ({})",
            if f.fixed_in.is_empty() && f.malicious {
                REMOVE_ADVICE.to_string()
            } else if f.fixed_in.is_empty() {
                "none published".to_string()
            } else {
                f.fixed_in.join(" / ")
            },
            f.package.source
        );
    }
    if r.informational_omitted > 0 {
        let _ = writeln!(
            s,
            "\n{} informational notice(s) (unmaintained and similar) omitted.",
            r.informational_omitted
        );
    }
    for (file, why) in &r.skipped {
        let _ = writeln!(s, "skipped {file}: {why}");
    }
    for (file, why) in &r.unchecked {
        let _ = writeln!(s, "unchecked {file}: {why}");
    }
    for n in &r.notes {
        let _ = writeln!(s, "note: {n}");
    }
    if !r.is_incomplete() {
        let _ = writeln!(
            s,
            "\nA clean result means no known advisory matched the lockfile versions listed above; it does not prove the code is secure."
        );
    } else {
        let _ = writeln!(
            s,
            "\nThis result is incomplete: some dependencies were not checked (see the data, skipped, unchecked and note lines above), so a lack of findings is not a clean result."
        );
    }
    s
}

/// Human-readable summary of a code scan.
pub fn code_text(r: &CodeReport) -> String {
    let mut s = String::new();
    let _ = writeln!(
        s,
        "opencraysec: {} source file(s) read, {} suspected issue(s)",
        r.files_scanned,
        r.findings.len()
    );
    for f in &r.findings {
        let _ = writeln!(
            s,
            "\n[{}] {} {}  {}:{}",
            f.severity.as_str().to_uppercase(),
            f.rule,
            f.cwe,
            f.file,
            f.line
        );
        let _ = writeln!(s, "    {}", f.title);
        if !f.snippet.is_empty() {
            let _ = writeln!(s, "    > {}", f.snippet);
        }
        let _ = writeln!(s, "    fix: {}", f.advice);
    }
    for e in &r.external {
        let _ = writeln!(s, "external {}: {} ({})", e.tool, e.status, e.detail);
    }
    for n in &r.notes {
        let _ = writeln!(s, "note: {n}");
    }
    s
}

/// SARIF 2.1.0 log for a code scan.
pub fn code_sarif(r: &CodeReport) -> Value {
    let mut ids: Vec<&str> = r.findings.iter().map(|f| f.rule.as_str()).collect();
    ids.sort();
    ids.dedup();
    let rules: Vec<Value> = ids
        .iter()
        .filter_map(|id| r.findings.iter().find(|f| f.rule == *id))
        .map(|f| json!({ "id": f.rule, "shortDescription": { "text": f.title }, "help": { "text": f.advice }, "properties": { "cwe": f.cwe } }))
        .collect();
    let results: Vec<Value> = r
        .findings
        .iter()
        .map(|f| {
            json!({
                "ruleId": f.rule,
                "level": sarif_level(f.severity),
                "message": { "text": format!("{} ({})", f.title, f.confidence) },
                "locations": [{ "physicalLocation": {
                    "artifactLocation": { "uri": f.file },
                    "region": { "startLine": f.line.max(1) } } }],
            })
        })
        .collect();
    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{ "tool": { "driver": { "name": "opencraysec", "version": env!("CARGO_PKG_VERSION"), "rules": rules } }, "results": results }],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use opencraysec_core::Finding;

    fn pkg(eco: Ecosystem, name: &str, v: &str) -> Package {
        Package {
            ecosystem: eco,
            name: name.into(),
            version: v.into(),
            source: "lock".into(),
            dev: false,
        }
    }

    #[test]
    fn purls() {
        assert_eq!(
            purl(&pkg(Ecosystem::Npm, "@babel/core", "7.0.0")),
            "pkg:npm/%40babel/core@7.0.0"
        );
        assert_eq!(
            purl(&pkg(Ecosystem::CratesIo, "serde", "1.0.1")),
            "pkg:cargo/serde@1.0.1"
        );
        assert_eq!(
            purl(&pkg(Ecosystem::Go, "golang.org/x/net", "v0.1.0")),
            "pkg:golang/golang.org/x/net@v0.1.0"
        );
        assert_eq!(
            purl(&pkg(Ecosystem::Packagist, "a/b", "1.0")),
            "pkg:composer/a/b@1.0"
        );
        assert_eq!(
            purl(&pkg(Ecosystem::PyPI, "django", "3.2")),
            "pkg:pypi/django@3.2"
        );
    }

    fn sample() -> ScanReport {
        let p = pkg(Ecosystem::Npm, "lodash", "4.17.4");
        ScanReport {
            root: "/p".into(),
            scanned_at: "t".into(),
            lockfiles: vec!["lock".into()],
            skipped: vec![],
            unchecked: vec![],
            packages_checked: 1,
            data_sources: vec![],
            notes: vec!["n".into()],
            informational_omitted: 0,
            findings: vec![Finding {
                id: "GHSA-1".into(),
                aliases: vec![],
                package: p.clone(),
                summary: "bad".into(),
                severity: Severity::High,
                cvss: Some(7.5),
                cwes: vec!["CWE-79".into()],
                known_exploited: true,
                malicious: false,
                epss: Some(0.5),
                fixed_in: vec!["4.17.21".into()],
                references: vec!["https://x".into()],
                reachability: None,
                symbol_refs: vec![],
            }],
            packages: vec![p],
            all_packages: vec![],
        }
    }

    fn malicious_sample() -> ScanReport {
        let mut r = sample();
        let f = &mut r.findings[0];
        f.id = "MAL-2026-7".into();
        f.summary = "Malicious code in lodash (npm)".into();
        f.malicious = true;
        f.severity = Severity::Critical;
        f.cvss = None;
        f.epss = None;
        f.known_exploited = false;
        f.fixed_in = vec![];
        r
    }

    #[test]
    fn a_malicious_package_reads_as_one_in_every_format() {
        let r = malicious_sample();
        let t = text(&r);
        assert!(
            t.contains("[CRITICAL] MAL-2026-7 lodash@4.17.4  <MALICIOUS>"),
            "{t}"
        );
        assert!(t.contains(&format!("fix: {REMOVE_ADVICE}")), "{t}");
        assert!(!t.contains("none published"), "{t}");

        let s = sarif(&r);
        let rule = &s["runs"][0]["tool"]["driver"]["rules"][0];
        assert_eq!(rule["properties"]["malicious"], true);
        assert_eq!(rule["properties"]["tags"][1], "malicious-package");
        let msg = s["runs"][0]["results"][0]["message"]["text"]
            .as_str()
            .expect("text");
        assert!(msg.contains("is reported malicious"), "{msg}");
        assert!(msg.contains(REMOVE_ADVICE), "{msg}");

        let c = cyclonedx(&r);
        let v = &c["vulnerabilities"][0];
        assert_eq!(v["ratings"][0]["method"], "other");
        assert_eq!(v["recommendation"], REMOVE_ADVICE);
        assert_eq!(v["properties"][0]["name"], "opencraysec:malicious");
    }

    #[test]
    fn an_ordinary_finding_carries_no_malicious_marks() {
        let r = sample();
        assert!(!text(&r).contains("MALICIOUS"));
        let s = sarif(&r);
        let props = &s["runs"][0]["tool"]["driver"]["rules"][0]["properties"];
        assert!(props.get("malicious").is_none() && props.get("tags").is_none());
        assert!(
            s["runs"][0]["results"][0]["message"]["text"]
                .as_str()
                .expect("text")
                .contains("is affected")
        );
        let c = cyclonedx(&r);
        assert_eq!(c["vulnerabilities"][0]["ratings"][0]["method"], "CVSSv31");
        assert!(c["vulnerabilities"][0].get("properties").is_none());
    }

    #[test]
    fn formats_are_well_formed() {
        let r = sample();
        let s = sarif(&r);
        assert_eq!(s["version"], "2.1.0");
        assert_eq!(s["runs"][0]["results"][0]["level"], "error");
        assert_eq!(s["runs"][0]["tool"]["driver"]["rules"][0]["id"], "GHSA-1");
        let c = cyclonedx(&r);
        assert_eq!(c["specVersion"], "1.5");
        assert_eq!(c["vulnerabilities"][0]["cwes"][0], 79);
        assert_eq!(
            c["vulnerabilities"][0]["affects"][0]["ref"],
            "pkg:npm/lodash@4.17.4"
        );
        let t = text(&r);
        assert!(t.contains("EXPLOITED"));
        assert!(t.contains("4.17.21"));
        assert!(t.contains("does not prove"));
    }

    fn has_null(v: &Value) -> bool {
        match v {
            Value::Null => true,
            Value::Array(a) => a.iter().any(has_null),
            Value::Object(o) => o.values().any(has_null),
            _ => false,
        }
    }

    #[test]
    fn missing_values_are_left_out_not_written_as_null() {
        let mut r = sample();
        r.findings[0].references.clear();
        r.findings[0].cvss = None;
        r.findings[0].epss = None;
        r.findings[0].fixed_in.clear();
        let s = sarif(&r);
        let rule = &s["runs"][0]["tool"]["driver"]["rules"][0];
        assert!(rule.get("helpUri").is_none());
        assert!(rule["properties"].get("security-severity").is_none());
        assert!(!has_null(&s), "SARIF must not contain null: {s}");
        let c = cyclonedx(&r);
        assert!(c["vulnerabilities"][0]["ratings"][0].get("score").is_none());
        assert!(c["vulnerabilities"][0].get("recommendation").is_none());
        assert!(!has_null(&c), "CycloneDX must not contain null: {c}");
    }

    #[test]
    fn machine_formats_disclose_what_was_not_checked() {
        let mut r = sample();
        r.skipped = vec![("big.lock".into(), "too large".into())];
        r.unchecked = vec![("requirements.txt".into(), "2 lines not pinned".into())];
        r.data_sources = vec![
            crate::scan::DataSource {
                ecosystem: "npm".into(),
                mode: "local".into(),
                updated_at: Some("2026-10-01T00:00:00Z".into()),
                packages: 3,
                malicious_records: None,
            },
            crate::scan::DataSource {
                ecosystem: "PyPI".into(),
                mode: "none".into(),
                updated_at: None,
                packages: 4,
                malicious_records: None,
            },
        ];
        let s = sarif(&r);
        let run = &s["runs"][0];
        assert_eq!(
            run["properties"]["unchecked"][0]["file"],
            "requirements.txt"
        );
        assert_eq!(run["properties"]["skipped"][0]["file"], "big.lock");
        assert_eq!(
            run["properties"]["dataSources"][0]["updatedAt"],
            "2026-10-01T00:00:00Z"
        );
        assert_eq!(run["invocations"][0]["executionSuccessful"], true);
        let notes = run["invocations"][0]["toolExecutionNotifications"].to_string();
        assert!(notes.contains("PyPI: no advisory data"), "{notes}");
        assert!(notes.contains("updated 2026-10-01"), "{notes}");
        let c = cyclonedx(&r).to_string();
        assert!(c.contains("opencraysec:disclosure"));
        assert!(c.contains("2 lines not pinned"));
        let t = text(&r);
        assert!(t.contains("unchecked requirements.txt"));
        assert!(t.contains("incomplete"));
        assert!(!t.contains("does not prove"));
    }
}
