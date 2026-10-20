//! OSV advisory records (<https://ossf.github.io/osv-schema/>) and affected-version matching.

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};

use crate::cvss;
use crate::model::{Ecosystem, Severity};
use crate::version::compare;

/// An OSV advisory, trimmed to the fields opencraysec uses.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct OsvRecord {
    /// Advisory id.
    pub id: String,
    /// Alternate ids (CVE, GHSA, ...).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    /// One-line summary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// Long description (truncated at ingest).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    /// Last modification time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified: Option<String>,
    /// Set when the advisory was withdrawn.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withdrawn: Option<String>,
    /// Severity vectors.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub severity: Vec<OsvSeverity>,
    /// Affected packages.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub affected: Vec<Affected>,
    /// Links.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<Reference>,
    /// Database-specific extras we read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database_specific: Option<DbSpecific>,
}

/// A severity entry.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct OsvSeverity {
    /// Scoring system, e.g. `CVSS_V3`.
    #[serde(rename = "type", default)]
    pub kind: String,
    /// The vector string.
    #[serde(default)]
    pub score: String,
}

/// A link.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Reference {
    /// URL.
    #[serde(default)]
    pub url: String,
}

/// The `database_specific` fields we keep.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DbSpecific {
    /// GHSA severity label (`HIGH`, `MODERATE`, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// CWE ids.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cwe_ids: Vec<String>,
    /// RustSec: `unmaintained`, `unsound`, `notice`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub informational: Option<String>,
}

/// One affected package entry.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Affected {
    /// Package identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<OsvPackage>,
    /// Version ranges.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ranges: Vec<Range>,
    /// Explicit affected versions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub versions: Vec<String>,
    /// Ecosystem-specific extras, trimmed at ingest to the symbol data reachability uses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ecosystem_specific: Option<serde_json::Value>,
}

/// A vulnerable code location named by an advisory: an import path (Go) or a crate path (Rust)
/// plus the functions or symbols that are affected. Empty `symbols` means the whole package.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SymbolRef {
    /// Go import path, or the Rust path up to the function (`smallvec::SmallVec`).
    pub path: String,
    /// Affected symbol names.
    pub symbols: Vec<String>,
}

/// Keeps only the parts of `ecosystem_specific` that opencraysec reads, dropping everything else
/// so the stored dataset stays small. Returns `None` when nothing relevant remains.
pub fn trim_ecosystem_specific(v: Option<serde_json::Value>) -> Option<serde_json::Value> {
    let obj = v?.as_object()?.clone();
    let mut out = serde_json::Map::new();
    if let Some(imports) = obj.get("imports").and_then(|i| i.as_array()) {
        let kept: Vec<serde_json::Value> = imports
            .iter()
            .filter_map(|i| {
                let path = i.get("path")?.as_str()?;
                let symbols: Vec<&str> = i
                    .get("symbols")
                    .and_then(|s| s.as_array())
                    .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
                    .unwrap_or_default();
                Some(serde_json::json!({ "path": path, "symbols": symbols }))
            })
            .collect();
        if !kept.is_empty() {
            out.insert("imports".into(), serde_json::Value::Array(kept));
        }
    }
    let mut functions: Vec<&str> = Vec::new();
    if let Some(a) = obj.get("affected_functions").and_then(|f| f.as_array()) {
        functions.extend(a.iter().filter_map(|x| x.as_str()));
    }
    if let Some(a) = obj
        .get("affects")
        .and_then(|a| a.get("functions"))
        .and_then(|f| f.as_array())
    {
        functions.extend(a.iter().filter_map(|x| x.as_str()));
    }
    if !functions.is_empty() {
        functions.sort_unstable();
        functions.dedup();
        out.insert("functions".into(), serde_json::json!(functions));
    }
    if out.is_empty() {
        None
    } else {
        Some(serde_json::Value::Object(out))
    }
}

/// Package identity inside an advisory.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct OsvPackage {
    /// OSV ecosystem name.
    #[serde(default)]
    pub ecosystem: String,
    /// Package name.
    #[serde(default)]
    pub name: String,
}

/// A version range.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Range {
    /// `SEMVER`, `ECOSYSTEM` or `GIT`.
    #[serde(rename = "type", default)]
    pub kind: String,
    /// Introduced/fixed events.
    #[serde(default)]
    pub events: Vec<Event>,
}

/// A range event; exactly one field is normally set.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Event {
    /// First affected version (`0` means from the beginning).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub introduced: Option<String>,
    /// First fixed version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixed: Option<String>,
    /// Last affected version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_affected: Option<String>,
}

/// Result of matching an installed version against an advisory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    /// Fixed versions above the installed one, lowest first.
    pub fixed_in: Vec<String>,
}

enum Kind {
    Introduced,
    Fixed,
    LastAffected,
}

fn range_affects(eco: Ecosystem, range: &Range, v: &str) -> bool {
    let mut events: Vec<(Kind, &str)> = Vec::new();
    for e in &range.events {
        if let Some(x) = &e.introduced {
            events.push((Kind::Introduced, x));
        }
        if let Some(x) = &e.fixed {
            events.push((Kind::Fixed, x));
        }
        if let Some(x) = &e.last_affected {
            events.push((Kind::LastAffected, x));
        }
    }
    // `introduced: "0"` means "from the very first version"; it must sort before everything,
    // including pre-release fixes such as `0.0.0-2021...` that compare below a plain `0`.
    let is_start = |e: &(Kind, &str)| matches!(e.0, Kind::Introduced) && e.1 == "0";
    events.sort_by(|a, b| match (is_start(a), is_start(b)) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        (false, false) => compare(eco, a.1, b.1),
    });
    let mut affected = false;
    for (kind, ver) in events {
        let ord = compare(eco, v, ver);
        match kind {
            Kind::Introduced => {
                if ver == "0" || ord != Ordering::Less {
                    affected = true;
                }
            }
            Kind::Fixed => {
                if ord != Ordering::Less {
                    affected = false;
                }
            }
            Kind::LastAffected => {
                if ord == Ordering::Greater {
                    affected = false;
                }
            }
        }
    }
    affected
}

fn is_version_range(r: &Range) -> bool {
    r.kind == "SEMVER" || r.kind == "ECOSYSTEM"
}

impl OsvRecord {
    /// Matches `version` of package `name` (already normalised) against this advisory.
    pub fn affects(&self, eco: Ecosystem, name: &str, version: &str) -> Option<Match> {
        let mut hit = false;
        let mut fixed: Vec<String> = Vec::new();
        for a in &self.affected {
            let Some(p) = &a.package else { continue };
            if Ecosystem::from_osv_name(&p.ecosystem) != Some(eco)
                || eco.normalize_name(&p.name) != name
            {
                continue;
            }
            let listed = a
                .versions
                .iter()
                .any(|x| compare(eco, x, version) == Ordering::Equal);
            let in_range = a
                .ranges
                .iter()
                .filter(|r| is_version_range(r))
                .any(|r| range_affects(eco, r, version));
            if listed || in_range {
                hit = true;
                // Only the range that contains the installed version names a valid fix; other
                // ranges describe different release branches the version is not on.
                let containing: Vec<&Range> = a
                    .ranges
                    .iter()
                    .filter(|r| is_version_range(r) && range_affects(eco, r, version))
                    .collect();
                let source: Vec<&Range> = if containing.is_empty() {
                    a.ranges.iter().filter(|r| is_version_range(r)).collect()
                } else {
                    containing
                };
                for r in source {
                    for e in &r.events {
                        if let Some(f) = &e.fixed
                            && compare(eco, f, version) == Ordering::Greater
                        {
                            fixed.push(f.clone());
                        }
                    }
                }
            }
        }
        if !hit {
            return None;
        }
        fixed.sort_by(|a, b| compare(eco, a, b));
        fixed.dedup();
        Some(Match { fixed_in: fixed })
    }

    /// CVE ids among the id and aliases.
    pub fn cve_ids(&self) -> Vec<String> {
        std::iter::once(&self.id)
            .chain(self.aliases.iter())
            .filter(|x| x.starts_with("CVE-"))
            .cloned()
            .collect()
    }

    /// Highest CVSS v3 base score found, if any vector could be scored.
    pub fn cvss_score(&self) -> Option<f32> {
        self.severity
            .iter()
            .filter_map(|s| cvss::base_score(&s.score))
            .fold(None, |acc: Option<f32>, x| {
                Some(acc.map_or(x, |a| a.max(x)))
            })
    }

    /// Severity bucket: CVSS score if available, else the database label.
    pub fn severity_bucket(&self) -> Severity {
        if let Some(score) = self.cvss_score() {
            return Severity::from_score(score);
        }
        self.database_specific
            .as_ref()
            .and_then(|d| d.severity.as_deref())
            .and_then(Severity::parse)
            .unwrap_or(Severity::Unknown)
    }

    /// Vulnerable symbols the advisory names for `name` (already normalised), if any.
    pub fn symbol_refs(&self, eco: Ecosystem, name: &str) -> Vec<SymbolRef> {
        let mut out = Vec::new();
        for a in &self.affected {
            let Some(p) = &a.package else { continue };
            if Ecosystem::from_osv_name(&p.ecosystem) != Some(eco)
                || eco.normalize_name(&p.name) != name
            {
                continue;
            }
            let Some(spec) = &a.ecosystem_specific else {
                continue;
            };
            for i in spec
                .get("imports")
                .and_then(|i| i.as_array())
                .into_iter()
                .flatten()
            {
                if let Some(path) = i.get("path").and_then(|x| x.as_str()) {
                    let symbols = i
                        .get("symbols")
                        .and_then(|s| s.as_array())
                        .map(|a| {
                            a.iter()
                                .filter_map(|x| x.as_str().map(str::to_string))
                                .collect()
                        })
                        .unwrap_or_default();
                    out.push(SymbolRef {
                        path: path.to_string(),
                        symbols,
                    });
                }
            }
            for f in spec
                .get("functions")
                .and_then(|f| f.as_array())
                .into_iter()
                .flatten()
            {
                if let Some(full) = f.as_str()
                    && let Some((path, symbol)) = full.rsplit_once("::")
                {
                    out.push(SymbolRef {
                        path: path.to_string(),
                        symbols: vec![symbol.to_string()],
                    });
                }
            }
        }
        out.sort();
        out.dedup();
        out
    }

    /// CWE ids (`CWE-79`).
    pub fn cwes(&self) -> Vec<String> {
        self.database_specific
            .as_ref()
            .map(|d| d.cwe_ids.clone())
            .unwrap_or_default()
    }

    /// True for RustSec notices that are not vulnerabilities (unmaintained crates and so on).
    pub fn is_informational_only(&self) -> bool {
        matches!(
            self.database_specific
                .as_ref()
                .and_then(|d| d.informational.as_deref()),
            Some("unmaintained" | "notice")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(json: &str) -> OsvRecord {
        serde_json::from_str(json).expect("valid test json")
    }

    const SAMPLE: &str = r#"{
      "id":"GHSA-xxxx","aliases":["CVE-2026-1"],
      "affected":[{"package":{"ecosystem":"npm","name":"lodash"},
        "ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.12"}]},
                  {"type":"SEMVER","events":[{"introduced":"5.0.0"},{"fixed":"5.1.0"}]}]}],
      "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
      "database_specific":{"severity":"HIGH","cwe_ids":["CWE-1321"]}
    }"#;

    #[test]
    fn range_matching_with_two_intervals() {
        let r = rec(SAMPLE);
        let m = r
            .affects(Ecosystem::Npm, "lodash", "4.17.11")
            .expect("affected");
        assert_eq!(
            m.fixed_in,
            vec!["4.17.12"],
            "only the range holding the version names a fix"
        );
        assert!(r.affects(Ecosystem::Npm, "lodash", "4.17.12").is_none());
        assert!(r.affects(Ecosystem::Npm, "lodash", "4.99.0").is_none());
        let m = r
            .affects(Ecosystem::Npm, "lodash", "5.0.5")
            .expect("affected");
        assert_eq!(m.fixed_in, vec!["5.1.0"]);
        assert!(r.affects(Ecosystem::Npm, "lodash", "5.1.0").is_none());
        assert!(r.affects(Ecosystem::Npm, "other", "1.0.0").is_none());
        assert!(r.affects(Ecosystem::CratesIo, "lodash", "1.0.0").is_none());
    }

    #[test]
    fn last_affected_and_explicit_versions() {
        let r = rec(
            r#"{"id":"X","affected":[{"package":{"ecosystem":"PyPI","name":"Foo_Bar"},
            "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0"},{"last_affected":"1.5"}]}],
            "versions":["3.0"]}]}"#,
        );
        let name = Ecosystem::PyPI.normalize_name("foo.bar");
        assert!(r.affects(Ecosystem::PyPI, &name, "1.5").is_some());
        assert!(r.affects(Ecosystem::PyPI, &name, "1.5.1").is_none());
        assert!(r.affects(Ecosystem::PyPI, &name, "0.9").is_none());
        assert!(r.affects(Ecosystem::PyPI, &name, "3.0").is_some());
    }

    #[test]
    fn introduced_zero_sorts_before_pseudo_version_fixes() {
        let r = rec(
            r#"{"id":"X","affected":[{"package":{"ecosystem":"Go","name":"m"},
            "ranges":[{"type":"SEMVER","events":[{"introduced":"0"},
            {"fixed":"0.0.0-20210520170846-37e1c6afe023"}]}]}]}"#,
        );
        assert!(r.affects(Ecosystem::Go, "m", "v0.7.0").is_none());
        assert!(
            r.affects(Ecosystem::Go, "m", "v0.0.0-20190101000000-abcdef")
                .is_some()
        );
    }

    #[test]
    fn symbol_refs_from_go_and_rust_shapes() {
        let go = rec(
            r#"{"id":"GO-1","affected":[{"package":{"ecosystem":"Go","name":"golang.org/x/net"},
            "ecosystem_specific":{"imports":[{"path":"golang.org/x/net/html","symbols":["Parse"]}]}}]}"#,
        );
        let refs = go.symbol_refs(Ecosystem::Go, "golang.org/x/net");
        assert_eq!(
            refs,
            vec![SymbolRef {
                path: "golang.org/x/net/html".into(),
                symbols: vec!["Parse".into()]
            }]
        );
        let rust = rec(
            r#"{"id":"R","affected":[{"package":{"ecosystem":"crates.io","name":"smallvec"},
            "ecosystem_specific":{"functions":["smallvec::SmallVec::insert_many"]}}]}"#,
        );
        let refs = rust.symbol_refs(Ecosystem::CratesIo, "smallvec");
        assert_eq!(refs[0].path, "smallvec::SmallVec");
        assert_eq!(refs[0].symbols, vec!["insert_many"]);
        assert!(rust.symbol_refs(Ecosystem::Go, "smallvec").is_empty());
    }

    #[test]
    fn trimming_keeps_only_symbol_data() {
        let raw = serde_json::json!({
            "affected_functions": null,
            "affects": {"arch": [], "os": [], "functions": ["a::b::c", "a::b::c"]},
            "imports": [{"path": "p", "symbols": ["S"], "goos": ["linux"]}],
            "noise": [1, 2, 3]
        });
        let t = trim_ecosystem_specific(Some(raw)).expect("kept");
        assert_eq!(t["functions"], serde_json::json!(["a::b::c"]));
        assert_eq!(
            t["imports"][0],
            serde_json::json!({"path": "p", "symbols": ["S"]})
        );
        assert!(t.get("noise").is_none());
        assert!(trim_ecosystem_specific(Some(serde_json::json!({"x": 1}))).is_none());
        assert!(trim_ecosystem_specific(Some(serde_json::json!("str"))).is_none());
        assert!(trim_ecosystem_specific(None).is_none());
    }

    #[test]
    fn git_ranges_are_ignored() {
        let r = rec(
            r#"{"id":"X","affected":[{"package":{"ecosystem":"Go","name":"m"},
            "ranges":[{"type":"GIT","events":[{"introduced":"0"}]}]}]}"#,
        );
        assert!(r.affects(Ecosystem::Go, "m", "v1.0.0").is_none());
    }

    #[test]
    fn scoring_and_labels() {
        let r = rec(SAMPLE);
        assert_eq!(r.cvss_score(), Some(9.8));
        assert_eq!(r.severity_bucket(), Severity::Critical);
        assert_eq!(r.cwes(), vec!["CWE-1321"]);
        assert_eq!(r.cve_ids(), vec!["CVE-2026-1"]);
        let label_only = rec(r#"{"id":"Y","database_specific":{"severity":"MODERATE"}}"#);
        assert_eq!(label_only.severity_bucket(), Severity::Medium);
        let none = rec(r#"{"id":"Z"}"#);
        assert_eq!(none.severity_bucket(), Severity::Unknown);
    }

    #[test]
    fn informational_notices_are_flagged() {
        let r = rec(r#"{"id":"RUSTSEC-1","database_specific":{"informational":"unmaintained"}}"#);
        assert!(r.is_informational_only());
        let r = rec(r#"{"id":"RUSTSEC-2","database_specific":{"informational":"unsound"}}"#);
        assert!(!r.is_informational_only());
    }
}
