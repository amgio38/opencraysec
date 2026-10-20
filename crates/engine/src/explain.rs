//! Look up one advisory and describe it, with CWE names for the common weakness classes.

use std::fs;
use std::io::{BufRead, BufReader};

use opencraysec_core::osv::OsvRecord;
use opencraysec_core::{Ecosystem, Severity};
use opencraysec_db::{Store, online};
use serde::Serialize;

use crate::EngineError;

/// A CWE reference.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CweInfo {
    /// `CWE-79`.
    pub id: String,
    /// Name, when it is one of the built-in common weaknesses.
    pub name: Option<String>,
    /// Short description (needs the downloaded catalog).
    pub description: Option<String>,
    /// MITRE page.
    pub url: String,
}

/// A readable view of one advisory.
#[derive(Debug, Clone, Serialize)]
pub struct Explanation {
    /// Advisory id.
    pub id: String,
    /// Other ids.
    pub aliases: Vec<String>,
    /// Summary.
    pub summary: String,
    /// Description (may be truncated).
    pub details: String,
    /// Severity bucket.
    pub severity: Severity,
    /// CVSS base score.
    pub cvss: Option<f32>,
    /// Weakness classes.
    pub cwes: Vec<CweInfo>,
    /// Listed by CISA as exploited in the wild.
    pub known_exploited: bool,
    /// EPSS probability.
    pub epss: Option<f32>,
    /// `ecosystem package` pairs the advisory names.
    pub affected: Vec<String>,
    /// Links.
    pub references: Vec<String>,
    /// `local` or `online`.
    pub source: String,
}

const CWE_NAMES: &[(u32, &str)] = &[
    (20, "Improper Input Validation"),
    (22, "Path Traversal"),
    (74, "Injection"),
    (77, "Command Injection"),
    (78, "OS Command Injection"),
    (79, "Cross-site Scripting"),
    (89, "SQL Injection"),
    (94, "Code Injection"),
    (116, "Improper Encoding or Escaping of Output"),
    (119, "Memory Buffer Errors"),
    (125, "Out-of-bounds Read"),
    (190, "Integer Overflow or Wraparound"),
    (200, "Exposure of Sensitive Information"),
    (254, "Security Features"),
    (284, "Improper Access Control"),
    (287, "Improper Authentication"),
    (295, "Improper Certificate Validation"),
    (306, "Missing Authentication for Critical Function"),
    (319, "Cleartext Transmission of Sensitive Information"),
    (327, "Use of a Broken or Risky Cryptographic Algorithm"),
    (345, "Insufficient Verification of Data Authenticity"),
    (352, "Cross-Site Request Forgery"),
    (400, "Uncontrolled Resource Consumption"),
    (416, "Use After Free"),
    (434, "Unrestricted Upload of Dangerous File Type"),
    (476, "NULL Pointer Dereference"),
    (502, "Deserialization of Untrusted Data"),
    (601, "Open Redirect"),
    (611, "XML External Entity Reference"),
    (639, "Authorization Bypass Through User-Controlled Key"),
    (693, "Protection Mechanism Failure"),
    (787, "Out-of-bounds Write"),
    (798, "Use of Hard-coded Credentials"),
    (862, "Missing Authorization"),
    (863, "Incorrect Authorization"),
    (918, "Server-Side Request Forgery"),
    (
        943,
        "Improper Neutralization of Special Elements in Data Query Logic",
    ),
    (1321, "Prototype Pollution"),
    (1333, "Inefficient Regular Expression Complexity"),
];

/// Describes a CWE id such as `CWE-79`: from the downloaded MITRE catalog when present, else from
/// a built-in list of common weaknesses.
pub fn cwe_info(store: &Store, id: &str) -> CweInfo {
    let num: Option<u32> = id.strip_prefix("CWE-").and_then(|n| n.parse().ok());
    let entry = num.and_then(|n| store.cwe(n));
    CweInfo {
        id: id.to_string(),
        description: entry
            .as_ref()
            .map(|e| e.description.clone())
            .filter(|d| !d.is_empty()),
        name: entry.map(|e| e.name).or_else(|| {
            num.and_then(|n| {
                CWE_NAMES
                    .iter()
                    .find(|(k, _)| *k == n)
                    .map(|(_, v)| v.to_string())
            })
        }),
        url: match num {
            Some(n) => format!("https://cwe.mitre.org/data/definitions/{n}.html"),
            None => "https://cwe.mitre.org/".to_string(),
        },
    }
}

fn find_local(store: &Store, id: &str) -> Option<OsvRecord> {
    for eco in Ecosystem::ALL {
        let Ok(file) = fs::File::open(
            store
                .dir()
                .join("osv")
                .join(format!("{}.jsonl", eco.osv_name())),
        ) else {
            continue;
        };
        for line in BufReader::new(file).lines().map_while(Result::ok) {
            if !line.contains(id) {
                continue;
            }
            let Some((_, body)) = line.split_once('\t') else {
                continue;
            };
            if let Ok(rec) = serde_json::from_str::<OsvRecord>(body)
                && (rec.id == id || rec.aliases.iter().any(|a| a == id))
            {
                return Some(rec);
            }
        }
    }
    None
}

/// Explains an advisory by id or alias (`GHSA-...`, `CVE-...`, `RUSTSEC-...`).
pub fn explain(store: &Store, id: &str, offline: bool) -> Result<Explanation, EngineError> {
    let id = id.trim();
    if id.is_empty() || id.len() > 64 || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err(EngineError(format!("not a valid advisory id: {id:?}")));
    }
    let (rec, source) = match find_local(store, id) {
        Some(r) => (r, "local"),
        None if offline => {
            return Err(EngineError(format!(
                "{id} is not in the local database (offline mode)"
            )));
        }
        None => (online::fetch_by_id(store, id)?, "online"),
    };
    let mut ids: Vec<String> = rec.cve_ids();
    ids.push(rec.id.clone());
    let set: std::collections::HashSet<String> = ids.into_iter().collect();
    let epss = store
        .epss(&set)
        .values()
        .copied()
        .fold(None, |a: Option<f32>, x| Some(a.map_or(x, |y| y.max(x))));
    let kev = store.kev();
    Ok(Explanation {
        id: rec.id.clone(),
        aliases: rec.aliases.clone(),
        summary: rec.summary.clone().unwrap_or_default(),
        details: rec.details.clone().unwrap_or_default(),
        severity: rec.severity_bucket(),
        cvss: rec.cvss_score(),
        cwes: rec.cwes().iter().map(|c| cwe_info(store, c)).collect(),
        known_exploited: set.iter().any(|i| kev.contains(i)),
        epss,
        affected: {
            let mut a: Vec<String> = rec
                .affected
                .iter()
                .filter_map(|a| a.package.as_ref())
                .map(|p| format!("{} {}", p.ecosystem, p.name))
                .collect();
            a.sort();
            a.dedup();
            a
        },
        references: rec.references.iter().map(|r| r.url.clone()).collect(),
        source: source.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cwe_lookup() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = Store::at(dir.path());
        assert_eq!(
            cwe_info(&store, "CWE-79").name.as_deref(),
            Some("Cross-site Scripting")
        );
        assert_eq!(
            cwe_info(&store, "CWE-79").url,
            "https://cwe.mitre.org/data/definitions/79.html"
        );
        assert_eq!(cwe_info(&store, "CWE-99999").name, None);
        assert_eq!(cwe_info(&store, "weird").url, "https://cwe.mitre.org/");
        std::fs::write(
            dir.path().join("cwe.tsv"),
            "#updated_at=t\n99999\tMade Up\tIt is made up.\n",
        )
        .expect("w");
        let c = cwe_info(&store, "CWE-99999");
        assert_eq!(
            (c.name.as_deref(), c.description.as_deref()),
            (Some("Made Up"), Some("It is made up."))
        );
    }

    #[test]
    fn rejects_bad_ids_and_offline_misses() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = Store::at(dir.path());
        assert!(explain(&store, "../etc/passwd", true).is_err());
        assert!(explain(&store, "", true).is_err());
        assert!(explain(&store, "GHSA-nope", true).is_err());
    }

    #[test]
    fn finds_local_by_alias() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = Store::at(dir.path());
        let rec: OsvRecord = serde_json::from_str(
            r#"{"id":"GHSA-1","aliases":["CVE-2026-5"],"summary":"s",
              "affected":[{"package":{"ecosystem":"Go","name":"m"}}],
              "database_specific":{"cwe_ids":["CWE-79"]}}"#,
        )
        .expect("json");
        fs::create_dir_all(dir.path().join("osv")).expect("mkdir");
        let line = opencraysec_db::encode_line(Ecosystem::Go, &rec)
            .expect("enc")
            .expect("some");
        fs::write(dir.path().join("osv/Go.jsonl"), line + "\n").expect("w");
        let e = explain(&store, "CVE-2026-5", true).expect("found");
        assert_eq!(e.id, "GHSA-1");
        assert_eq!(e.source, "local");
        assert_eq!(e.cwes[0].name.as_deref(), Some("Cross-site Scripting"));
        assert_eq!(e.affected, vec!["Go m"]);
    }
}
