//! CVEs that NVD lists for a product at a version, read from an NVD 2.0 `cpeName` response.
//!
//! NVD is the right source for the products that lockfile advisories never cover (PHP, nginx, a
//! database server): it records them as CPE version ranges, not as package coordinates. The API
//! filters by CPE, but this module still evaluates the ranges itself, because the filter also
//! returns old entries that name every version of a product, and those are not evidence about a
//! particular version. They are counted and reported as left out, never dropped quietly.

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::evaluate::compare;

/// One CVE that applies to a product at a version.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeCve {
    /// `CVE-YYYY-NNNN`.
    pub id: String,
    /// Publication date (`YYYY-MM-DD`).
    pub published: Option<String>,
    /// First sentence or so of NVD's English description.
    pub summary: String,
    /// CVSS base score (v3.1, else v4.0, else v3.0).
    pub cvss: Option<f32>,
    /// CWE ids (`CWE-416`); NVD placeholders such as `NVD-CWE-Other` are dropped.
    pub cwes: Vec<String>,
    /// The version ranges NVD gives, as text, limited to the ones that contain the version.
    pub affects: Vec<String>,
    /// Listed in CISA's Known Exploited Vulnerabilities catalogue.
    pub known_exploited: bool,
    /// EPSS probability of exploitation in the next 30 days.
    pub epss: Option<f32>,
}

/// What an NVD lookup for one product at one version found.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NvdOutcome {
    /// The CVEs, most urgent first (see [`rank`]).
    pub cves: Vec<RuntimeCve>,
    /// Entries that list every version of the product, so say nothing about this one.
    pub all_versions_omitted: usize,
    /// True when NVD has more results than one response carried.
    pub truncated: bool,
    /// Why the lookup did not happen or failed. `None` means NVD answered.
    pub error: Option<String>,
}

impl NvdOutcome {
    /// A lookup that did not happen or failed, with the reason.
    pub fn failed(why: impl Into<String>) -> NvdOutcome {
        NvdOutcome {
            error: Some(why.into()),
            ..NvdOutcome::default()
        }
    }
}

/// One version constraint from a `cpeMatch` entry.
enum Constraint {
    /// The CPE names every version.
    All,
    /// The CPE names exactly one version.
    Exact(String),
    /// `*` with bounds.
    Range {
        start: Option<(String, bool)>,
        end: Option<(String, bool)>,
    },
}

impl Constraint {
    fn contains(&self, version: &str) -> bool {
        match self {
            Constraint::All => false,
            Constraint::Exact(v) => compare(version, v) == Ordering::Equal,
            Constraint::Range { start, end } => {
                let above = start.as_ref().is_none_or(|(s, inclusive)| {
                    let o = compare(version, s);
                    o == Ordering::Greater || (*inclusive && o == Ordering::Equal)
                });
                let below = end.as_ref().is_none_or(|(e, inclusive)| {
                    let o = compare(version, e);
                    o == Ordering::Less || (*inclusive && o == Ordering::Equal)
                });
                above && below
            }
        }
    }

    fn describe(&self) -> String {
        match self {
            Constraint::All => "every version".into(),
            Constraint::Exact(v) => format!("= {v}"),
            Constraint::Range { start, end } => {
                let lo = start
                    .as_ref()
                    .map(|(s, inc)| format!("{s} {}", if *inc { "<=" } else { "<" }));
                let hi = end
                    .as_ref()
                    .map(|(e, inc)| format!("{} {e}", if *inc { "<=" } else { "<" }));
                match (lo, hi) {
                    (Some(l), Some(h)) => format!("{l} v {h}"),
                    (Some(l), None) => format!("{l} v"),
                    (None, Some(h)) => format!("v {h}"),
                    (None, None) => "every version".into(),
                }
            }
        }
    }
}

/// CVSS base score and CWE ids from one NVD `cve` object.
pub fn score_and_cwes(cve: &Value) -> (Option<f32>, Vec<String>) {
    let mut cvss = None;
    for key in ["cvssMetricV31", "cvssMetricV40", "cvssMetricV30"] {
        let Some(list) = cve
            .get("metrics")
            .and_then(|m| m.get(key))
            .and_then(Value::as_array)
        else {
            continue;
        };
        let chosen = list
            .iter()
            .find(|m| m.get("type").and_then(Value::as_str) == Some("Primary"))
            .or_else(|| list.first());
        if let Some(score) = chosen
            .and_then(|m| m.get("cvssData"))
            .and_then(|d| d.get("baseScore"))
            .and_then(Value::as_f64)
        {
            cvss = Some(score as f32);
            break;
        }
    }
    let mut cwes: Vec<String> = Vec::new();
    for w in cve
        .get("weaknesses")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        for d in w
            .get("description")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(val) = d.get("value").and_then(Value::as_str)
                && val.starts_with("CWE-")
                && !cwes.iter().any(|c| c == val)
            {
                cwes.push(val.to_string());
            }
        }
    }
    (cvss, cwes)
}

/// The constraints a CVE's configurations put on `cpe` (`cpe:2.3:a:php:php`).
fn constraints(cve: &Value, cpe: &str) -> Vec<Constraint> {
    let prefix = format!("{cpe}:");
    let mut out = Vec::new();
    for cfg in cve
        .get("configurations")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        for node in cfg
            .get("nodes")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            for m in node
                .get("cpeMatch")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if m.get("vulnerable").and_then(Value::as_bool) != Some(true) {
                    continue;
                }
                let Some(criteria) = m.get("criteria").and_then(Value::as_str) else {
                    continue;
                };
                if !criteria.starts_with(&prefix) {
                    continue;
                }
                let component = criteria.split(':').nth(5).unwrap_or("*");
                let bound = |inc: &str, exc: &str| -> Option<(String, bool)> {
                    if let Some(v) = m.get(inc).and_then(Value::as_str) {
                        Some((v.to_string(), true))
                    } else {
                        m.get(exc)
                            .and_then(Value::as_str)
                            .map(|v| (v.to_string(), false))
                    }
                };
                let start = bound("versionStartIncluding", "versionStartExcluding");
                let end = bound("versionEndIncluding", "versionEndExcluding");
                out.push(match component {
                    "*" if start.is_none() && end.is_none() => Constraint::All,
                    "*" => Constraint::Range { start, end },
                    "-" => continue,
                    v => Constraint::Exact(v.to_string()),
                });
            }
        }
    }
    out
}

/// Reads an NVD 2.0 response for `cpe` at `version`.
pub fn parse_cpe_response(doc: &Value, cpe: &str, version: &str) -> NvdOutcome {
    let mut out = NvdOutcome::default();
    let list = doc
        .get("vulnerabilities")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let total = doc.get("totalResults").and_then(Value::as_u64).unwrap_or(0);
    out.truncated = total > list.len() as u64;
    for v in list {
        let Some(cve) = v.get("cve") else { continue };
        let Some(id) = cve.get("id").and_then(Value::as_str) else {
            continue;
        };
        let cs = constraints(cve, cpe);
        let matching: Vec<String> = cs
            .iter()
            .filter(|c| c.contains(version))
            .map(Constraint::describe)
            .collect();
        let only_all = !cs.is_empty() && cs.iter().all(|c| matches!(c, Constraint::All));
        if only_all {
            out.all_versions_omitted += 1;
            continue;
        }
        // NVD said this CVE applies, but no range we can read contains the version (a range in a
        // shape this parser does not know). Keep it and say so rather than lose a real finding.
        let affects = if matching.is_empty() {
            vec!["NVD lists this version (its range was not parsed)".to_string()]
        } else {
            matching
        };
        let (cvss, cwes) = score_and_cwes(cve);
        let summary = cve
            .get("descriptions")
            .and_then(Value::as_array)
            .and_then(|d| {
                d.iter()
                    .find(|x| x.get("lang").and_then(Value::as_str) == Some("en"))
            })
            .and_then(|d| d.get("value"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .chars()
            .take(200)
            .collect();
        out.cves.push(RuntimeCve {
            id: id.to_string(),
            published: cve
                .get("published")
                .and_then(Value::as_str)
                .map(|p| p.chars().take(10).collect()),
            summary,
            cvss,
            cwes,
            affects,
            known_exploited: false,
            epss: None,
        });
    }
    out
}

/// Most urgent first: exploited in the wild, then an EPSS of 10% or more, then CVSS, then id.
pub fn rank(cves: &mut [RuntimeCve]) {
    cves.sort_by(|a, b| {
        let hot = |c: &RuntimeCve| c.epss.is_some_and(|e| e >= 0.1);
        b.known_exploited
            .cmp(&a.known_exploited)
            .then(hot(b).cmp(&hot(a)))
            .then(b.cvss.partial_cmp(&a.cvss).unwrap_or(Ordering::Equal))
            .then(a.id.cmp(&b.id))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const CPE: &str = "cpe:2.3:a:php:php";

    fn cve(id: &str, matches: Value) -> Value {
        json!({"cve":{"id":id,"published":"2026-10-21T14:00:00.000",
            "descriptions":[{"lang":"es","value":"x"},{"lang":"en","value":"PHP uses longjmp()"}],
            "metrics":{"cvssMetricV31":[{"type":"Primary","cvssData":{"baseScore":9.2}}]},
            "weaknesses":[{"description":[{"value":"CWE-416"},{"value":"NVD-CWE-Other"}]}],
            "configurations":[{"nodes":[{"cpeMatch": matches}]}]}})
    }

    fn range(start: Option<&str>, end_excl: &str) -> Value {
        let mut m = json!({"vulnerable":true,"criteria":"cpe:2.3:a:php:php:*:*:*:*:*:*:*:*",
            "versionEndExcluding": end_excl});
        if let Some(s) = start {
            m["versionStartIncluding"] = json!(s);
        }
        m
    }

    fn response(items: Vec<Value>) -> Value {
        json!({"totalResults": items.len(), "vulnerabilities": items})
    }

    #[test]
    fn the_range_that_contains_the_version_is_reported() {
        let doc = response(vec![cve(
            "CVE-2026-109618",
            json!([
                range(None, "8.2.35"),
                range(Some("8.3.0"), "8.3.36"),
                range(Some("8.4.0"), "8.4.27")
            ]),
        )]);
        let r = parse_cpe_response(&doc, CPE, "8.4.26");
        assert_eq!(r.cves.len(), 1);
        let c = &r.cves[0];
        assert_eq!(c.id, "CVE-2026-109618");
        assert_eq!(c.affects, vec!["8.4.0 <= v < 8.4.27"]);
        assert_eq!(
            (c.cvss, c.cwes.clone()),
            (Some(9.2), vec!["CWE-416".to_string()])
        );
        assert_eq!(c.published.as_deref(), Some("2026-10-21"));
        assert_eq!(c.summary, "PHP uses longjmp()");
        // 7.4.33 is below the first range's open start: that range still contains it.
        let old = parse_cpe_response(&doc, CPE, "7.4.33");
        assert_eq!(old.cves[0].affects, vec!["v < 8.2.35"]);
        assert!(!r.truncated && r.error.is_none());
    }

    #[test]
    fn entries_naming_every_version_are_counted_not_listed() {
        let all = json!([{"vulnerable":true,"criteria":"cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"}]);
        let doc = response(vec![
            cve("CVE-2007-3205", all),
            cve("CVE-2026-109618", json!([range(None, "8.2.35")])),
        ]);
        let r = parse_cpe_response(&doc, CPE, "8.2.30");
        assert_eq!(r.all_versions_omitted, 1);
        assert_eq!(r.cves.len(), 1);
    }

    #[test]
    fn exact_versions_and_other_products_are_handled() {
        let doc = response(vec![
            cve(
                "CVE-1",
                json!([{"vulnerable":true,"criteria":"cpe:2.3:a:php:php:7.4.33:*:*:*:*:*:*:*"}]),
            ),
            cve(
                "CVE-2",
                json!([{"vulnerable":true,"criteria":"cpe:2.3:a:other:thing:*:*:*:*:*:*:*:*","versionEndExcluding":"9"}]),
            ),
            cve(
                "CVE-3",
                json!([{"vulnerable":false,"criteria":"cpe:2.3:a:php:php:*:*:*:*:*:*:*:*","versionEndExcluding":"9"}]),
            ),
        ]);
        let r = parse_cpe_response(&doc, CPE, "7.4.33");
        let ids: Vec<&str> = r.cves.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["CVE-1", "CVE-2", "CVE-3"],
            "the API's own filter is trusted over our reading"
        );
        assert_eq!(r.cves[0].affects, vec!["= 7.4.33"]);
        assert!(
            r.cves[1].affects[0].contains("not parsed"),
            "an unreadable range is kept and flagged, not lost: {:?}",
            r.cves[1].affects
        );
    }

    #[test]
    fn truncated_responses_are_flagged_and_bad_input_is_empty() {
        let mut doc = response(vec![]);
        doc["totalResults"] = json!(5000);
        assert!(parse_cpe_response(&doc, CPE, "1.0").truncated);
        assert_eq!(
            parse_cpe_response(&json!({}), CPE, "1.0"),
            NvdOutcome::default()
        );
        assert_eq!(NvdOutcome::failed("x").error.as_deref(), Some("x"));
    }

    #[test]
    fn ranking_puts_exploited_then_likely_then_severe_first() {
        let mk = |id: &str, cvss: f32, kev: bool, epss: Option<f32>| RuntimeCve {
            id: id.into(),
            published: None,
            summary: String::new(),
            cvss: Some(cvss),
            cwes: vec![],
            affects: vec![],
            known_exploited: kev,
            epss,
        };
        let mut v = vec![
            mk("D-severe", 9.8, false, Some(0.001)),
            mk("C-likely", 5.0, false, Some(0.5)),
            mk("B-kev", 4.0, true, None),
            mk("A-severe-too", 9.8, false, None),
        ];
        rank(&mut v);
        let ids: Vec<&str> = v.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, vec!["B-kev", "C-likely", "A-severe-too", "D-severe"]);
    }
}
