//! Building and recording events from engine results.

use std::path::Path;

use opencraysec_core::{Finding, Severity};
use opencraysec_engine::{CodeReport, FixPlan, RuntimeReport, ScanReport, VerifyOutcome};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::snapshot::{self, Change};
use crate::{Event, EventLog};

/// At most this many findings are stored per scan event.
const MAX_FINDINGS: usize = 300;
const MAX_TEXT: usize = 4000;
const MAX_LIST: usize = 100;

/// A finding reduced to what the report needs.
pub fn compact_finding(f: &Finding) -> Value {
    json!({
        "id": f.id,
        "aliases": f.aliases.iter().take(4).collect::<Vec<_>>(),
        "ecosystem": f.package.ecosystem.osv_name(),
        "package": f.package.name,
        "version": f.package.version,
        "source": f.package.source,
        "dev": f.package.dev,
        "severity": f.severity.as_str(),
        "cvss": f.cvss,
        "cwes": f.cwes,
        "exploited": f.known_exploited,
        "epss": f.epss,
        "fixed_in": f.fixed_in.iter().take(4).collect::<Vec<_>>(),
        "reach": f.reachability.as_ref().map(|r| json!({
            "level": r.level,
            "evidence": r.evidence.iter().take(2).collect::<Vec<_>>(),
        })),
        "summary": f.summary,
        "refs": f.references.iter().take(3).collect::<Vec<_>>(),
    })
}

fn severity_counts<'a>(sevs: impl Iterator<Item = &'a Severity>) -> Value {
    let (mut c, mut h, mut m, mut l, mut u) = (0, 0, 0, 0, 0);
    for s in sevs {
        match s {
            Severity::Critical => c += 1,
            Severity::High => h += 1,
            Severity::Medium => m += 1,
            Severity::Low => l += 1,
            Severity::Unknown => u += 1,
        }
    }
    json!({ "critical": c, "high": h, "medium": m, "low": l, "unknown": u })
}

/// The event for a finished dependency scan.
pub fn scan_event(r: &ScanReport, client: Option<&str>) -> Event {
    let findings: Vec<Value> = r
        .findings
        .iter()
        .take(MAX_FINDINGS)
        .map(compact_finding)
        .collect();
    Event::new(
        "scan",
        &r.root,
        client,
        json!({
            "packages_checked": r.packages_checked,
            "lockfiles": r.lockfiles,
            "data_sources": r.data_sources,
            "notes": r.notes,
            "skipped": r.skipped,
            "unchecked": r.unchecked,
            "total": r.findings.len(),
            "by_severity": severity_counts(r.findings.iter().map(|f| &f.severity)),
            "exploited": r.findings.iter().filter(|f| f.known_exploited).count(),
            "findings": findings,
        }),
    )
}

/// Every advisory id and alias that scans of `workspace` have reported so far. `verify_fix` uses it
/// as the proof that a finding existed here before it was fixed.
pub fn seen_finding_ids(log: &EventLog, workspace: &str) -> Vec<String> {
    let mut ids: Vec<String> = Vec::new();
    for e in log
        .read_all()
        .iter()
        .filter(|e| e.kind == "scan" && e.workspace == workspace)
    {
        let findings = e.data.get("findings").and_then(Value::as_array);
        for f in findings.into_iter().flatten() {
            let own = f.get("id").and_then(Value::as_str);
            let aliases = f
                .get("aliases")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str);
            ids.extend(own.into_iter().chain(aliases).map(str::to_string));
        }
    }
    ids.sort();
    ids.dedup();
    ids
}

/// The event for a finished code scan.
pub fn code_event(r: &CodeReport, client: Option<&str>) -> Event {
    let findings: Vec<Value> = r
        .findings
        .iter()
        .take(MAX_FINDINGS)
        .map(|f| {
            json!({
                "rule": f.rule, "title": f.title, "cwe": f.cwe, "severity": f.severity.as_str(),
                "file": f.file, "line": f.line, "source": f.source, "advice": f.advice,
            })
        })
        .collect();
    Event::new(
        "scan_code",
        &r.root,
        client,
        json!({
            "files_scanned": r.files_scanned,
            "total": r.findings.len(),
            "by_severity": severity_counts(r.findings.iter().map(|f| &f.severity)),
            "external": r.external,
            "findings": findings,
        }),
    )
}

fn status_of(s: impl Serialize) -> String {
    serde_json::to_value(s)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// The event for a runtime scan: what each product was judged to be and, when NVD was asked, the
/// CVEs it listed. `workspace` is the project the runtime belongs to (the runtime itself is not a path).
pub fn runtime_event(workspace: &str, r: &RuntimeReport, client: Option<&str>) -> Event {
    let results: Vec<Value> = r
        .results
        .iter()
        .take(MAX_LIST)
        .map(|x| {
            let nvd = x.nvd.as_ref().map(|n| {
                // The struct's own serialization, so scores print the same here as in `--format json`.
                let cves: Vec<Value> = n
                    .cves
                    .iter()
                    .take(MAX_LIST)
                    .filter_map(|c| serde_json::to_value(c).ok())
                    .collect();
                json!({
                    "cves": cves, "total": n.cves.len(),
                    "all_versions_omitted": n.all_versions_omitted,
                    "truncated": n.truncated, "error": n.error,
                })
            });
            json!({
                "product": x.product, "version": x.version, "source": x.source,
                "status": status_of(x.status), "cycle": x.cycle, "eol_from": x.eol_from,
                "latest": x.latest, "patches_behind": x.patches_behind,
                "advice": x.advice, "nvd": nvd,
            })
        })
        .collect();
    let count = |s: &str| {
        r.results
            .iter()
            .filter(|x| status_of(x.status) == s)
            .count()
    };
    Event::new(
        "scan_runtime",
        workspace,
        client,
        json!({
            "total": r.results.len(),
            "by_status": {
                "eol": count("eol"), "outdated": count("outdated"),
                "current": count("current"), "unknown": count("unknown"),
            },
            "data": r.data,
            "notes": r.notes.iter().take(MAX_LIST).map(|n| n.chars().take(MAX_TEXT).collect::<String>()).collect::<Vec<_>>(),
            "results": results,
        }),
    )
}

/// The event for a fix plan.
pub fn plan_event(workspace: &str, plan: &FixPlan, client: Option<&str>) -> Event {
    Event::new(
        "plan_fix",
        workspace,
        client,
        json!({ "steps": plan.steps, "unfixable": plan.unfixable }),
    )
}

/// The event for a verification re-scan.
pub fn verify_event(
    workspace: &str,
    ids: &[String],
    v: &VerifyOutcome,
    client: Option<&str>,
) -> Event {
    Event::new(
        "verify_fix",
        workspace,
        client,
        json!({
            "ids": ids,
            "resolved": v.resolved,
            "unknown": v.unknown,
            "remaining": v.remaining.iter().map(|f| f.id.clone()).collect::<Vec<_>>(),
            "trustworthy": v.trustworthy,
            "total_findings_now": v.total_findings_now,
        }),
    )
}

/// Records a scan and snapshots the dependency set it saw.
pub fn log_scan(log: &EventLog, r: &ScanReport, client: Option<&str>) -> std::io::Result<()> {
    let ev = scan_event(r, client);
    log.save_snapshot(&r.root, &snapshot::take(&ev.ts, &r.all_packages))?;
    log.append(&ev)
}

/// What an AI (or a person) reports after making a change, like a commit message.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixInput {
    /// Advisory ids the change addresses.
    pub ids: Vec<String>,
    /// What was changed.
    pub summary: String,
    /// Why (the reasoning behind the change).
    #[serde(default)]
    pub reason: String,
    /// Files that were edited.
    #[serde(default)]
    pub files: Vec<String>,
    /// Commands that were run.
    #[serde(default)]
    pub commands: Vec<String>,
    /// Git commit, if one was made.
    #[serde(default)]
    pub commit: String,
}

impl FixInput {
    /// Rejects empty or oversized input.
    pub fn validate(&self) -> Result<(), String> {
        if self.ids.is_empty() {
            return Err("ids is required: the advisory ids this change addresses".into());
        }
        if self.summary.trim().is_empty() {
            return Err("summary is required: say what was changed".into());
        }
        let long = |s: &str| s.chars().count() > MAX_TEXT;
        if long(&self.summary) || long(&self.reason) || long(&self.commit) {
            return Err(format!(
                "summary, reason and commit are limited to {MAX_TEXT} characters"
            ));
        }
        if self.ids.len() > MAX_LIST
            || self.files.len() > MAX_LIST
            || self.commands.len() > MAX_LIST
        {
            return Err(format!(
                "ids, files and commands are limited to {MAX_LIST} entries each"
            ));
        }
        if self
            .files
            .iter()
            .chain(&self.commands)
            .chain(&self.ids)
            .any(|s| long(s))
        {
            return Err(format!("list entries are limited to {MAX_TEXT} characters"));
        }
        Ok(())
    }
}

/// Result of [`record_fix`].
#[derive(Debug, Clone, Serialize)]
pub struct Recorded {
    /// Time of the recorded event.
    pub recorded_at: String,
    /// Dependency changes found by comparing the lockfile with the last different snapshot.
    pub changes: Vec<Change>,
    /// False when there was no earlier snapshot to compare with.
    pub baseline_found: bool,
    /// Ids that the last scan did not contain.
    pub unknown_ids: Vec<String>,
}

/// Records a fix: the caller's description, plus what actually changed in the lockfiles.
///
/// The change list is computed here by comparing dependency snapshots, so the report does not
/// rely on the caller's word alone. The caller's text is stored as `ai_reported`.
pub fn record_fix(
    log: &EventLog,
    workspace: &str,
    root: &Path,
    input: &FixInput,
    client: Option<&str>,
) -> Result<Recorded, String> {
    input.validate()?;
    let disc = opencraysec_lockfile::discover(root, None);
    let now = Event::new("record_fix", workspace, client, Value::Null);
    let after = snapshot::take(&now.ts, &disc.packages);
    let before = log
        .snapshots(workspace)
        .into_iter()
        .rev()
        .find(|s| s.hash != after.hash);
    let changes = before
        .as_ref()
        .map(|b| snapshot::diff(b, &after))
        .unwrap_or_default();

    let last_scan = log
        .read_all()
        .into_iter()
        .rev()
        .find(|e| e.kind == "scan" && e.workspace == workspace);
    let known: Vec<Value> = last_scan
        .as_ref()
        .and_then(|e| e.data.get("findings").and_then(|f| f.as_array()).cloned())
        .unwrap_or_default();
    let mut details = Vec::new();
    let mut unknown_ids = Vec::new();
    for id in &input.ids {
        let hit = known.iter().find(|f| {
            f.get("id").and_then(|x| x.as_str()) == Some(id)
                || f.get("aliases")
                    .and_then(|a| a.as_array())
                    .is_some_and(|a| a.iter().any(|x| x.as_str() == Some(id)))
        });
        match hit {
            Some(f) => details.push(f.clone()),
            None => unknown_ids.push(id.clone()),
        }
    }

    let ev = Event {
        data: json!({
            "source": "ai_reported",
            "ids": input.ids,
            "summary": input.summary,
            "reason": input.reason,
            "files": input.files,
            "commands": input.commands,
            "commit": input.commit,
            "changes": changes,
            "baseline_found": before.is_some(),
            "findings": details,
            "unknown_ids": unknown_ids,
        }),
        ..now
    };
    log.append(&ev)
        .map_err(|e| format!("could not write the log: {e}"))?;
    let _ = log.save_snapshot(workspace, &after);
    Ok(Recorded {
        recorded_at: ev.ts,
        changes,
        baseline_found: before.is_some(),
        unknown_ids,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use opencraysec_engine::{
        DataInfo, NvdOutcome, ProductResult, RuntimeCve, RuntimeReport, RuntimeStatus,
    };
    use std::fs;

    fn runtime_result(
        product: &str,
        version: &str,
        status: RuntimeStatus,
        nvd: Option<NvdOutcome>,
    ) -> ProductResult {
        ProductResult {
            product: product.into(),
            version: version.into(),
            source: "given".into(),
            status,
            cycle: Some("7.4".into()),
            eol_from: Some("2022-11-28".into()),
            latest: Some("7.4.33".into()),
            patches_behind: None,
            advice: "move to a supported line".into(),
            nvd,
        }
    }

    #[test]
    fn a_runtime_scan_event_keeps_the_verdicts_and_the_cves() {
        let cve = RuntimeCve {
            id: "CVE-2026-109618".into(),
            published: Some("2026-10-21".into()),
            summary: "PHP uses longjmp()".into(),
            cvss: Some(9.8),
            cwes: vec!["CWE-416".into()],
            affects: vec!["v < 8.2.35".into()],
            known_exploited: true,
            epss: Some(0.4),
        };
        let report = RuntimeReport {
            scanned_at: "2026-10-22T07:00:00Z".into(),
            data: DataInfo {
                lifecycle_updated_at: Some("2026-10-22T06:00:00Z".into()),
                vendor_updated_at: vec![],
            },
            results: vec![
                runtime_result(
                    "php",
                    "7.4.33",
                    RuntimeStatus::Eol,
                    Some(NvdOutcome {
                        cves: vec![cve],
                        all_versions_omitted: 1,
                        truncated: false,
                        error: None,
                    }),
                ),
                runtime_result("nginx", "1.28.0", RuntimeStatus::Current, None),
                runtime_result(
                    "redis",
                    "7.0.0",
                    RuntimeStatus::Unknown,
                    Some(NvdOutcome::failed("rate limited")),
                ),
            ],
            notes: vec!["a note".into()],
        };
        let ev = runtime_event("/proj", &report, Some("cli"));
        assert_eq!(
            (ev.kind.as_str(), ev.workspace.as_str()),
            ("scan_runtime", "/proj")
        );
        assert_eq!(ev.client.as_deref(), Some("cli"));
        let d = &ev.data;
        assert_eq!(d["total"], 3);
        assert_eq!(
            d["by_status"],
            json!({"eol": 1, "outdated": 0, "current": 1, "unknown": 1})
        );
        assert_eq!(d["data"]["lifecycle_updated_at"], "2026-10-22T06:00:00Z");
        assert_eq!(d["notes"][0], "a note");
        let php = &d["results"][0];
        assert_eq!(
            (&php["product"], &php["status"]),
            (&json!("php"), &json!("eol"))
        );
        assert_eq!(php["nvd"]["total"], 1);
        assert_eq!(php["nvd"]["all_versions_omitted"], 1);
        let c = &php["nvd"]["cves"][0];
        assert_eq!(
            (&c["id"], &c["cvss"], &c["known_exploited"]),
            (&json!("CVE-2026-109618"), &json!(9.8), &json!(true))
        );
        assert_eq!(c["affects"][0], "v < 8.2.35");
        assert!(
            d["results"][1]["nvd"].is_null(),
            "NVD was not asked for nginx"
        );
        assert_eq!(d["results"][2]["nvd"]["error"], "rate limited");
    }

    fn lock(version: &str) -> String {
        format!(
            r#"{{"lockfileVersion":3,"packages":{{"node_modules/lodash":{{"version":"{version}"}}}}}}"#
        )
    }

    fn seed_scan(log: &EventLog, ws: &str) {
        log.append(&Event::new(
            "scan",
            ws,
            Some("test"),
            json!({"findings":[{"id":"GHSA-1","aliases":["CVE-2026-0001"],"package":"lodash","severity":"high","summary":"bad","refs":["https://x"]}]}),
        ))
        .expect("append");
    }

    #[test]
    fn seen_ids_cover_ids_and_aliases_of_this_workspace_only() {
        let dir = tempfile::tempdir().expect("tmp");
        let log = EventLog::at(dir.path().join("log"));
        seed_scan(&log, "/a");
        log.append(&Event::new(
            "scan",
            "/b",
            None,
            json!({"findings":[{"id":"GHSA-OTHER","aliases":[]}]}),
        ))
        .expect("append");
        // Only scans count: a plan or a verification does not prove a finding existed.
        log.append(&Event::new(
            "verify_fix",
            "/a",
            None,
            json!({"findings":[{"id":"GHSA-NOT-A-SCAN"}]}),
        ))
        .expect("append");
        assert_eq!(
            seen_finding_ids(&log, "/a"),
            vec!["CVE-2026-0001".to_string(), "GHSA-1".to_string()]
        );
        assert!(seen_finding_ids(&log, "/nowhere").is_empty());
    }

    #[test]
    fn scan_events_keep_what_was_not_checked() {
        let report = ScanReport {
            root: "/p".into(),
            scanned_at: "t".into(),
            lockfiles: vec!["requirements.txt".into()],
            skipped: vec![("big.lock".into(), "too large".into())],
            unchecked: vec![("requirements.txt".into(), "2 lines".into())],
            packages_checked: 0,
            data_sources: vec![],
            notes: vec![],
            informational_omitted: 0,
            findings: vec![],
            packages: vec![],
            all_packages: vec![],
        };
        let ev = scan_event(&report, None);
        assert_eq!(ev.data["unchecked"][0][0], "requirements.txt");
        assert_eq!(ev.data["skipped"][0][1], "too large");
        // The dashboard and the exported HTML read these through the summary's notes.
        let notes = crate::summary::summarize(&[ev], Some("/p"))["notes"].to_string();
        assert!(
            notes.contains("unchecked requirements.txt: 2 lines"),
            "{notes}"
        );
        assert!(notes.contains("skipped big.lock: too large"), "{notes}");
    }

    #[test]
    fn validation_rejects_empty_and_oversized_input() {
        let ok = FixInput {
            ids: vec!["A".into()],
            summary: "bumped".into(),
            ..FixInput::default()
        };
        assert!(ok.validate().is_ok());
        assert!(
            FixInput {
                ids: vec![],
                ..ok.clone()
            }
            .validate()
            .is_err()
        );
        assert!(
            FixInput {
                summary: "  ".into(),
                ..ok.clone()
            }
            .validate()
            .is_err()
        );
        assert!(
            FixInput {
                reason: "x".repeat(MAX_TEXT + 1),
                ..ok.clone()
            }
            .validate()
            .is_err()
        );
        assert!(
            FixInput {
                files: vec!["f".into(); MAX_LIST + 1],
                ..ok.clone()
            }
            .validate()
            .is_err()
        );
        assert!(
            FixInput {
                commands: vec!["x".repeat(MAX_TEXT + 1)],
                ..ok
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn record_fix_computes_real_changes_from_snapshots() {
        let dir = tempfile::tempdir().expect("tmp");
        let log = EventLog::at(dir.path().join("log"));
        let proj = dir.path().join("proj");
        fs::create_dir_all(&proj).expect("mkdir");
        let ws = proj.display().to_string();

        fs::write(proj.join("package-lock.json"), lock("4.17.4")).expect("w");
        let disc = opencraysec_lockfile::discover(&proj, None);
        log.save_snapshot(&ws, &snapshot::take("2026-10-19T10:00:00Z", &disc.packages))
            .expect("snap");
        seed_scan(&log, &ws);

        fs::write(proj.join("package-lock.json"), lock("4.17.21")).expect("w");
        let input = FixInput {
            ids: vec!["CVE-2026-0001".into(), "GHSA-missing".into()],
            summary: "Upgrade lodash".into(),
            reason: "Prototype pollution".into(),
            files: vec!["package-lock.json".into()],
            commands: vec!["npm install lodash@4.17.21".into()],
            commit: "abc123".into(),
        };
        let rec = record_fix(&log, &ws, &proj, &input, Some("claude-code")).expect("record");
        assert!(rec.baseline_found);
        assert_eq!(rec.changes.len(), 1);
        assert_eq!(
            (rec.changes[0].from.clone(), rec.changes[0].to.clone()),
            (vec!["4.17.4".to_string()], vec!["4.17.21".to_string()])
        );
        assert_eq!(rec.unknown_ids, vec!["GHSA-missing"]);

        let ev = log
            .read_all()
            .into_iter()
            .find(|e| e.kind == "record_fix")
            .expect("event");
        assert_eq!(ev.client.as_deref(), Some("claude-code"));
        assert_eq!(ev.data["source"], "ai_reported");
        assert_eq!(
            ev.data["findings"][0]["id"], "GHSA-1",
            "alias lookup attaches the advisory details"
        );
        assert_eq!(ev.data["commit"], "abc123");

        // Recording again with no further change finds nothing new to diff against.
        let again = record_fix(
            &log,
            &ws,
            &proj,
            &FixInput {
                ids: vec!["GHSA-1".into()],
                summary: "noop".into(),
                ..FixInput::default()
            },
            None,
        )
        .expect("record");
        assert_eq!(
            again.changes.len(),
            1,
            "diff is against the last different snapshot"
        );
        assert!(record_fix(&log, &ws, &proj, &FixInput::default(), None).is_err());
    }

    #[test]
    fn record_fix_without_baseline_says_so() {
        let dir = tempfile::tempdir().expect("tmp");
        let log = EventLog::at(dir.path().join("log"));
        let proj = dir.path().join("p");
        fs::create_dir_all(&proj).expect("mkdir");
        fs::write(proj.join("package-lock.json"), lock("1.0.0")).expect("w");
        let input = FixInput {
            ids: vec!["X".into()],
            summary: "s".into(),
            ..FixInput::default()
        };
        let rec =
            record_fix(&log, &proj.display().to_string(), &proj, &input, None).expect("record");
        assert!(!rec.baseline_found && rec.changes.is_empty());
    }
}
