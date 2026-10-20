//! Turns the event log into the numbers and lists the report shows.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use crate::Event;

const SEVERITIES: [&str; 5] = ["critical", "high", "medium", "low", "unknown"];

fn weight(sev: &str) -> u32 {
    match sev {
        "critical" => 10,
        "high" => 7,
        "medium" => 4,
        "low" => 1,
        _ => 2,
    }
}

fn str_of<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(|x| x.as_str()).unwrap_or("")
}

fn array_of<'a>(v: &'a Value, key: &str) -> &'a [Value] {
    v.get(key)
        .and_then(|x| x.as_array())
        .map_or(&[], Vec::as_slice)
}

fn day(ts: &str) -> &str {
    ts.get(..10).unwrap_or(ts)
}

fn matches_id(finding: &Value, id: &str) -> bool {
    str_of(finding, "id") == id
        || array_of(finding, "aliases")
            .iter()
            .any(|a| a.as_str() == Some(id))
}

/// What the latest scan did not check, as one line each: its own notes, lockfiles it could not
/// read, and requirement lines it could not match. The report shows these next to the findings so
/// "0 findings" is never read as "all clear".
fn scan_notes(e: &Event) -> Value {
    let mut out: Vec<Value> = array_of(&e.data, "notes").to_vec();
    for label in ["skipped", "unchecked"] {
        for pair in array_of(&e.data, label) {
            let (Some(file), Some(why)) = (
                pair.get(0).and_then(Value::as_str),
                pair.get(1).and_then(Value::as_str),
            ) else {
                continue;
            };
            out.push(Value::String(format!("{label} {file}: {why}")));
        }
    }
    Value::Array(out)
}

/// The projects that appear in the log, most recently active first.
pub fn workspaces(events: &[Event]) -> Vec<Value> {
    let mut by: BTreeMap<&str, (&str, usize)> = BTreeMap::new();
    for e in events {
        let slot = by.entry(e.workspace.as_str()).or_insert((e.ts.as_str(), 0));
        if e.ts.as_str() > slot.0 {
            slot.0 = e.ts.as_str();
        }
        slot.1 += 1;
    }
    let mut list: Vec<_> = by.into_iter().collect();
    list.sort_by(|a, b| b.1.0.cmp(a.1.0));
    list.into_iter()
        .map(|(w, (ts, n))| json!({ "path": w, "last_event": ts, "events": n }))
        .collect()
}

/// Finds the advisory details for `id` in the newest scan event at or before `ts`.
fn lookup_finding(evs: &[&Event], ts: &str, id: &str) -> Option<Value> {
    evs.iter()
        .rev()
        .filter(|e| e.kind == "scan" && e.ts.as_str() <= ts)
        .find_map(|e| {
            array_of(&e.data, "findings")
                .iter()
                .find(|f| matches_id(f, id))
                .cloned()
        })
}

/// Everything the report needs for one project (or the most recent one when `workspace` is `None`).
pub fn summarize(events: &[Event], workspace: Option<&str>) -> Value {
    let all_ws = workspaces(events);
    let selected: Option<String> = workspace.map(str::to_string).or_else(|| {
        all_ws
            .first()
            .and_then(|w| str_of(w, "path").to_string().into())
    });
    let Some(ws) = selected else {
        return json!({ "workspaces": all_ws, "workspace": null, "empty": true });
    };
    let evs: Vec<&Event> = events.iter().filter(|e| e.workspace == ws).collect();
    let scans: Vec<&&Event> = evs.iter().filter(|e| e.kind == "scan").collect();
    let latest_scan = scans.last();
    let latest_code = evs.iter().rev().find(|e| e.kind == "scan_code");

    let timeline: Vec<Value> = scans
        .iter()
        .map(|e| {
            json!({
                "ts": e.ts,
                "total": e.data.get("total").cloned().unwrap_or(json!(0)),
                "by_severity": e.data.get("by_severity").cloned().unwrap_or(json!({})),
                "exploited": e.data.get("exploited").cloned().unwrap_or(json!(0)),
            })
        })
        .collect();

    let findings: Vec<Value> = latest_scan
        .map(|e| array_of(&e.data, "findings").to_vec())
        .unwrap_or_default();

    let mut sev_now: BTreeMap<&str, usize> = SEVERITIES.iter().map(|s| (*s, 0)).collect();
    let mut reach: BTreeMap<String, usize> = BTreeMap::new();
    let mut packages: BTreeMap<String, (usize, u32, bool, String)> = BTreeMap::new();
    for f in &findings {
        let sev = str_of(f, "severity");
        if let Some(c) = sev_now.get_mut(sev) {
            *c += 1;
        }
        let level = f
            .get("reach")
            .and_then(|r| r.get("level"))
            .and_then(|l| l.as_str())
            .unwrap_or("not_checked");
        *reach.entry(level.to_string()).or_default() += 1;
        let key = format!("{}@{}", str_of(f, "package"), str_of(f, "version"));
        let slot = packages
            .entry(key)
            .or_insert((0, 0, false, sev.to_string()));
        slot.0 += 1;
        slot.1 += weight(sev);
        slot.2 |= f
            .get("exploited")
            .and_then(|x| x.as_bool())
            .unwrap_or(false);
        if weight(sev) > weight(&slot.3) {
            slot.3 = sev.to_string();
        }
    }
    let mut top: Vec<_> = packages.into_iter().collect();
    top.sort_by(|a, b| {
        (b.1.2 as u32 * 100 + b.1.1)
            .cmp(&(a.1.2 as u32 * 100 + a.1.1))
            .then(a.0.cmp(&b.0))
    });
    let top_packages: Vec<Value> = top
        .into_iter()
        .take(10)
        .map(|(name, (count, score, kev, sev))| json!({ "package": name, "findings": count, "score": score, "exploited": kev, "severity": sev }))
        .collect();

    // Fix history: verified resolutions and AI-recorded changes.
    let mut resolved_ids: BTreeSet<String> = BTreeSet::new();
    let mut fixes: Vec<Value> = Vec::new();
    for e in &evs {
        match e.kind.as_str() {
            "verify_fix" => {
                let resolved: Vec<String> = array_of(&e.data, "resolved")
                    .iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect();
                if resolved.is_empty() {
                    continue;
                }
                let trustworthy = e
                    .data
                    .get("trustworthy")
                    .and_then(|x| x.as_bool())
                    .unwrap_or(false);
                if trustworthy {
                    resolved_ids.extend(resolved.iter().cloned());
                }
                let details: Vec<Value> = resolved
                    .iter()
                    .filter_map(|id| lookup_finding(&evs, &e.ts, id))
                    .collect();
                fixes.push(json!({
                    "kind": "verified", "ts": e.ts, "client": e.client, "ids": resolved,
                    "trustworthy": trustworthy, "findings": details,
                }));
            }
            "record_fix" => {
                let mut v = e.data.clone();
                if let Some(o) = v.as_object_mut() {
                    o.insert("kind".into(), json!("recorded"));
                    o.insert("ts".into(), json!(e.ts));
                    o.insert("client".into(), json!(e.client));
                }
                fixes.push(v);
            }
            _ => {}
        }
    }
    // A recorded fix counts as verified when a later re-scan resolved any of its ids.
    let verifications: Vec<(&str, BTreeSet<&str>)> = evs
        .iter()
        .filter(|e| {
            e.kind == "verify_fix"
                && e.data.get("trustworthy").and_then(|x| x.as_bool()) == Some(true)
        })
        .map(|e| {
            (
                e.ts.as_str(),
                array_of(&e.data, "resolved")
                    .iter()
                    .filter_map(|x| x.as_str())
                    .collect(),
            )
        })
        .collect();
    for f in fixes.iter_mut().filter(|f| str_of(f, "kind") == "recorded") {
        let ts = str_of(f, "ts").to_string();
        let ids: Vec<String> = array_of(f, "ids")
            .iter()
            .filter_map(|x| x.as_str().map(str::to_string))
            .collect();
        let verified = verifications
            .iter()
            .any(|(vts, set)| *vts >= ts.as_str() && ids.iter().any(|i| set.contains(i.as_str())));
        if let Some(o) = f.as_object_mut() {
            o.insert("verified".into(), json!(verified));
        }
    }
    fixes.reverse();

    // Per-day activity.
    let mut activity: BTreeMap<String, (usize, usize, usize)> = BTreeMap::new();
    for e in &evs {
        let d = day(&e.ts).to_string();
        let slot = activity.entry(d).or_default();
        match e.kind.as_str() {
            "scan" | "scan_code" => slot.0 += 1,
            "record_fix" => slot.1 += 1,
            "verify_fix" => slot.2 += array_of(&e.data, "resolved").len(),
            _ => {}
        }
    }
    let activity: Vec<Value> = activity
        .into_iter()
        .map(|(d, (scans, recorded, resolved))| json!({ "day": d, "scans": scans, "recorded_fixes": recorded, "resolved": resolved }))
        .collect();

    let open_high = sev_now["critical"] + sev_now["high"];
    let exploited_open = findings
        .iter()
        .filter(|f| {
            f.get("exploited")
                .and_then(|x| x.as_bool())
                .unwrap_or(false)
        })
        .count();
    let used_open = findings
        .iter()
        .filter(|f| {
            f.get("reach")
                .and_then(|r| r.get("level"))
                .and_then(|l| l.as_str())
                == Some("used_symbol")
        })
        .count();

    json!({
        "empty": false,
        "workspaces": all_ws,
        "workspace": ws,
        "generated_events": evs.len(),
        "kpis": {
            "open": findings.len(),
            "open_critical_high": open_high,
            "exploited_open": exploited_open,
            "used_in_code": used_open,
            "resolved_verified": resolved_ids.len(),
            "recorded_fixes": fixes.iter().filter(|f| str_of(f, "kind") == "recorded").count(),
            "scans": scans.len(),
            "code_suspected": latest_code.map_or(0, |e| e.data.get("total").and_then(|x| x.as_u64()).unwrap_or(0)),
            "last_scan": latest_scan.map(|e| e.ts.clone()),
            "packages_checked": latest_scan.map_or(0, |e| e.data.get("packages_checked").and_then(|x| x.as_u64()).unwrap_or(0)),
        },
        "severity_now": sev_now,
        "reachability": reach,
        "top_packages": top_packages,
        "timeline": timeline,
        "activity": activity,
        "findings": findings,
        "data_sources": latest_scan.map(|e| e.data.get("data_sources").cloned().unwrap_or(json!([]))),
        "notes": latest_scan.map(|e| scan_notes(e)),
        "code": latest_code.map(|e| json!({
            "ts": e.ts,
            "files_scanned": e.data.get("files_scanned"),
            "by_severity": e.data.get("by_severity"),
            "external": e.data.get("external"),
            "findings": e.data.get("findings"),
        })),
        "fixes": fixes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(ts: &str, kind: &str, ws: &str, data: Value) -> Event {
        Event {
            v: 1,
            ts: ts.into(),
            kind: kind.into(),
            workspace: ws.into(),
            client: Some("claude-code".into()),
            data,
        }
    }

    fn finding(id: &str, pkg: &str, sev: &str, exploited: bool, reach: &str) -> Value {
        json!({"id": id, "aliases": [format!("CVE-{id}")], "package": pkg, "version": "1.0.0", "severity": sev,
               "exploited": exploited, "reach": {"level": reach}, "summary": "s", "refs": ["https://r"]})
    }

    fn sample() -> Vec<Event> {
        vec![
            ev(
                "2026-10-18T09:00:00Z",
                "scan",
                "/a",
                json!({
                "total": 3, "by_severity": {"critical": 1, "high": 1, "medium": 1, "low": 0, "unknown": 0}, "exploited": 1,
                "packages_checked": 40, "data_sources": [{"ecosystem": "npm"}], "notes": ["n"],
                "findings": [finding("G1", "lodash", "critical", true, "used_symbol"), finding("G2", "minimist", "high", false, "not_found"), finding("G3", "x", "medium", false, "imported")]}),
            ),
            ev(
                "2026-10-19T10:00:00Z",
                "record_fix",
                "/a",
                json!({"ids": ["G1"], "summary": "bumped", "reason": "r", "changes": []}),
            ),
            ev(
                "2026-10-19T10:05:00Z",
                "verify_fix",
                "/a",
                json!({"ids": ["G1"], "resolved": ["G1"], "trustworthy": true}),
            ),
            ev(
                "2026-10-19T10:06:00Z",
                "scan",
                "/a",
                json!({
                "total": 2, "by_severity": {"critical": 0, "high": 1, "medium": 1, "low": 0, "unknown": 0}, "exploited": 0, "packages_checked": 40,
                "findings": [finding("G2", "minimist", "high", false, "not_found"), finding("G3", "x", "medium", false, "imported")]}),
            ),
            ev(
                "2026-10-19T10:07:00Z",
                "scan_code",
                "/a",
                json!({"total": 1, "files_scanned": 9, "findings": [{"rule": "js-eval"}]}),
            ),
            ev(
                "2026-10-17T00:00:00Z",
                "scan",
                "/old",
                json!({"total": 0, "findings": []}),
            ),
        ]
    }

    #[test]
    fn workspaces_are_ordered_by_recent_activity() {
        let w = workspaces(&sample());
        assert_eq!(w[0]["path"], "/a");
        assert_eq!(w[0]["events"], 5);
        assert_eq!(w[1]["path"], "/old");
    }

    #[test]
    fn summary_numbers_and_fix_history() {
        let s = summarize(&sample(), None);
        assert_eq!(s["workspace"], "/a");
        let k = &s["kpis"];
        assert_eq!(
            (
                k["open"].as_u64(),
                k["open_critical_high"].as_u64(),
                k["exploited_open"].as_u64()
            ),
            (Some(2), Some(1), Some(0))
        );
        assert_eq!(
            (
                k["resolved_verified"].as_u64(),
                k["recorded_fixes"].as_u64(),
                k["scans"].as_u64()
            ),
            (Some(1), Some(1), Some(2))
        );
        assert_eq!(k["code_suspected"], 1);
        assert_eq!(s["timeline"].as_array().expect("arr").len(), 2);
        assert_eq!(s["severity_now"]["high"], 1);
        assert_eq!(s["reachability"]["not_found"], 1);
        assert_eq!(s["top_packages"][0]["package"], "minimist@1.0.0");

        let fixes = s["fixes"].as_array().expect("arr");
        assert_eq!(fixes.len(), 2);
        assert_eq!(fixes[0]["kind"], "verified", "newest first");
        assert_eq!(
            fixes[0]["findings"][0]["package"], "lodash",
            "details come from the scan before the fix"
        );
        assert_eq!(fixes[1]["kind"], "recorded");
        assert_eq!(fixes[1]["verified"], true);
        let day = s["activity"]
            .as_array()
            .expect("arr")
            .iter()
            .find(|d| d["day"] == "2026-10-19")
            .expect("day")
            .clone();
        assert_eq!(
            (
                day["recorded_fixes"].as_u64(),
                day["resolved"].as_u64(),
                day["scans"].as_u64()
            ),
            (Some(1), Some(1), Some(2))
        );
    }

    #[test]
    fn unverified_and_untrusted_fixes_are_not_counted_as_resolved() {
        let mut evs = sample();
        evs.retain(|e| e.kind != "verify_fix");
        evs.push(ev(
            "2026-10-19T10:30:00Z",
            "verify_fix",
            "/a",
            json!({"resolved": ["G1"], "trustworthy": false}),
        ));
        let s = summarize(&evs, Some("/a"));
        assert_eq!(s["kpis"]["resolved_verified"], 0);
        let recorded = s["fixes"]
            .as_array()
            .expect("arr")
            .iter()
            .find(|f| f["kind"] == "recorded")
            .expect("rec")
            .clone();
        assert_eq!(recorded["verified"], false);
    }

    #[test]
    fn empty_log_and_unknown_workspace() {
        let s = summarize(&[], None);
        assert_eq!(s["empty"], true);
        let s = summarize(&sample(), Some("/nope"));
        assert_eq!(s["kpis"]["open"], 0);
        assert!(s["fixes"].as_array().expect("arr").is_empty());
    }
}
