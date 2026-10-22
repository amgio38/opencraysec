//! End-to-end scan, enrichment and verification flows against local data and a mock server.
#![allow(clippy::expect_used)]

use std::fs;
use std::path::Path;

use opencraysec_core::osv::OsvRecord;
use opencraysec_core::{Ecosystem, Severity};
use opencraysec_db::testutil::{MockServer, Route};
use opencraysec_db::{Endpoints, Store, encode_line};
use opencraysec_engine::{ScanOptions, report, scan, verify_fix};

fn store_with(dir: &Path, server: Option<&MockServer>) -> Store {
    let store = Store::at(dir.join("data"));
    match server {
        Some(s) => store.with_endpoints(Endpoints {
            osv_dump: s.base.clone(),
            osv_api: format!("{}/v1", s.base),
            nvd: format!("{}/nvd", s.base),
            eol: format!("{}/eol", s.base),
            php_releases: format!("{}/php", s.base),
            nvd_gap_ms: Some(0),
            ..Endpoints::default()
        }),
        None => store,
    }
}

fn write_go_data(store: &Store, records: &[String]) {
    let osv = store.dir().join("osv");
    fs::create_dir_all(&osv).expect("mkdir");
    let lines: Vec<String> = records
        .iter()
        .map(|r| {
            let rec: OsvRecord = serde_json::from_str(r).expect("json");
            encode_line(Ecosystem::Go, &rec)
                .expect("enc")
                .expect("some")
        })
        .collect();
    fs::write(osv.join("Go.jsonl"), lines.join("\n") + "\n").expect("w");
    fs::write(
        osv.join("Go.meta.json"),
        r#"{"updated_at":"t","records":1,"schema":2}"#,
    )
    .expect("w");
}

fn go_advisory(id: &str, cve: &str, fixed: &str) -> String {
    format!(
        r#"{{"id":"{id}","aliases":["{cve}"],"summary":"s {id}",
        "affected":[{{"package":{{"ecosystem":"Go","name":"example.com/m"}},
        "ranges":[{{"type":"SEMVER","events":[{{"introduced":"0"}},{{"fixed":"{fixed}"}}]}}],
        "ecosystem_specific":{{"imports":[{{"path":"example.com/m/p","symbols":["F"]}}]}}}}]}}"#
    )
}

fn go_project(dir: &Path, version: &str, code: &str) -> std::path::PathBuf {
    let p = dir.join("proj");
    fs::create_dir_all(&p).expect("mkdir");
    fs::write(
        p.join("go.mod"),
        format!("module x\nrequire example.com/m {version}\n"),
    )
    .expect("w");
    fs::write(p.join("main.go"), code).expect("w");
    p
}

const USES_F: &str = "package main\nimport \"example.com/m/p\"\nfunc main() { p.F() }\n";

#[test]
fn nvd_enrichment_scores_unscored_findings_and_caches() {
    let nvd_body = r#"{"vulnerabilities":[{"cve":{"metrics":{"cvssMetricV31":[{"type":"Primary","cvssData":{"baseScore":9.1}}]},
        "weaknesses":[{"description":[{"value":"CWE-918"}]}]}}]}"#;
    let server = MockServer::start(vec![Route::get("/nvd?cveId=CVE-2026-0007", nvd_body)]);
    let dir = tempfile::tempdir().expect("tmp");
    let store = store_with(dir.path(), Some(&server));
    write_go_data(&store, &[go_advisory("GO-7", "CVE-2026-0007", "1.5.0")]);
    let proj = go_project(dir.path(), "v1.0.0", USES_F);

    let plain = scan(&store, &proj, &ScanOptions::default()).expect("scan");
    assert_eq!(plain.findings[0].severity, Severity::Unknown);
    assert!(
        plain
            .notes
            .iter()
            .any(|n| n.contains("enrich_nvd") || n.contains("--enrich-nvd"))
    );
    assert!(
        server.requests().is_empty(),
        "no network without enrich_nvd"
    );

    let opts = ScanOptions {
        enrich_nvd: true,
        ..ScanOptions::default()
    };
    let r = scan(&store, &proj, &opts).expect("scan");
    let f = &r.findings[0];
    assert_eq!((f.severity, f.cvss), (Severity::Critical, Some(9.1)));
    assert!(f.cwes.contains(&"CWE-918".to_string()));
    assert_eq!(f.reachability.as_ref().expect("reach").level, "used_symbol");
    assert_eq!(server.requests().len(), 1);

    let again = scan(&store, &proj, &plain_opts()).expect("scan");
    assert_eq!(
        again.findings[0].cvss,
        Some(9.1),
        "cached score is used without enrich_nvd"
    );
    assert_eq!(server.requests().len(), 1);
}

fn plain_opts() -> ScanOptions {
    ScanOptions::default()
}

#[test]
fn nvd_limits_failures_and_offline_are_reported() {
    let dir = tempfile::tempdir().expect("tmp");
    let records: Vec<String> = (1..=17)
        .map(|i| {
            format!(
                r#"{{"id":"GO-{i}","aliases":["CVE-2026-{i:04}"],"affected":[{{"package":{{"ecosystem":"Go","name":"example.com/m"}},
                "ranges":[{{"type":"SEMVER","events":[{{"introduced":"0"}},{{"fixed":"9.0.0"}}]}}]}}]}}"#
            )
        })
        .collect();
    let server = MockServer::start(vec![]); // every NVD request is a 404
    let store = store_with(dir.path(), Some(&server));
    write_go_data(&store, &records);
    let proj = go_project(dir.path(), "v1.0.0", "package main\n");
    let opts = ScanOptions {
        enrich_nvd: true,
        ..ScanOptions::default()
    };
    let r = scan(&store, &proj, &opts).expect("scan");
    assert_eq!(r.findings.len(), 17);
    assert!(r.notes.iter().any(|n| n.contains("lookup(s) failed")));
    assert!(r.notes.iter().any(|n| n.contains("limit 15")));
    assert_eq!(server.requests().len(), 15);
    let offline = ScanOptions {
        enrich_nvd: true,
        offline: true,
        ..ScanOptions::default()
    };
    let before = server.requests().len();
    scan(&store, &proj, &offline).expect("scan");
    assert_eq!(server.requests().len(), before, "offline never calls NVD");
}

#[test]
fn online_fallback_when_an_ecosystem_has_no_local_data() {
    let adv = r#"{"id":"GHSA-9","modified":"m","summary":"proto","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "affected":[{"package":{"ecosystem":"npm","name":"lodash"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}"#;
    let server = MockServer::start(vec![
        Route::post(
            "/v1/querybatch",
            r#"{"results":[{"vulns":[{"id":"GHSA-9","modified":"m"}]}]}"#,
        ),
        Route::get("/v1/vulns/GHSA-9", adv),
    ]);
    let dir = tempfile::tempdir().expect("tmp");
    let store = store_with(dir.path(), Some(&server));
    let proj = dir.path().join("web");
    fs::create_dir_all(&proj).expect("mkdir");
    fs::write(proj.join("package-lock.json"), r#"{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.4","dev":true}}}"#).expect("w");
    fs::write(proj.join("index.js"), "const _ = require('lodash');\n").expect("w");

    let r = scan(&store, &proj, &ScanOptions::default()).expect("scan");
    assert_eq!(r.data_sources[0].mode, "online");
    assert_eq!(r.findings[0].severity, Severity::Critical);
    assert_eq!(r.findings[0].fixed_in, vec!["4.17.21"]);
    assert_eq!(
        r.findings[0].reachability.as_ref().expect("r").level,
        "imported"
    );
    assert!(r.notes.iter().any(|n| n.contains("api.osv.dev")));

    let no_dev = ScanOptions {
        include_dev: false,
        ..ScanOptions::default()
    };
    assert_eq!(
        scan(&store, &proj, &no_dev).expect("scan").packages_checked,
        0
    );
    let rust_only = ScanOptions {
        ecosystems: Some(vec![Ecosystem::CratesIo]),
        ..ScanOptions::default()
    };
    assert_eq!(
        scan(&store, &proj, &rust_only)
            .expect("scan")
            .packages_checked,
        0
    );

    let text = report::text(&r);
    assert!(text.contains("usage: your code imports it"), "{text}");
    let sbom = report::cyclonedx(&r);
    assert_eq!(sbom["components"][0]["purl"], "pkg:npm/lodash@4.17.4");
}

/// Ids an earlier scan of the project would have reported.
fn seen(ids: &[&str]) -> Vec<String> {
    ids.iter().map(|s| s.to_string()).collect()
}

#[test]
fn verify_fix_proves_resolution_and_flags_untrustworthy_scans() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = store_with(dir.path(), None);
    write_go_data(&store, &[go_advisory("GO-1", "CVE-2026-0001", "1.2.0")]);
    let proj = go_project(dir.path(), "v1.0.0", USES_F);
    let opts = ScanOptions {
        offline: true,
        ..ScanOptions::default()
    };
    let ids = vec!["GO-1".to_string()];
    let before_scan = seen(&["GO-1", "CVE-2026-0001"]);

    let before = verify_fix(&store, &proj, &opts, &ids, &before_scan).expect("verify");
    assert_eq!((before.resolved.len(), before.remaining.len()), (0, 1));
    assert!(before.trustworthy);

    fs::write(
        proj.join("go.mod"),
        "module x\nrequire example.com/m v1.3.0\n",
    )
    .expect("w");
    let after = verify_fix(&store, &proj, &opts, &ids, &before_scan).expect("verify");
    assert_eq!(after.resolved, ids);
    assert!(after.remaining.is_empty() && after.unknown.is_empty() && after.trustworthy);
    assert_eq!(after.total_findings_now, 0);

    let alias = verify_fix(
        &store,
        &proj,
        &opts,
        &["CVE-2026-0001".to_string()],
        &before_scan,
    )
    .expect("verify");
    assert_eq!(alias.resolved.len(), 1);

    // Without an earlier scan nothing proves the finding was ever here.
    let no_history = verify_fix(&store, &proj, &opts, &ids, &[]).expect("verify");
    assert!(no_history.resolved.is_empty());
    assert_eq!(no_history.unknown, ids);
    assert!(no_history.notes.iter().any(|n| n.contains("earlier scan")));

    // The other half of "trustworthy": every conjunct must hold on its own.
    fs::write(
        proj.join("package-lock.json"),
        r#"{"packages":{"node_modules/a":{"version":"1.0.0"}}}"#,
    )
    .expect("w");
    let partial = verify_fix(&store, &proj, &opts, &ids, &before_scan).expect("verify");
    assert!(
        !partial.trustworthy,
        "npm was not scanned offline, so 'resolved' proves nothing"
    );
    fs::remove_file(proj.join("package-lock.json")).expect("rm");

    fs::write(proj.join("requirements.txt"), "flask>=2.0\n").expect("w");
    let unchecked = verify_fix(&store, &proj, &opts, &ids, &before_scan).expect("verify");
    assert!(
        !unchecked.trustworthy,
        "an unpinned requirement was not checked"
    );
    fs::remove_file(proj.join("requirements.txt")).expect("rm");

    fs::write(proj.join("Cargo.lock"), "this is not toml [[").expect("w");
    let skipped = verify_fix(&store, &proj, &opts, &ids, &before_scan).expect("verify");
    assert!(!skipped.trustworthy, "an unreadable lockfile was skipped");
}

#[test]
fn verify_fix_is_not_fooled_by_display_filters_or_unrelated_ids() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = store_with(dir.path(), None);
    // GO-OTHER is a real advisory in the database, but for a module this project never had.
    let other = go_advisory("GO-OTHER", "CVE-2026-0002", "1.2.0")
        .replace("example.com/m", "example.com/unrelated");
    write_go_data(
        &store,
        &[go_advisory("GO-1", "CVE-2026-0001", "1.2.0"), other],
    );
    let proj = go_project(dir.path(), "v1.0.0", USES_F);
    // GO-1 has no severity, so it falls below a `high` display threshold.
    let opts = ScanOptions {
        offline: true,
        min_severity: Severity::High,
        ..ScanOptions::default()
    };
    let earlier = seen(&["GO-1", "CVE-2026-0001"]);
    let v = verify_fix(&store, &proj, &opts, &["GO-1".to_string()], &earlier).expect("verify");
    assert!(v.resolved.is_empty(), "still vulnerable: {v:?}");
    assert_eq!(v.remaining.len(), 1);

    // A vulnerability is still present (total 1) while an unrelated id is verified.
    let ids = vec!["GO-OTHER".to_string(), "GHSA-does-not-exist".to_string()];
    let v = verify_fix(&store, &proj, &opts, &ids, &earlier).expect("verify");
    assert!(v.resolved.is_empty(), "{v:?}");
    assert_eq!(v.unknown, ids);
    assert_eq!(v.total_findings_now, 1);

    // The same unrelated id on a project that is now clean is still not "resolved".
    fs::write(
        proj.join("go.mod"),
        "module x\nrequire example.com/m v1.3.0\n",
    )
    .expect("w");
    let v = verify_fix(&store, &proj, &opts, &ids, &earlier).expect("verify");
    assert!(v.resolved.is_empty() && v.trustworthy, "{v:?}");
    assert_eq!(v.unknown, ids);
}

#[test]
fn unpinned_requirements_are_reported_not_silently_dropped() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = store_with(dir.path(), None);
    let proj = dir.path().join("py");
    fs::create_dir_all(&proj).expect("mkdir");
    fs::write(proj.join("requirements.txt"), "flask>=2.0\n-r other.txt\n").expect("w");
    let opts = ScanOptions {
        offline: true,
        ..ScanOptions::default()
    };
    let r = scan(&store, &proj, &opts).expect("scan");
    assert_eq!(r.packages_checked, 0);
    assert_eq!(r.unchecked.len(), 1, "{:?}", r.unchecked);
    let text = report::text(&r);
    assert!(text.contains("unchecked requirements.txt"), "{text}");
    assert!(
        !text.contains("does not prove"),
        "no false clean result: {text}"
    );
    assert!(
        report::sarif(&r)["runs"][0]["properties"]["unchecked"][0]["reason"]
            .as_str()
            .is_some_and(|s| s.contains("2 requirement line"))
    );
}

#[test]
fn a_scan_that_checked_nothing_is_not_a_clean_result() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = store_with(dir.path(), None);
    let proj = go_project(dir.path(), "v1.0.0", USES_F);
    let opts = ScanOptions {
        offline: true,
        ..ScanOptions::default()
    };
    // No advisory data at all and no network: every package is unscanned.
    let r = scan(&store, &proj, &opts).expect("scan");
    assert!(r.findings.is_empty());
    assert!(r.unscanned() && r.is_incomplete());
    let text = report::text(&r);
    assert!(
        !text.contains("does not prove"),
        "no false clean result: {text}"
    );
    assert!(text.contains("incomplete"), "{text}");
}

/// The two definitions are one hierarchy: whatever fails a CI gate is also "incomplete", and the
/// report text and the gate cannot disagree about an empty or unmatchable project.
#[test]
fn the_gate_and_the_report_agree_on_what_was_not_checked() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = store_with(dir.path(), None);
    write_go_data(&store, &[go_advisory("GO-1", "CVE-2026-0001", "1.2.0")]);
    let opts = ScanOptions {
        offline: true,
        ..ScanOptions::default()
    };
    let check = |files: &[(&str, &str)]| {
        let proj = dir.path().join(format!("p{}", files.len()));
        let _ = fs::remove_dir_all(&proj);
        fs::create_dir_all(&proj).expect("mkdir");
        for (name, text) in files {
            fs::write(proj.join(name), text).expect("w");
        }
        let r = scan(&store, &proj, &opts).expect("scan");
        let text = report::text(&r);
        assert_eq!(
            !text.contains("does not prove"),
            r.is_incomplete(),
            "text and is_incomplete disagree: {text}"
        );
        assert!(
            !r.unscanned() || r.is_incomplete(),
            "a gate failure must be incomplete"
        );
        (r.unscanned(), r.is_incomplete())
    };
    let fixed = "module x\nrequire example.com/m v1.3.0\n";
    // Nothing to read at all.
    assert_eq!(check(&[]), (true, true));
    // Only requirement lines that cannot be matched.
    assert_eq!(check(&[("requirements.txt", "flask>=2\n")]), (true, true));
    // Something was checked; a stray range is listed and makes the report incomplete, but it does
    // not stop a project from ever passing a gate.
    assert_eq!(
        check(&[("go.mod", fixed), ("requirements.txt", "flask>=2\n")]),
        (false, true)
    );
    // A normal, fully checked project.
    assert_eq!(check(&[("go.mod", fixed)]), (false, false));
}

#[test]
fn old_dataset_layout_gets_a_note() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = store_with(dir.path(), None);
    write_go_data(&store, &[go_advisory("GO-1", "CVE-2026-0001", "1.2.0")]);
    fs::write(
        store.dir().join("osv/Go.meta.json"),
        r#"{"updated_at":"t","records":1}"#,
    )
    .expect("w");
    let proj = go_project(dir.path(), "v1.0.0", USES_F);
    let r = scan(
        &store,
        &proj,
        &ScanOptions {
            offline: true,
            ..ScanOptions::default()
        },
    )
    .expect("scan");
    assert!(r.notes.iter().any(|n| n.contains("dataset layout v2")));
}

#[test]
fn not_found_findings_sink_but_exploited_ones_lead() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = store_with(dir.path(), None);
    write_go_data(
        &store,
        &[
            go_advisory("GO-USED", "CVE-2026-0001", "9.0.0"),
            r#"{"id":"GO-KEV","aliases":["CVE-2026-0002"],"affected":[{"package":{"ecosystem":"Go","name":"example.com/m"},
              "ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"9.0.0"}]}],
              "ecosystem_specific":{"imports":[{"path":"example.com/m/other","symbols":["G"]}]}}]}"#
                .to_string(),
        ],
    );
    fs::write(
        store.dir().join("kev.json"),
        r#"{"updated_at":"t","ids":["CVE-2026-0002"]}"#,
    )
    .expect("w");
    let proj = go_project(dir.path(), "v1.0.0", USES_F);
    let r = scan(
        &store,
        &proj,
        &ScanOptions {
            offline: true,
            ..ScanOptions::default()
        },
    )
    .expect("scan");
    let levels: Vec<_> = r
        .findings
        .iter()
        .map(|f| {
            (
                f.id.as_str(),
                f.reachability.as_ref().expect("r").level.as_str(),
            )
        })
        .collect();
    assert_eq!(
        levels,
        vec![("GO-KEV", "not_found"), ("GO-USED", "used_symbol")],
        "exploited leads even when unused"
    );
}

#[test]
fn runtime_scan_judges_given_versions_offline_after_an_update() {
    use opencraysec_db::runtime_data::update_runtime;
    use opencraysec_engine::{RuntimeOptions, scan_runtime};
    use opencraysec_runtime::Status;

    let dir = tempfile::tempdir().expect("tmp");
    let server = MockServer::start(vec![
        Route::get(
            "/eol",
            r#"{"result":[{"name":"php","releases":[
                {"name":"8.4","eolFrom":"2028-12-31","isEol":false,"latest":{"name":"8.4.26"}},
                {"name":"7.4","eolFrom":"2022-11-28","isEol":true,"latest":{"name":"7.4.33"}}]}]}"#,
        ),
        Route::get("/php", r#"{"8":{"8.4":{"version":"8.4.27"}}}"#),
    ]);
    let store = store_with(dir.path(), Some(&server));
    let opts = RuntimeOptions {
        products: vec![
            "php@7.4.33".into(),
            "php@8.4.26".into(),
            "nosuch@1.0".into(),
        ],
    };

    // Before any update: honest about knowing nothing.
    let before = scan_runtime(&store, &opts).expect("scans");
    assert!(before.results.iter().all(|r| r.status == Status::Unknown));
    assert!(
        before
            .notes
            .iter()
            .any(|n| n.contains("opencraysec update"))
    );
    assert_eq!(before.data.lifecycle_updated_at, None);

    update_runtime(&store).expect("update");
    // The scan itself must not need the network: scan with a store that has no endpoints.
    let offline = Store::at(dir.path().join("data"));
    let after = scan_runtime(&offline, &opts).expect("scans");
    let status = |p: &str, v: &str| {
        after
            .results
            .iter()
            .find(|r| r.product == p && r.version == v)
            .map(|r| r.status)
    };
    assert_eq!(status("php", "7.4.33"), Some(Status::Eol));
    assert_eq!(
        status("php", "8.4.26"),
        Some(Status::Outdated),
        "php.net is ahead of the aggregator"
    );
    assert_eq!(status("nosuch", "1.0"), Some(Status::Unknown));
    assert!(after.data.lifecycle_updated_at.is_some());
    assert_eq!(after.data.vendor_updated_at[0].0, "php");

    // A malformed argument is an error, not a silent skip.
    let bad = RuntimeOptions {
        products: vec!["php".into()],
    };
    assert!(scan_runtime(&offline, &bad).is_err());
}
