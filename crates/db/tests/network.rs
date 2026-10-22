//! Dataset updates and online lookups against a local mock server.
#![allow(clippy::expect_used)]

use std::collections::HashSet;
use std::io::Write;

use opencraysec_core::{Ecosystem, Package};
use opencraysec_db::testutil::{MockServer, Route};
use opencraysec_db::{Endpoints, Store, cwe, net, nvd, online, update};

fn zip_of(files: &[(&str, &str)]) -> Vec<u8> {
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut z = zip::ZipWriter::new(&mut buf);
        let opts = zip::write::SimpleFileOptions::default();
        for (name, body) in files {
            z.start_file(*name, opts).expect("start");
            z.write_all(body.as_bytes()).expect("write");
        }
        z.finish().expect("finish");
    }
    buf.into_inner()
}

fn store_for(server: &MockServer, dir: &std::path::Path) -> Store {
    Store::at(dir).with_endpoints(Endpoints {
        osv_dump: server.base.clone(),
        osv_api: format!("{}/v1", server.base),
        kev: format!("{}/kev.json", server.base),
        epss: format!("{}/epss.csv.gz", server.base),
        cwe: format!("{}/cwe.zip", server.base),
        nvd: format!("{}/nvd", server.base),
        eol: format!("{}/eol", server.base),
        php_releases: format!("{}/php", server.base),
        nvd_gap_ms: Some(0),
    })
}

fn pkg(name: &str, version: &str) -> Package {
    Package {
        ecosystem: Ecosystem::Npm,
        name: name.into(),
        version: version.into(),
        source: "package-lock.json".into(),
        dev: false,
    }
}

fn advisory(id: &str) -> String {
    format!(
        r#"{{"id":"{id}","modified":"m","summary":"s","affected":[{{"package":{{"ecosystem":"npm","name":"lodash"}},
        "ranges":[{{"type":"SEMVER","events":[{{"introduced":"0"}},{{"fixed":"9.0.0"}}]}}]}}]}}"#
    )
}

const GO_ADVISORY: &str = r#"{"id":"GO-1","aliases":["CVE-2026-1"],"summary":"s",
  "affected":[{"package":{"ecosystem":"Go","name":"example.com/m"},
  "ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.0"}]}],
  "ecosystem_specific":{"imports":[{"path":"example.com/m/p","symbols":["F"],"goos":["linux"]}]}}]}"#;

#[test]
fn osv_dump_kev_epss_cwe_updates() {
    let gz = {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(b"#model_version:v1\ncve,epss,percentile\nCVE-2026-1,0.5,0.9\n")
            .expect("gz");
        enc.finish().expect("gz")
    };
    let cwe_xml = r#"<Weakness_Catalog><Weakness ID="79" Name="XSS"><Description>d</Description></Weakness></Weakness_Catalog>"#;
    let server = MockServer::start(vec![
        Route::get("/Go/all.zip", zip_of(&[("GO-1.json", GO_ADVISORY)])),
        Route::get(
            "/kev.json",
            r#"{"vulnerabilities":[{"cveID":"CVE-2026-1"}]}"#,
        ),
        Route::get("/epss.csv.gz", gz),
        Route::get("/cwe.zip", zip_of(&[("cwec.xml", cwe_xml)])),
    ]);
    let dir = tempfile::tempdir().expect("tmp");
    let store = store_for(&server, dir.path());

    let meta = update::update_osv(&store, Ecosystem::Go).expect("osv");
    assert_eq!((meta.records, meta.schema), (1, opencraysec_db::SCHEMA));
    assert!(store.has(Ecosystem::Go));
    let want: HashSet<String> = ["example.com/m".to_string()].into();
    let recs = store.load_for(Ecosystem::Go, &want).expect("load");
    let spec = recs["example.com/m"][0].affected[0]
        .ecosystem_specific
        .as_ref()
        .expect("spec");
    assert!(
        spec["imports"][0].get("goos").is_none(),
        "extra fields are trimmed"
    );

    assert_eq!(update::update_kev(&store).expect("kev"), 1);
    assert!(store.kev().contains("CVE-2026-1"));
    assert_eq!(update::update_epss(&store).expect("epss"), 1);
    let ids: HashSet<String> = ["CVE-2026-1".to_string()].into();
    assert!((store.epss(&ids)["CVE-2026-1"] - 0.5).abs() < 1e-6);
    assert_eq!(cwe::update_cwe(&store).expect("cwe"), 1);
    assert_eq!(store.cwe(79).expect("79").name, "XSS");

    let status = store.status();
    assert!(
        status.kev_updated_at.is_some()
            && status.epss_updated_at.is_some()
            && status.cwe_updated_at.is_some()
    );
}

#[test]
fn the_github_actions_dump_is_fetched_with_its_space_encoded_and_matched_without_regard_to_case() {
    let advisory = r#"{"id":"GHSA-act-1","summary":"s","affected":[
        {"package":{"ecosystem":"GitHub Actions","name":"Acme/Tool"},
         "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.2.0"}]}]},
        {"package":{"ecosystem":"npm","name":"other"}}]}"#;
    let server = MockServer::start(vec![Route::get(
        "/GitHub%20Actions/all.zip",
        zip_of(&[("GHSA-act-1.json", advisory)]),
    )]);
    let dir = tempfile::tempdir().expect("tmp");
    let store = store_for(&server, dir.path());
    let meta = update::update_osv(&store, Ecosystem::GitHubActions).expect("actions dump");
    assert_eq!(
        meta.records, 1,
        "only the GitHub Actions entry of the record is stored"
    );
    assert!(store.has(Ecosystem::GitHubActions));
    let want: HashSet<String> = [Ecosystem::GitHubActions.normalize_name("ACME/tool")].into();
    let recs = store
        .load_for(Ecosystem::GitHubActions, &want)
        .expect("load");
    assert_eq!(recs["acme/tool"][0].id, "GHSA-act-1");
    let listed: Vec<String> = store
        .status()
        .ecosystems
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    assert_eq!(listed, vec!["GitHub Actions"]);
}

#[test]
fn update_failures_are_errors_and_leave_no_partial_state() {
    let server = MockServer::start(vec![
        Route::get("/Go/all.zip", b"this is not a zip".to_vec()),
        Route::get("/kev.json", "{}"),
        Route::get("/cwe.zip", zip_of(&[("readme.txt", "no xml here")])),
    ]);
    let dir = tempfile::tempdir().expect("tmp");
    let store = store_for(&server, dir.path());
    assert!(
        update::update_osv(&store, Ecosystem::Go).is_err(),
        "bad zip"
    );
    assert!(!store.has(Ecosystem::Go));
    assert!(update::update_osv(&store, Ecosystem::Npm).is_err(), "404");
    assert!(
        update::update_kev(&store).is_err(),
        "no vulnerabilities array"
    );
    assert!(update::update_epss(&store).is_err(), "404");
    assert!(cwe::update_cwe(&store).is_err(), "no xml entry");
    assert!(net::get_bytes(&format!("{}/missing", server.base), 10).is_err());
    let over =
        net::get_bytes_with_headers(&format!("{}/kev.json", server.base), &[("x-test", "1")], 1);
    assert!(over.is_err(), "over the size limit");
}

#[test]
fn nvd_fetch_caches_and_validates() {
    let body = r#"{"vulnerabilities":[{"cve":{"metrics":{"cvssMetricV31":[{"type":"Primary","cvssData":{"baseScore":7.5}}]},
        "weaknesses":[{"description":[{"value":"CWE-400"}]}]}}]}"#;
    let server = MockServer::start(vec![Route::get("/nvd?cveId=CVE-2026-0001", body)]);
    let dir = tempfile::tempdir().expect("tmp");
    let store = store_for(&server, dir.path());
    let info = nvd::fetch(&store, "CVE-2026-0001", Some("key")).expect("fetch");
    assert_eq!(
        (info.cvss, info.cwes.clone()),
        (Some(7.5), vec!["CWE-400".to_string()])
    );
    assert_eq!(nvd::cached(&store, "CVE-2026-0001", true), Some(info));
    assert!(nvd::fetch(&store, "../bad", None).is_err());
    assert!(nvd::fetch(&store, "CVE-2026-9999", None).is_err(), "404");
}

#[test]
fn online_query_maps_hits_to_packages_and_caches_advisories() {
    let server = MockServer::start(vec![
        Route::post(
            "/v1/querybatch",
            r#"{"results":[{"vulns":[{"id":"GHSA-1","modified":"m"}]},{}]}"#,
        ),
        Route::get("/v1/vulns/GHSA-1", advisory("GHSA-1")),
    ]);
    let dir = tempfile::tempdir().expect("tmp");
    let store = store_for(&server, dir.path());
    let pkgs = vec![pkg("lodash", "4.0.0"), pkg("other", "1.0.0")];
    let hits = online::query(&store, &pkgs).expect("query");
    assert_eq!(hits.len(), 1);
    assert_eq!(
        (hits[0].package_index, hits[0].record.id.as_str()),
        (0, "GHSA-1")
    );
    online::query(&store, &pkgs).expect("again");
    let fetches = server
        .requests()
        .iter()
        .filter(|r| r.starts_with("GET /v1/vulns/GHSA-1"))
        .count();
    assert_eq!(fetches, 1, "second run reads the cached advisory");
    assert_eq!(
        online::fetch_by_id(&store, "GHSA-1").expect("cached").id,
        "GHSA-1"
    );
    assert_eq!(online::ecosystems_of(&pkgs), vec![Ecosystem::Npm]);
}

#[test]
fn online_query_follows_page_tokens() {
    let server = MockServer::start(vec![
        Route::post(
            "/v1/querybatch",
            r#"{"results":[{"vulns":[{"id":"GHSA-1","modified":"m"}],"next_page_token":"t2"}]}"#,
        )
        .then(r#"{"results":[{"vulns":[{"id":"GHSA-2","modified":"m"}]}]}"#),
        Route::get("/v1/vulns/GHSA-1", advisory("GHSA-1")),
        Route::get("/v1/vulns/GHSA-2", advisory("GHSA-2")),
    ]);
    let dir = tempfile::tempdir().expect("tmp");
    let hits =
        online::query(&store_for(&server, dir.path()), &[pkg("lodash", "4.0.0")]).expect("query");
    let mut ids: Vec<_> = hits.iter().map(|h| h.record.id.clone()).collect();
    ids.sort();
    assert_eq!(ids, vec!["GHSA-1", "GHSA-2"]);
    assert!(
        server
            .requests()
            .iter()
            .any(|r| r.contains("\"page_token\":\"t2\""))
    );
}

#[test]
fn online_query_failures_are_errors() {
    let dir = tempfile::tempdir().expect("tmp");
    let no_results = MockServer::start(vec![Route::post("/v1/querybatch", "{}")]);
    assert!(
        online::query(
            &store_for(&no_results, dir.path()),
            &[pkg("lodash", "4.0.0")]
        )
        .is_err()
    );
    let missing_advisory = MockServer::start(vec![Route::post(
        "/v1/querybatch",
        r#"{"results":[{"vulns":[{"id":"GHSA-X"}]}]}"#,
    )]);
    assert!(
        online::query(
            &store_for(&missing_advisory, dir.path()),
            &[pkg("lodash", "4.0.0")]
        )
        .is_err()
    );
    assert!(
        online::query(&store_for(&no_results, dir.path()), &[])
            .expect("empty is fine")
            .is_empty()
    );
}
