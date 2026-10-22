//! Protocol-level tests for the MCP server.
#![allow(clippy::expect_used)]
use std::fs;
use std::io::Cursor;

use opencraysec_core::Ecosystem;
use opencraysec_core::osv::OsvRecord;
use opencraysec_db::Store;
use opencraysec_mcp::{ServerConfig, serve};
use serde_json::{Value, json};

fn seeded(dir: &std::path::Path) -> ServerConfig {
    let data = dir.join("data");
    let rec: OsvRecord = serde_json::from_str(
        r#"{"id":"GHSA-1","aliases":["CVE-2026-1"],"summary":"bad",
        "affected":[{"package":{"ecosystem":"npm","name":"lodash"},
        "ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}],
        "database_specific":{"severity":"HIGH","cwe_ids":["CWE-1321"]}}"#,
    )
    .expect("json");
    fs::create_dir_all(data.join("osv")).expect("mkdir");
    let line = opencraysec_db::encode_line(Ecosystem::Npm, &rec)
        .expect("enc")
        .expect("some");
    fs::write(data.join("osv/npm.jsonl"), line + "\n").expect("w");
    fs::write(
        data.join("osv/npm.meta.json"),
        r#"{"updated_at":"t","records":1}"#,
    )
    .expect("w");
    let ws = dir.join("ws");
    fs::create_dir_all(&ws).expect("mkdir");
    fs::write(
        ws.join("package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.4"}}}"#,
    )
    .expect("w");
    ServerConfig::new(ws, Store::at(data), true)
}

fn talk(cfg: &ServerConfig, msgs: &[Value]) -> Vec<Value> {
    let input: String = msgs.iter().map(|m| m.to_string() + "\n").collect();
    let mut out = Vec::new();
    serve(cfg, Cursor::new(input), &mut out).expect("serve");
    String::from_utf8(out)
        .expect("utf8")
        .lines()
        .map(|l| serde_json::from_str(l).expect("json line"))
        .collect()
}

#[test]
fn handshake_list_and_scan() {
    let dir = tempfile::tempdir().expect("tmp");
    let cfg = seeded(dir.path());
    let r = talk(
        &cfg,
        &[
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
            json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"scan_dependencies","arguments":{}}}),
            json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"plan_fix","arguments":{}}}),
            json!({"jsonrpc":"2.0","id":5,"method":"ping"}),
        ],
    );
    assert_eq!(r.len(), 5, "notification gets no reply");
    assert_eq!(r[0]["result"]["serverInfo"]["name"], "opencraysec");
    let names: Vec<&str> = r[1]["result"]["tools"]
        .as_array()
        .expect("arr")
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert!(names.contains(&"scan_dependencies") && names.contains(&"verify_fix"));
    let scan = &r[2]["result"]["structuredContent"];
    assert_eq!(r[2]["result"]["isError"], false);
    assert_eq!(scan["findings_total"], 1);
    assert_eq!(scan["findings"][0]["package"]["name"], "lodash");
    let plan = &r[3]["result"]["structuredContent"];
    assert_eq!(plan["steps"][0]["to"], "4.17.21");
    assert_eq!(r[4]["id"], 5);
}

#[test]
fn errors_and_confinement() {
    let dir = tempfile::tempdir().expect("tmp");
    let cfg = seeded(dir.path());
    let r = talk(
        &cfg,
        &[
            json!({"jsonrpc":"2.0","id":1,"method":"nope"}),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"nope"}}),
            json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"scan_dependencies","arguments":{"path":"../"}}}),
            json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"scan_dependencies","arguments":{"path":"/etc"}}}),
            json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"verify_fix","arguments":{}}}),
            json!({"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"update_db","arguments":{}}}),
            json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"explain_advisory","arguments":{"id":"x/../y"}}}),
        ],
    );
    assert_eq!(r[0]["error"]["code"], -32601);
    assert_eq!(r[1]["error"]["code"], -32602);
    for (i, item) in r.iter().enumerate().take(7).skip(2) {
        assert_eq!(item["result"]["isError"], true, "case {i}: {item}");
    }
    assert!(
        r[2]["result"]["structuredContent"]["error"]
            .as_str()
            .expect("s")
            .contains("outside the workspace")
    );
}

#[test]
fn bad_json_and_batches() {
    let dir = tempfile::tempdir().expect("tmp");
    let cfg = seeded(dir.path());
    let mut out = Vec::new();
    serve(
        &cfg,
        Cursor::new("not json\n[]\n\n{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"ping\"}\n"),
        &mut out,
    )
    .expect("serve");
    let lines: Vec<Value> = String::from_utf8(out)
        .expect("utf8")
        .lines()
        .map(|l| serde_json::from_str(l).expect("json"))
        .collect();
    assert_eq!(lines[0]["error"]["code"], -32700);
    assert_eq!(lines[1]["error"]["code"], -32600);
    assert_eq!(lines[2]["id"], 9);
}

fn call(cfg: &ServerConfig, name: &str, args: Value) -> Value {
    let r = talk(
        cfg,
        &[
            json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":args}}),
        ],
    );
    r[0]["result"].clone()
}

#[test]
fn every_tool_is_listed_and_callable() {
    let dir = tempfile::tempdir().expect("tmp");
    let cfg = seeded(dir.path());
    fs::write(
        cfg.workspace.join("app.js"),
        "eval(userInput);\nconst _ = require('lodash');\n",
    )
    .expect("w");

    let listed = talk(
        &cfg,
        &[json!({"jsonrpc":"2.0","id":1,"method":"tools/list"})],
    );
    let names: Vec<&str> = listed[0]["result"]["tools"]
        .as_array()
        .expect("arr")
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    for want in [
        "scan_dependencies",
        "scan_code",
        "scan_runtime",
        "explain_advisory",
        "plan_fix",
        "verify_fix",
        "update_db",
        "db_status",
    ] {
        assert!(names.contains(&want), "{want} missing from {names:?}");
    }

    let code = call(&cfg, "scan_code", json!({"limit": 5}));
    assert_eq!(code["isError"], false);
    assert_eq!(code["structuredContent"]["findings"][0]["rule"], "js-eval");

    let scan = call(
        &cfg,
        "scan_dependencies",
        json!({"ecosystems":["js"],"min_severity":"low","include_dev":false,"limit":0}),
    );
    assert_eq!(scan["structuredContent"]["findings_returned"], 0);
    assert_eq!(scan["structuredContent"]["findings_total"], 1);
    let full = call(&cfg, "scan_dependencies", json!({"offline": true}));
    assert_eq!(
        full["structuredContent"]["findings"][0]["reachability"]["level"],
        "imported"
    );

    let plan = call(&cfg, "plan_fix", json!({"id":"GHSA-1"}));
    assert_eq!(plan["structuredContent"]["steps"][0]["package"], "lodash");
    let verify = call(&cfg, "verify_fix", json!({"ids":["GHSA-1"]}));
    assert_eq!(verify["structuredContent"]["remaining"][0]["id"], "GHSA-1");
    // An id that no scan of this path ever reported cannot be called resolved.
    let ghost = call(&cfg, "verify_fix", json!({"ids":["GHSA-never-seen"]}));
    assert_eq!(ghost["structuredContent"]["unknown"][0], "GHSA-never-seen");
    assert_eq!(ghost["structuredContent"]["resolved"], json!([]));

    let explained = call(&cfg, "explain_advisory", json!({"id":"CVE-2026-1"}));
    assert_eq!(explained["structuredContent"]["id"], "GHSA-1");
    assert_eq!(call(&cfg, "explain_advisory", json!({}))["isError"], true);
    assert_eq!(
        call(&cfg, "explain_advisory", json!({"id":"GHSA-none"}))["isError"],
        true
    );

    let status = call(&cfg, "db_status", json!({}));
    assert_eq!(status["structuredContent"]["ecosystems"][0][0], "npm");

    assert_eq!(
        call(&cfg, "scan_dependencies", json!({"ecosystems":["cobol"]}))["isError"],
        true
    );
    assert_eq!(
        call(&cfg, "scan_dependencies", json!({"ecosystems":[1]}))["isError"],
        true
    );
    assert_eq!(
        call(&cfg, "scan_dependencies", json!({"min_severity":"urgent"}))["isError"],
        true
    );
    assert_eq!(
        call(&cfg, "scan_code", json!({"path":"missing-dir"}))["isError"],
        true
    );
}

#[test]
fn update_db_runs_online_and_reports_per_source_errors() {
    let dir = tempfile::tempdir().expect("tmp");
    let mut cfg = seeded(dir.path());
    cfg.offline = false;
    let server = opencraysec_db::testutil::MockServer::start(vec![]);
    cfg.store = cfg.store.clone().with_endpoints(opencraysec_db::Endpoints {
        osv_dump: server.base.clone(),
        kev: format!("{}/kev", server.base),
        epss: format!("{}/epss", server.base),
        cwe: format!("{}/cwe", server.base),
        eol: format!("{}/eol", server.base),
        php_releases: format!("{}/php", server.base),
        ..opencraysec_db::Endpoints::default()
    });
    let r = call(&cfg, "update_db", json!({"ecosystems":["go"]}));
    assert_eq!(r["isError"], false);
    let updated = r["structuredContent"]["updated"].as_array().expect("arr");
    assert_eq!(updated.len(), 5, "go + KEV + EPSS + CWE + runtime data");
    assert!(
        updated.iter().all(|u| u.get("error").is_some()),
        "the mock serves nothing: {updated:?}"
    );
    let no_enrich = call(&cfg, "update_db", json!({"enrich": false}));
    assert_eq!(
        no_enrich["structuredContent"]["updated"]
            .as_array()
            .expect("arr")
            .len(),
        1,
        "refreshes only what is downloaded (npm)"
    );
}

#[test]
fn oversized_messages_do_not_desync_the_stream() {
    let dir = tempfile::tempdir().expect("tmp");
    let cfg = seeded(dir.path());
    let huge = "x".repeat(opencraysec_mcp::MAX_MESSAGE_BYTES + 10);
    let input = format!(
        "{huge}\n{}\n",
        json!({"jsonrpc":"2.0","id":3,"method":"ping"})
    );
    let mut out = Vec::new();
    serve(&cfg, Cursor::new(input), &mut out).expect("serve");
    let lines: Vec<Value> = String::from_utf8(out)
        .expect("utf8")
        .lines()
        .map(|l| serde_json::from_str(l).expect("json"))
        .collect();
    assert_eq!(lines[0]["error"]["message"], "message too large");
    assert_eq!(lines[1]["id"], 3);
}

#[test]
fn malformed_requests_get_protocol_errors() {
    let dir = tempfile::tempdir().expect("tmp");
    let cfg = seeded(dir.path());
    let r = talk(
        &cfg,
        &[
            json!({"jsonrpc":"2.0","id":1}),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{}}),
            json!({"jsonrpc":"2.0","method":"nothing/to/see"}),
            json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"db_status"}}),
        ],
    );
    assert_eq!(r.len(), 3, "notifications get no reply");
    assert_eq!(r[0]["error"]["code"], -32600);
    assert_eq!(r[1]["error"]["code"], -32602);
    assert_eq!(r[2]["result"]["isError"], false, "arguments are optional");
    let abs = cfg.workspace.canonicalize().expect("canon");
    let r = call(
        &cfg,
        "scan_dependencies",
        json!({"path": abs.to_str().expect("s"), "offline": true}),
    );
    assert_eq!(
        r["isError"], false,
        "absolute paths inside the workspace are fine"
    );
    let file = abs.join("package-lock.json");
    let r = call(
        &cfg,
        "scan_dependencies",
        json!({"path": file.to_str().expect("s")}),
    );
    assert_eq!(r["structuredContent"]["lockfiles"][0], "package-lock.json");
}

#[test]
fn record_fix_logs_what_changed_and_who_asked() {
    let dir = tempfile::tempdir().expect("tmp");
    let cfg = seeded(dir.path());
    let lock = cfg.workspace.join("package-lock.json");
    let lock_with = |v: &str| {
        format!(
            r#"{{"lockfileVersion":3,"packages":{{"node_modules/lodash":{{"version":"{v}"}}}}}}"#
        )
    };
    let msgs = |id: u64, name: &str, args: Value| json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":name,"arguments":args}});

    let r = talk(
        &cfg,
        &[
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"clientInfo":{"name":"test-client","version":"1.2"}}}),
            msgs(2, "scan_dependencies", json!({"offline": true})),
            msgs(3, "plan_fix", json!({"offline": true})),
        ],
    );
    assert!(
        r[2]["result"]["structuredContent"]["after_you_apply_it"]
            .as_str()
            .expect("s")
            .contains("record_fix")
    );
    assert_eq!(cfg.client_name().as_deref(), Some("test-client 1.2"));

    fs::write(&lock, lock_with("4.17.21")).expect("w");
    let r = talk(
        &cfg,
        &[
            msgs(4, "verify_fix", json!({"ids": ["GHSA-1"], "offline": true})),
            msgs(
                5,
                "record_fix",
                json!({"ids": ["GHSA-1"], "summary": "Upgrade lodash", "reason": "Prototype pollution", "files": ["package-lock.json"], "commands": ["npm i lodash@4.17.21"], "commit": "abc"}),
            ),
            msgs(6, "record_fix", json!({"ids": ["GHSA-1"]})),
        ],
    );
    assert!(
        r[0]["result"]["structuredContent"]["next"]
            .as_str()
            .expect("s")
            .contains("record_fix")
    );
    let rec = &r[1]["result"]["structuredContent"];
    assert_eq!(rec["recorded"], true);
    assert_eq!(rec["lockfile_changes_detected"][0]["to"][0], "4.17.21");
    assert_eq!(r[2]["result"]["isError"], true, "summary is required");

    let events = opencraysec_log::EventLog::for_store(&cfg.store).read_all();
    let kinds: Vec<&str> = events.iter().map(|e| e.kind.as_str()).collect();
    for k in ["scan", "plan_fix", "verify_fix", "record_fix"] {
        assert!(kinds.contains(&k), "{k} missing from {kinds:?}");
    }
    assert!(
        events
            .iter()
            .all(|e| e.client.as_deref() == Some("test-client 1.2") || e.client.is_none())
    );
    let summary = opencraysec_log::summary::summarize(&events, None);
    assert_eq!(summary["kpis"]["recorded_fixes"], 1);
    assert_eq!(summary["fixes"][0]["kind"], "recorded");
}

#[test]
fn logging_can_be_turned_off() {
    let dir = tempfile::tempdir().expect("tmp");
    let mut cfg = seeded(dir.path());
    cfg.log_enabled = false;
    let scan = call(&cfg, "scan_dependencies", json!({"offline": true}));
    assert_eq!(scan["isError"], false);
    assert!(
        opencraysec_log::EventLog::for_store(&cfg.store)
            .read_all()
            .is_empty()
    );
    let rec = call(
        &cfg,
        "record_fix",
        json!({"ids": ["GHSA-1"], "summary": "s"}),
    );
    assert_eq!(rec["isError"], true);
}

#[test]
fn update_db_stores_datasets_when_the_sources_answer() {
    use std::io::Write as _;
    let zip = |name: &str, body: &str| {
        let mut buf = Cursor::new(Vec::new());
        {
            let mut z = zip::ZipWriter::new(&mut buf);
            z.start_file(name, zip::write::SimpleFileOptions::default())
                .expect("start");
            z.write_all(body.as_bytes()).expect("write");
            z.finish().expect("finish");
        }
        buf.into_inner()
    };
    let gz = {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(b"cve,epss,percentile\nCVE-2026-0001,0.5,0.9\n")
            .expect("gz");
        enc.finish().expect("gz")
    };
    let advisory = r#"{"id":"GO-1","affected":[{"package":{"ecosystem":"Go","name":"m"}}]}"#;
    let server = opencraysec_db::testutil::MockServer::start(vec![
        opencraysec_db::testutil::Route::get("/Go/all.zip", zip("GO-1.json", advisory)),
        opencraysec_db::testutil::Route::get(
            "/kev",
            r#"{"vulnerabilities":[{"cveID":"CVE-2026-0001"}]}"#,
        ),
        opencraysec_db::testutil::Route::get("/epss", gz),
        opencraysec_db::testutil::Route::get(
            "/eol",
            r#"{"result":[{"name":"php","releases":[{"name":"7.4","eolFrom":"2022-11-28","isEol":true,"latest":{"name":"7.4.33"}}]}]}"#,
        ),
        opencraysec_db::testutil::Route::get("/php", r#"{"8":{"8.4":{"version":"8.4.27"}}}"#),
        opencraysec_db::testutil::Route::get(
            "/cwe",
            zip(
                "c.xml",
                r#"<Weakness ID="79" Name="XSS"><Description>d</Description></Weakness>"#,
            ),
        ),
    ]);
    let dir = tempfile::tempdir().expect("tmp");
    let mut cfg = seeded(dir.path());
    cfg.offline = false;
    cfg.store = cfg.store.clone().with_endpoints(opencraysec_db::Endpoints {
        osv_dump: server.base.clone(),
        kev: format!("{}/kev", server.base),
        epss: format!("{}/epss", server.base),
        cwe: format!("{}/cwe", server.base),
        eol: format!("{}/eol", server.base),
        php_releases: format!("{}/php", server.base),
        ..opencraysec_db::Endpoints::default()
    });
    let r = call(&cfg, "update_db", json!({"ecosystems": ["go"]}));
    assert_eq!(r["isError"], false);
    let updated = r["structuredContent"]["updated"].as_array().expect("arr");
    assert!(
        updated.iter().all(|u| u.get("error").is_none()),
        "{updated:?}"
    );
    assert_eq!(updated[0]["records"], 1);
    assert_eq!(updated.len(), 5);

    // The data update_db just stored is what scan_runtime judges with, offline.
    cfg.offline = true;
    let rt = call(
        &cfg,
        "scan_runtime",
        json!({"products": ["php@7.4.33", "php@8.4.26"]}),
    );
    assert_eq!(rt["isError"], false, "{rt}");
    let results = rt["structuredContent"]["results"].as_array().expect("arr");
    assert_eq!(results[0]["status"], "eol");
    assert_eq!(
        results[1]["status"], "unknown",
        "no 8.4 line in this mock's end-of-life data"
    );
    assert!(rt["structuredContent"]["data"]["lifecycle_updated_at"].is_string());
    // The call is in the activity log, so the dashboard shows it.
    let log = fs::read_to_string(cfg.store.dir().join("log/events.jsonl")).expect("logged");
    assert!(
        log.lines()
            .any(|l| l.contains("\"kind\":\"scan_runtime\"") && l.contains("php")),
        "{log}"
    );
    let bad = call(&cfg, "scan_runtime", json!({"products": ["php"]}));
    assert_eq!(bad["isError"], true);
    let nvd = call(
        &cfg,
        "scan_runtime",
        json!({"products": ["php@7.4.33"], "nvd": true}),
    );
    assert_eq!(
        nvd["isError"], true,
        "offline mode refuses NVD lookups: {nvd}"
    );
    assert!(nvd.to_string().contains("offline"), "{nvd}");
}

#[test]
fn optional_arguments_are_honoured() {
    let dir = tempfile::tempdir().expect("tmp");
    let cfg = seeded(dir.path());
    fs::write(cfg.workspace.join("a.js"), "const x = 1;\n").expect("w");
    let code = call(
        &cfg,
        "scan_code",
        json!({"external": ["semgrep"], "limit": 3}),
    );
    assert_eq!(code["isError"], false);
    assert_eq!(code["structuredContent"]["external"][0]["tool"], "semgrep");
    assert_eq!(
        code["structuredContent"]["external"][0]["status"], "failed",
        "semgrep needs a rules config"
    );
    let explained = call(
        &cfg,
        "explain_advisory",
        json!({"id": "GHSA-1", "offline": true}),
    );
    assert_eq!(explained["isError"], false);
    let unscanned = call(
        &cfg,
        "scan_dependencies",
        json!({"reachability": false, "enrich_nvd": false, "offline": true}),
    );
    assert!(
        unscanned["structuredContent"]["findings"][0]
            .get("reachability")
            .is_none()
            || unscanned["structuredContent"]["findings"][0]["reachability"].is_null()
    );
}

#[test]
fn client_info_without_a_version_and_unterminated_oversized_input() {
    let dir = tempfile::tempdir().expect("tmp");
    let cfg = seeded(dir.path());
    let r = talk(
        &cfg,
        &[
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"clientInfo":{"name":"bare\u{7}client"}}}),
        ],
    );
    assert_eq!(r[0]["result"]["serverInfo"]["name"], "opencraysec");
    assert_eq!(
        cfg.client_name().as_deref(),
        Some("bareclient"),
        "control characters are stripped"
    );
    let huge = "y".repeat(opencraysec_mcp::MAX_MESSAGE_BYTES + 10);
    let mut out = Vec::new();
    serve(&cfg, Cursor::new(huge), &mut out).expect("serve");
    let lines: Vec<Value> = String::from_utf8(out)
        .expect("utf8")
        .lines()
        .map(|l| serde_json::from_str(l).expect("json"))
        .collect();
    assert_eq!(lines[0]["error"]["message"], "message too large");
}
