//! Tool definitions and implementations.

use std::path::{Path, PathBuf};

use opencraysec_core::{Ecosystem, Severity};
use opencraysec_db::{runtime_data, update};
use opencraysec_engine::{
    AgentOptions, CodeOptions, RuntimeOptions, ScanOptions, ScanReport, explain, plan_fix, scan,
    scan_agent_config, scan_code, scan_runtime, verify_fix,
};
use opencraysec_log::EventLog;
use opencraysec_log::events::{
    FixInput, agent_event, code_event, log_scan, plan_event, record_fix, runtime_event,
    seen_finding_ids, verify_event,
};
use serde_json::{Value, json};

use crate::server::ServerConfig;

/// Why a tool call did not produce a result.
pub enum ToolError {
    /// No such tool.
    UnknownTool,
    /// The tool ran and failed; the message is for the model.
    Failed(String),
}

fn fail<T>(m: impl Into<String>) -> Result<T, ToolError> {
    Err(ToolError::Failed(m.into()))
}

/// Default number of findings returned inline.
const DEFAULT_LIMIT: usize = 50;

/// Tool catalogue for `tools/list`.
pub fn list() -> Value {
    let path = json!({ "type": "string", "description": "Directory or lockfile to check, relative to the workspace. Default: the workspace root." });
    let ecos = json!({ "type": "array", "items": { "type": "string" }, "description": "Limit to ecosystems: rust, js, php, go, python (or crates.io, npm, Packagist, Go, PyPI)." });
    let common = |extra: Value| {
        let mut props = json!({
            "path": path, "ecosystems": ecos,
            "include_dev": { "type": "boolean", "description": "Include dev-only dependencies (default true)." },
            "offline": { "type": "boolean", "description": "Never use the network; ecosystems without local data are reported as not scanned." },
            "min_severity": { "type": "string", "enum": ["low", "medium", "high", "critical"] },
            "reachability": { "type": "boolean", "description": "Check whether the project's own source imports each vulnerable package (default true). `not_found` findings are ranked lower but never hidden." },
            "enrich_nvd": { "type": "boolean", "description": "Look up missing CVSS scores/CWEs on NVD (network, slow without NVD_API_KEY, max 15 per scan; default false)." },
        });
        if let (Some(p), Some(e)) = (props.as_object_mut(), extra.as_object()) {
            for (k, v) in e {
                p.insert(k.clone(), v.clone());
            }
        }
        props
    };
    json!([
        {
            "name": "scan_dependencies",
            "description": "Check the project's lockfiles (Cargo.lock, package-lock.json, yarn.lock, pnpm-lock.yaml, composer.lock, go.mod, poetry.lock, uv.lock, Pipfile.lock, requirements.txt) against current public vulnerability data. Findings are ranked: known-exploited, then EPSS, then CVSS. Read `notes` for anything not covered.",
            "inputSchema": { "type": "object", "properties": common(json!({ "limit": { "type": "integer", "description": "Max findings returned (default 50)." } })) },
            "annotations": { "readOnlyHint": true, "openWorldHint": true }
        },
        {
            "name": "scan_code",
            "description": "Find suspected weaknesses in the project's own source with a small built-in rule pack (hard-coded secrets, eval/command/SQL injection patterns, disabled TLS verification, unsafe deserialization; JS/TS, Python, PHP, Go, Rust). Every hit is a SUSPECTED issue: read the code path and reproduce before reporting it. Secret values are never returned. Optionally runs gitleaks or semgrep if installed.",
            "inputSchema": { "type": "object", "properties": {
                "path": path,
                "external": { "type": "array", "items": { "type": "string", "enum": ["gitleaks", "semgrep"] }, "description": "Also run these scanners if installed." },
                "semgrep_config": { "type": "string", "description": "Rules for semgrep: a local file, or a registry pack (downloads rules from semgrep.dev)." },
                "limit": { "type": "integer", "description": "Max findings returned (default 100)." }
            } },
            "annotations": { "readOnlyHint": true }
        },
        {
            "name": "scan_agent_config",
            "description": "Check the files that steer an AI coding assistant in the project: rule files (CLAUDE.md, AGENTS.md, GEMINI.md, .cursorrules, .cursor/rules, copilot-instructions.md), MCP server settings (.mcp.json, .cursor/mcp.json, .vscode/mcp.json), hooks (.claude/settings.json) and auto-run tasks (.vscode/tasks.json). Reports invisible or bidirectional characters, instruction-override phrases, instructions hidden in HTML comments, commands that download and run code, lines that send secrets to a URL, MCP servers started from unpinned packages and hard-coded tokens. Packages an MCP server starts with an exact version are also checked against current advisories, including malicious-package reports. Rule findings are SUSPECTED patterns: read the file before reporting. The matched text is never returned. It stays inside the workspace and does not read the home directory.",
            "inputSchema": { "type": "object", "properties": {
                "path": path,
                "limit": { "type": "integer", "description": "Max findings returned (default 100)." }
            } },
            "annotations": { "readOnlyHint": true, "openWorldHint": true }
        },
        {
            "name": "scan_runtime",
            "description": "Check the interpreters, servers and databases the application runs on (PHP, nginx, Node.js, MySQL, ...) - things no lockfile lists - against release and end-of-life data stored locally. Reports end-of-life release lines and missing patch releases. Without `nvd` it does not check CVEs: a flaw in PHP itself shows up as `outdated` or `eol`, not as an advisory; with `nvd: true` it also lists the CVEs NVD records for each product at its version. Without `products` it runs a fixed set of version commands on this machine (php --version, nginx -v, ...); pass `products` (php@8.2.30) to check a machine or container you cannot run commands on. Needs `update_db` once for the release data. Uses the network only when `nvd` is true.",
            "inputSchema": { "type": "object", "properties": {
                "products": { "type": "array", "items": { "type": "string" }, "description": "product@version entries, for example php@8.2.30 or nodejs@20.11.0. Omit to detect what is installed here." },
                "nvd": { "type": "boolean", "description": "Also ask NVD which CVEs apply to each product at its version (network, answers cached 12 hours, slow without NVD_API_KEY, at most 10 lookups per call). This is what finds a flaw in PHP itself. Default false. Disabled in offline mode." }
            } },
            "annotations": { "readOnlyHint": true, "openWorldHint": true }
        },
        {
            "name": "explain_advisory",
            "description": "Explain one advisory by id (GHSA-..., CVE-..., RUSTSEC-..., GO-...): description, severity, CWE weakness class, exploitation signals, affected packages and links.",
            "inputSchema": { "type": "object", "properties": { "id": { "type": "string" }, "offline": { "type": "boolean" } }, "required": ["id"] },
            "annotations": { "readOnlyHint": true, "openWorldHint": true }
        },
        {
            "name": "plan_fix",
            "description": "Scan and return the minimal dependency upgrades that clear the findings, with the exact commands per package manager. Nothing is modified. Steps with needs_confirmation=true cross a major version: ask the user first. After you apply the changes, call verify_fix and then (recommended) record_fix.",
            "inputSchema": { "type": "object", "properties": common(json!({ "id": { "type": "string", "description": "Only plan for this advisory id or package name." } })) },
            "annotations": { "readOnlyHint": true, "openWorldHint": true }
        },
        {
            "name": "verify_fix",
            "description": "Re-scan the whole project after upgrading and report which of the given advisory ids are gone. Severity, dev and ecosystem filters are ignored here. An id is `resolved` only if an earlier scan_dependencies of the same path reported it; ids no earlier scan reported are `unknown` (not resolved). If `trustworthy` is false, part of the project could not be scanned and 'resolved' proves nothing. If you changed files to fix these, also call record_fix (recommended).",
            "inputSchema": { "type": "object", "properties": common(json!({ "ids": { "type": "array", "items": { "type": "string" } } })), "required": ["ids"] },
            "annotations": { "readOnlyHint": true, "openWorldHint": true }
        },
        {
            "name": "record_fix",
            "description": "Optional but recommended, like a commit message: after you changed the project to fix vulnerabilities, record what you changed and why so the user's report shows it. Give the advisory ids, a summary of the change, your reasoning, the files you edited, the commands you ran and the git commit if you made one. Lockfile version changes are measured independently by comparing dependency snapshots; your text is stored as AI-reported. Does not modify the project.",
            "inputSchema": { "type": "object", "properties": {
                "path": path,
                "ids": { "type": "array", "items": { "type": "string" }, "description": "Advisory ids this change addresses (from scan_dependencies)." },
                "summary": { "type": "string", "description": "What you changed, in one or two sentences." },
                "reason": { "type": "string", "description": "Why: the vulnerability, how it affects this project, why this fix." },
                "files": { "type": "array", "items": { "type": "string" }, "description": "Files you edited." },
                "commands": { "type": "array", "items": { "type": "string" }, "description": "Commands you ran." },
                "commit": { "type": "string", "description": "Git commit hash, if you committed." }
            }, "required": ["ids", "summary"] },
            "annotations": { "readOnlyHint": false, "idempotentHint": false }
        },
        {
            "name": "update_db",
            "description": "Download or refresh the local advisory data (OSV per ecosystem; with enrich=true also CISA KEV, EPSS, the MITRE CWE catalog and the release/end-of-life data scan_runtime uses). npm is large (hundreds of MB). Without ecosystems it refreshes what was already downloaded.",
            "inputSchema": { "type": "object", "properties": { "ecosystems": ecos, "enrich": { "type": "boolean", "description": "Also refresh CISA KEV and EPSS (default true)." } } },
            "annotations": { "readOnlyHint": false, "idempotentHint": true, "openWorldHint": true }
        },
        {
            "name": "db_status",
            "description": "Show which advisory data is stored locally and how old it is.",
            "inputSchema": { "type": "object", "properties": {} },
            "annotations": { "readOnlyHint": true }
        }
    ])
}

/// Resolves `path` inside the workspace, refusing anything that escapes it.
pub fn resolve(workspace: &Path, path: Option<&str>) -> Result<PathBuf, String> {
    let root = workspace
        .canonicalize()
        .map_err(|e| format!("workspace unavailable: {e}"))?;
    let joined = match path {
        None | Some("") | Some(".") => root.clone(),
        Some(p) => {
            let p = Path::new(p);
            if p.is_absolute() {
                p.to_path_buf()
            } else {
                root.join(p)
            }
        }
    };
    let canon = joined
        .canonicalize()
        .map_err(|e| format!("cannot open {}: {e}", joined.display()))?;
    if canon.starts_with(&root) {
        Ok(canon)
    } else {
        Err(format!(
            "{} is outside the workspace {}",
            canon.display(),
            root.display()
        ))
    }
}

fn str_arg<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key).and_then(|v| v.as_str())
}

fn eco_list(args: &Value) -> Result<Option<Vec<Ecosystem>>, String> {
    let Some(arr) = args.get("ecosystems").and_then(|v| v.as_array()) else {
        return Ok(None);
    };
    let mut out = Vec::new();
    for v in arr {
        let s = v.as_str().ok_or("ecosystems must be strings")?;
        out.push(Ecosystem::parse(s).ok_or_else(|| format!("unknown ecosystem {s:?}"))?);
    }
    Ok(Some(out))
}

fn scan_opts(cfg: &ServerConfig, args: &Value) -> Result<ScanOptions, String> {
    let min = match str_arg(args, "min_severity") {
        Some(s) => Severity::parse(s).ok_or_else(|| format!("unknown severity {s:?}"))?,
        None => Severity::Unknown,
    };
    Ok(ScanOptions {
        ecosystems: eco_list(args)?,
        include_dev: args
            .get("include_dev")
            .and_then(|v| v.as_bool())
            .unwrap_or(true),
        offline: cfg.offline
            || args
                .get("offline")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
        min_severity: min,
        reachability: args
            .get("reachability")
            .and_then(|v| v.as_bool())
            .unwrap_or(true),
        enrich_nvd: args
            .get("enrich_nvd")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
    })
}

fn summarize(report: &ScanReport, limit: usize) -> Value {
    let mut counts = serde_json::Map::new();
    for sev in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Unknown,
    ] {
        let n = report.findings.iter().filter(|f| f.severity == sev).count();
        counts.insert(sev.as_str().to_string(), json!(n));
    }
    let total = report.findings.len();
    let mut v = serde_json::to_value(report).unwrap_or(Value::Null);
    if let Some(f) = v.get_mut("findings").and_then(|f| f.as_array_mut()) {
        f.truncate(limit);
    }
    if let Some(a) = v.get_mut("install_scripts").and_then(|x| x.as_array_mut()) {
        a.truncate(limit);
    }
    v["install_scripts_total"] = json!(report.install_scripts.len());
    v["findings_total"] = json!(total);
    v["findings_returned"] = json!(total.min(limit));
    v["by_severity"] = Value::Object(counts);
    v
}

/// Runs the named tool.
pub fn call(cfg: &ServerConfig, name: &str, args: &Value) -> Result<Value, ToolError> {
    match name {
        "scan_dependencies" => {
            let root = resolve(&cfg.workspace, str_arg(args, "path")).or_else(fail_str)?;
            let opts = scan_opts(cfg, args).or_else(fail_str)?;
            let limit = args
                .get("limit")
                .and_then(|v| v.as_u64())
                .map_or(DEFAULT_LIMIT, |n| n as usize);
            let report = scan(&cfg.store, &root, &opts).or_else(|e| fail(e.to_string()))?;
            logged(cfg, |log, client| log_scan(log, &report, client));
            Ok(summarize(&report, limit))
        }
        "scan_code" => {
            let root = resolve(&cfg.workspace, str_arg(args, "path")).or_else(fail_str)?;
            let external: Vec<String> = args
                .get("external")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            let limit = args
                .get("limit")
                .and_then(|v| v.as_u64())
                .map_or(100, |n| n as usize);
            let opts = CodeOptions {
                external,
                semgrep_config: str_arg(args, "semgrep_config").map(str::to_string),
                work_dir: Some(cfg.store.dir().join("tmp")),
                max_findings: Some(limit),
                ..CodeOptions::default()
            };
            let r = scan_code(&root, &opts).or_else(|e| fail(e.to_string()))?;
            logged(cfg, |log, client| log.append(&code_event(&r, client)));
            Ok(serde_json::to_value(r).unwrap_or(Value::Null))
        }
        "scan_agent_config" => {
            let root = resolve(&cfg.workspace, str_arg(args, "path")).or_else(fail_str)?;
            let limit = args
                .get("limit")
                .and_then(|v| v.as_u64())
                .map_or(100, |n| n as usize);
            let opts = AgentOptions {
                // The server stays inside its workspace: the home directory is never read.
                include_home: false,
                scan: ScanOptions {
                    offline: cfg.offline,
                    ..ScanOptions::default()
                },
                max_findings: Some(limit),
                ..AgentOptions::default()
            };
            let r = scan_agent_config(&cfg.store, &root, &opts).or_else(|e| fail(e.to_string()))?;
            logged(cfg, |log, client| log.append(&agent_event(&r, client)));
            Ok(serde_json::to_value(r).unwrap_or(Value::Null))
        }
        "scan_runtime" => {
            let nvd = args.get("nvd").and_then(|v| v.as_bool()).unwrap_or(false);
            if nvd && cfg.offline {
                return fail("the server runs in offline mode; nvd lookups are disabled");
            }
            let opts = RuntimeOptions {
                products: string_list(args, "products"),
                nvd,
            };
            let report = scan_runtime(&cfg.store, &opts).or_else(|e| fail(e.to_string()))?;
            let workspace = cfg
                .workspace
                .canonicalize()
                .unwrap_or_else(|_| cfg.workspace.clone())
                .display()
                .to_string();
            logged(cfg, |log, client| {
                log.append(&runtime_event(&workspace, &report, client))
            });
            Ok(serde_json::to_value(report).unwrap_or(Value::Null))
        }
        "explain_advisory" => {
            let id =
                str_arg(args, "id").ok_or_else(|| ToolError::Failed("id is required".into()))?;
            let offline = cfg.offline
                || args
                    .get("offline")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
            let e = explain(&cfg.store, id, offline).or_else(|e| fail(e.to_string()))?;
            Ok(serde_json::to_value(e).unwrap_or(Value::Null))
        }
        "plan_fix" => {
            let root = resolve(&cfg.workspace, str_arg(args, "path")).or_else(fail_str)?;
            let opts = scan_opts(cfg, args).or_else(fail_str)?;
            let report = scan(&cfg.store, &root, &opts).or_else(|e| fail(e.to_string()))?;
            logged(cfg, |log, client| log_scan(log, &report, client));
            let plan = plan_fix(&report.findings, str_arg(args, "id"));
            logged(cfg, |log, client| {
                log.append(&plan_event(&root.display().to_string(), &plan, client))
            });
            let mut v = serde_json::to_value(plan).unwrap_or(Value::Null);
            v["notes"] = json!(report.notes);
            v["after_you_apply_it"] = json!(
                "Run the project's tests, call verify_fix with the advisory ids, then (recommended) call record_fix to log what you changed and why."
            );
            Ok(v)
        }
        "verify_fix" => {
            let root = resolve(&cfg.workspace, str_arg(args, "path")).or_else(fail_str)?;
            let opts = scan_opts(cfg, args).or_else(fail_str)?;
            let ids: Vec<String> = args
                .get("ids")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            if ids.is_empty() {
                return fail("ids is required (advisory ids from scan_dependencies)");
            }
            let seen = if cfg.log_enabled {
                seen_finding_ids(
                    &EventLog::for_store(&cfg.store),
                    &root.display().to_string(),
                )
            } else {
                Vec::new()
            };
            let out = verify_fix(&cfg.store, &root, &opts, &ids, &seen)
                .or_else(|e| fail(e.to_string()))?;
            logged(cfg, |log, client| {
                log.append(&verify_event(
                    &root.display().to_string(),
                    &ids,
                    &out,
                    client,
                ))
            });
            let mut v = serde_json::to_value(out).unwrap_or(Value::Null);
            v["next"] = json!(
                "If you changed files to fix these, call record_fix (recommended) so the report can show what changed and why."
            );
            Ok(v)
        }
        "record_fix" => {
            if !cfg.log_enabled {
                return fail(
                    "logging is disabled (OPENCRAYSEC_LOG=off), so there is nowhere to record the change",
                );
            }
            let root = resolve(&cfg.workspace, str_arg(args, "path")).or_else(fail_str)?;
            let input = FixInput {
                ids: string_list(args, "ids"),
                summary: str_arg(args, "summary").unwrap_or("").to_string(),
                reason: str_arg(args, "reason").unwrap_or("").to_string(),
                files: string_list(args, "files"),
                commands: string_list(args, "commands"),
                commit: str_arg(args, "commit").unwrap_or("").to_string(),
            };
            let client = cfg.client_name();
            let rec = record_fix(
                &EventLog::for_store(&cfg.store),
                &root.display().to_string(),
                &root,
                &input,
                client.as_deref(),
            )
            .or_else(fail_str)?;
            Ok(json!({
                "recorded": true,
                "recorded_at": rec.recorded_at,
                "lockfile_changes_detected": rec.changes,
                "baseline_found": rec.baseline_found,
                "ids_not_in_last_scan": rec.unknown_ids,
                "note": "Lockfile changes are measured by comparing dependency snapshots, not taken from your description. Call verify_fix to prove the advisories are gone."
            }))
        }
        "update_db" => {
            if cfg.offline {
                return fail("the server runs in offline mode; update_db is disabled");
            }
            let requested = eco_list(args).or_else(fail_str)?;
            let ecos: Vec<Ecosystem> = match requested {
                Some(e) => e,
                None => Ecosystem::ALL
                    .into_iter()
                    .filter(|e| cfg.store.has(*e))
                    .collect(),
            };
            let mut results = Vec::new();
            for eco in &ecos {
                match update::update_osv(&cfg.store, *eco) {
                    Ok(m) => results.push(json!({ "ecosystem": eco.osv_name(), "records": m.records, "updated_at": m.updated_at })),
                    Err(e) => results.push(json!({ "ecosystem": eco.osv_name(), "error": e.to_string() })),
                }
            }
            if args.get("enrich").and_then(|v| v.as_bool()).unwrap_or(true) {
                results.push(match update::update_kev(&cfg.store) {
                    Ok(n) => json!({ "source": "CISA KEV", "entries": n }),
                    Err(e) => json!({ "source": "CISA KEV", "error": e.to_string() }),
                });
                results.push(match update::update_epss(&cfg.store) {
                    Ok(n) => json!({ "source": "EPSS", "entries": n }),
                    Err(e) => json!({ "source": "EPSS", "error": e.to_string() }),
                });
                results.push(match update::update_cwe(&cfg.store) {
                    Ok(n) => json!({ "source": "MITRE CWE", "entries": n }),
                    Err(e) => json!({ "source": "MITRE CWE", "error": e.to_string() }),
                });
                results.push(match runtime_data::update_runtime(&cfg.store) {
                    Ok(u) => json!({ "source": "runtime release data", "products": u.products, "php_lines": u.php_lines, "php_error": u.php_error }),
                    Err(e) => json!({ "source": "runtime release data", "error": e.to_string() }),
                });
            }
            Ok(json!({ "updated": results, "status": cfg.store.status() }))
        }
        "db_status" => Ok(serde_json::to_value(cfg.store.status()).unwrap_or(Value::Null)),
        _ => Err(ToolError::UnknownTool),
    }
}

/// Writes to the activity log when it is enabled. A logging problem never fails a tool call.
fn logged(cfg: &ServerConfig, f: impl FnOnce(&EventLog, Option<&str>) -> std::io::Result<()>) {
    if cfg.log_enabled {
        let client = cfg.client_name();
        let _ = f(&EventLog::for_store(&cfg.store), client.as_deref());
    }
}

fn string_list(args: &Value, key: &str) -> Vec<String> {
    args.get(key)
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn fail_str<T>(m: String) -> Result<T, ToolError> {
    Err(ToolError::Failed(m))
}
