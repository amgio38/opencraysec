//! JSON-RPC framing and dispatch.

use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::sync::Mutex;

use opencraysec_db::Store;
use serde_json::{Value, json};

use crate::tools;
use crate::{PROTOCOL_VERSION, SERVER_NAME};

/// A single request line may not exceed this many bytes.
pub const MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;

/// Server configuration.
pub struct ServerConfig {
    /// The only directory tools may scan.
    pub workspace: PathBuf,
    /// Advisory store.
    pub store: Store,
    /// Refuse network access (also makes `update_db` fail).
    pub offline: bool,
    /// Keep an activity log (what was scanned, planned, fixed and verified).
    pub log_enabled: bool,
    /// The AI client's name, taken from the `initialize` request.
    pub client: Mutex<Option<String>>,
}

impl ServerConfig {
    /// A configuration with logging on (unless `OPENCRAYSEC_LOG=off`).
    pub fn new(workspace: PathBuf, store: Store, offline: bool) -> ServerConfig {
        ServerConfig {
            workspace,
            store,
            offline,
            log_enabled: opencraysec_log::enabled_by_env(),
            client: Mutex::new(None),
        }
    }

    /// The connected client's name, if it sent one.
    pub fn client_name(&self) -> Option<String> {
        self.client.lock().ok().and_then(|c| c.clone())
    }
}

const INSTRUCTIONS: &str = "opencraysec checks a project's dependencies against current public \
vulnerability data (OSV, with CISA KEV and EPSS for ranking). Call scan_dependencies first. Use \
explain_advisory for details, plan_fix for the upgrade commands, then run the commands yourself \
(ask the user before major-version bumps), call verify_fix to prove the findings are gone, and (recommended) record_fix to log what you changed and why, like a commit message. \
A clean scan does not prove the code is secure: it only covers known advisories for lockfile \
versions. Read `notes` in every result.";

fn ok(id: &Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn err(id: &Value, code: i32, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

/// Handles one parsed message; `None` means no response (a notification).
pub fn handle(cfg: &ServerConfig, msg: &Value) -> Option<Value> {
    let id = msg.get("id").cloned();
    let method = msg.get("method").and_then(|m| m.as_str());
    let Some(method) = method else {
        return id.map(|i| err(&i, -32600, "invalid request: missing method"));
    };
    let id = id?;
    Some(match method {
        "initialize" => {
            let info = msg.get("params").and_then(|p| p.get("clientInfo"));
            let name = info.and_then(|i| i.get("name")).and_then(|n| n.as_str());
            let version = info.and_then(|i| i.get("version")).and_then(|n| n.as_str());
            if let (Some(name), Ok(mut slot)) = (name, cfg.client.lock()) {
                let clean: String = name.chars().filter(|c| !c.is_control()).take(80).collect();
                *slot = Some(match version {
                    Some(v) => format!(
                        "{clean} {}",
                        v.chars()
                            .filter(|c| !c.is_control())
                            .take(40)
                            .collect::<String>()
                    ),
                    None => clean,
                });
            }
            ok(
                &id,
                json!({
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": SERVER_NAME, "version": env!("CARGO_PKG_VERSION") },
                    "instructions": INSTRUCTIONS,
                }),
            )
        }
        "ping" => ok(&id, json!({})),
        "tools/list" => ok(&id, json!({ "tools": tools::list() })),
        "tools/call" => {
            let params = msg.get("params").cloned().unwrap_or(Value::Null);
            let Some(name) = params.get("name").and_then(|n| n.as_str()) else {
                return Some(err(&id, -32602, "tools/call needs params.name"));
            };
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            match tools::call(cfg, name, &args) {
                Ok(v) => ok(&id, tool_result(&v, false)),
                Err(tools::ToolError::UnknownTool) => {
                    err(&id, -32602, &format!("unknown tool: {name}"))
                }
                Err(tools::ToolError::Failed(m)) => {
                    ok(&id, tool_result(&json!({ "error": m }), true))
                }
            }
        }
        other => err(&id, -32601, &format!("method not found: {other}")),
    })
}

fn tool_result(v: &Value, is_error: bool) -> Value {
    json!({
        "content": [{ "type": "text", "text": serde_json::to_string(v).unwrap_or_default() }],
        "structuredContent": v,
        "isError": is_error,
    })
}

/// Reads requests from `input` until EOF, writing responses to `output`.
pub fn serve<R: BufRead, W: Write>(
    cfg: &ServerConfig,
    mut input: R,
    mut output: W,
) -> io::Result<()> {
    let mut line = String::new();
    loop {
        line.clear();
        let n = io::Read::take(&mut input, MAX_MESSAGE_BYTES as u64 + 1).read_line(&mut line)?;
        if n == 0 {
            return Ok(());
        }
        if line.len() > MAX_MESSAGE_BYTES {
            // Drain the rest of the oversized line so framing stays in sync.
            let mut sink = Vec::new();
            if !line.ends_with('\n') {
                input.read_until(b'\n', &mut sink)?;
            }
            write_line(&mut output, &err(&Value::Null, -32600, "message too large"))?;
            continue;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Value>(trimmed) {
            Ok(Value::Array(_)) => Some(err(
                &Value::Null,
                -32600,
                "batch requests are not supported",
            )),
            Ok(msg) => handle(cfg, &msg),
            Err(_) => Some(err(&Value::Null, -32700, "parse error")),
        };
        if let Some(r) = response {
            write_line(&mut output, &r)?;
        }
    }
}

fn write_line<W: Write>(out: &mut W, v: &Value) -> io::Result<()> {
    out.write_all(v.to_string().as_bytes())?;
    out.write_all(b"\n")?;
    out.flush()
}
