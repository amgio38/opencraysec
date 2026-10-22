//! The activity log: what was scanned, planned, fixed and verified, kept as one JSON object per
//! line (JSONL) under the data directory. No database. The dashboard and the HTML report read it.
//!
//! The log holds package names, versions, advisory ids and file paths. It never holds source code
//! or secret values. It stays on the local machine.

use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use opencraysec_db::{Store, now_rfc3339};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub mod events;
pub mod snapshot;
pub mod summary;

/// Log format version, stored on every event.
pub const FORMAT: u32 = 1;

/// One log line.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    /// Format version.
    pub v: u32,
    /// RFC 3339 UTC time.
    pub ts: String,
    /// `scan`, `scan_code`, `scan_agent_config`, `scan_runtime`, `plan_fix`, `verify_fix` or `record_fix`.
    pub kind: String,
    /// The project path the event is about.
    pub workspace: String,
    /// The AI client that asked (MCP `clientInfo`), or `cli`.
    pub client: Option<String>,
    /// Event payload; its shape depends on `kind`.
    pub data: Value,
}

impl Event {
    /// A new event stamped with the current time.
    pub fn new(kind: &str, workspace: &str, client: Option<&str>, data: Value) -> Event {
        Event {
            v: FORMAT,
            ts: now_rfc3339(),
            kind: kind.to_string(),
            workspace: workspace.to_string(),
            client: client.map(str::to_string),
            data,
        }
    }
}

/// True unless `OPENCRAYSEC_LOG` is `off`, `0`, `false` or `no`.
pub fn enabled_by_env() -> bool {
    !matches!(
        std::env::var("OPENCRAYSEC_LOG")
            .map(|v| v.to_ascii_lowercase())
            .as_deref(),
        Ok("off" | "0" | "false" | "no")
    )
}

/// Handle to the log directory.
#[derive(Debug, Clone)]
pub struct EventLog {
    dir: PathBuf,
}

impl EventLog {
    /// A log rooted at `dir` (created on first write).
    pub fn at(dir: impl Into<PathBuf>) -> EventLog {
        EventLog { dir: dir.into() }
    }

    /// The log that lives next to the advisory data of `store`.
    pub fn for_store(store: &Store) -> EventLog {
        EventLog::at(store.dir().join("log"))
    }

    /// Log directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn file(&self) -> PathBuf {
        self.dir.join("events.jsonl")
    }

    /// Appends one event. The line is written with a single `write` so concurrent processes do
    /// not interleave inside a line.
    pub fn append(&self, ev: &Event) -> io::Result<()> {
        fs::create_dir_all(&self.dir)?;
        let mut line = serde_json::to_string(ev)?;
        line.push('\n');
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.file())?;
        f.write_all(line.as_bytes())
    }

    /// All events, oldest first. Unreadable lines are skipped.
    pub fn read_all(&self) -> Vec<Event> {
        let Ok(f) = fs::File::open(self.file()) else {
            return Vec::new();
        };
        BufReader::new(f)
            .lines()
            .map_while(Result::ok)
            .filter_map(|l| serde_json::from_str::<Event>(&l).ok())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_and_read_back_skipping_garbage() {
        let dir = tempfile::tempdir().expect("tmp");
        let log = EventLog::at(dir.path().join("log"));
        assert!(log.read_all().is_empty());
        log.append(&Event::new(
            "scan",
            "/p",
            Some("claude-code"),
            serde_json::json!({"a": 1}),
        ))
        .expect("append");
        fs::OpenOptions::new()
            .append(true)
            .open(log.file())
            .expect("open")
            .write_all(b"not json\n")
            .expect("write");
        log.append(&Event::new("verify_fix", "/p", None, Value::Null))
            .expect("append");
        let all = log.read_all();
        assert_eq!(all.len(), 2);
        assert_eq!(
            (all[0].kind.as_str(), all[0].client.as_deref()),
            ("scan", Some("claude-code"))
        );
        assert_eq!(all[1].client, None);
        assert_eq!(all[0].v, FORMAT);
    }

    #[test]
    fn env_switch_defaults_to_enabled() {
        if std::env::var_os("OPENCRAYSEC_LOG").is_none() {
            assert!(enabled_by_env());
        }
    }
}
