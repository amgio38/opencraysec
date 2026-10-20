//! Package snapshots: the set of resolved dependencies at the time of a scan. Comparing two
//! snapshots is the evidence for "the lockfile changed from X to Y", independent of what the AI
//! says it did.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use opencraysec_core::Package;
use serde::{Deserialize, Serialize};

use crate::EventLog;

const KEEP: usize = 12;

/// The resolved dependencies of a project at one moment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Snapshot {
    /// When it was taken.
    pub ts: String,
    /// Hash of the package set.
    pub hash: String,
    /// `"<ecosystem> <name>"` to versions (several versions of one package can coexist).
    pub packages: BTreeMap<String, Vec<String>>,
}

/// A version change between two snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    /// `"<ecosystem> <name>"` key, for example `npm lodash`.
    pub package: String,
    /// Versions before (empty when the package is new).
    pub from: Vec<String>,
    /// Versions after (empty when the package was removed).
    pub to: Vec<String>,
}

fn fnv(data: &str) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in data.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{h:016x}")
}

/// Builds a snapshot from resolved packages.
pub fn take(ts: &str, pkgs: &[Package]) -> Snapshot {
    let mut packages: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for p in pkgs {
        let key = format!("{} {}", p.ecosystem.osv_name(), p.name);
        let v = packages.entry(key).or_default();
        if !v.contains(&p.version) {
            v.push(p.version.clone());
            v.sort();
        }
    }
    let canonical = serde_json::to_string(&packages).unwrap_or_default();
    Snapshot {
        ts: ts.to_string(),
        hash: fnv(&canonical),
        packages,
    }
}

/// Differences between `before` and `after`, sorted by package.
pub fn diff(before: &Snapshot, after: &Snapshot) -> Vec<Change> {
    let mut out = Vec::new();
    let keys: std::collections::BTreeSet<&String> = before
        .packages
        .keys()
        .chain(after.packages.keys())
        .collect();
    for k in keys {
        let (b, a) = (before.packages.get(k), after.packages.get(k));
        if b != a {
            out.push(Change {
                package: k.clone(),
                from: b.cloned().unwrap_or_default(),
                to: a.cloned().unwrap_or_default(),
            });
        }
    }
    out
}

/// A short stable hash of a project path, used as a directory name.
pub fn workspace_key(workspace: &str) -> String {
    fnv(workspace)
}

impl EventLog {
    fn snap_dir(&self, workspace: &str) -> PathBuf {
        self.dir().join("snapshots").join(workspace_key(workspace))
    }

    /// Stores a snapshot for `workspace` (skipped when identical to the newest one) and keeps the
    /// most recent few.
    pub fn save_snapshot(&self, workspace: &str, snap: &Snapshot) -> std::io::Result<()> {
        if self
            .snapshots(workspace)
            .last()
            .is_some_and(|s| s.hash == snap.hash)
        {
            return Ok(());
        }
        let dir = self.snap_dir(workspace);
        fs::create_dir_all(&dir)?;
        let name = format!("{}-{}.json", snap.ts.replace([':', '-'], ""), snap.hash);
        fs::write(dir.join(name), serde_json::to_string(snap)?)?;
        let mut files: Vec<_> = fs::read_dir(&dir)?.flatten().map(|e| e.path()).collect();
        files.sort();
        while files.len() > KEEP {
            let _ = fs::remove_file(files.remove(0));
        }
        Ok(())
    }

    /// Snapshots for `workspace`, oldest first.
    pub fn snapshots(&self, workspace: &str) -> Vec<Snapshot> {
        let Ok(rd) = fs::read_dir(self.snap_dir(workspace)) else {
            return Vec::new();
        };
        let mut files: Vec<_> = rd.flatten().map(|e| e.path()).collect();
        files.sort();
        files
            .iter()
            .filter_map(|p| fs::read_to_string(p).ok())
            .filter_map(|t| serde_json::from_str(&t).ok())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opencraysec_core::Ecosystem;

    fn p(name: &str, v: &str) -> Package {
        Package {
            ecosystem: Ecosystem::Npm,
            name: name.into(),
            version: v.into(),
            source: "l".into(),
            dev: false,
        }
    }

    #[test]
    fn diff_reports_changed_added_and_removed() {
        let a = take(
            "t1",
            &[p("lodash", "4.17.4"), p("old", "1.0.0"), p("same", "1.0.0")],
        );
        let b = take(
            "t2",
            &[
                p("lodash", "4.17.21"),
                p("new", "2.0.0"),
                p("same", "1.0.0"),
            ],
        );
        assert_ne!(a.hash, b.hash);
        let d = diff(&a, &b);
        let find = |n: &str| {
            d.iter()
                .find(|c| c.package == format!("npm {n}"))
                .expect(n)
                .clone()
        };
        assert_eq!(find("lodash").from, vec!["4.17.4".to_string()]);
        assert_eq!(find("lodash").to, vec!["4.17.21".to_string()]);
        assert!(find("old").to.is_empty() && find("new").from.is_empty());
        assert_eq!(d.len(), 3);
        assert!(diff(&a, &a).is_empty());
        assert_eq!(
            take("x", &[p("a", "1"), p("a", "1")]).packages["npm a"],
            vec!["1"]
        );
    }

    #[test]
    fn snapshots_are_stored_deduplicated_and_pruned() {
        let dir = tempfile::tempdir().expect("tmp");
        let log = EventLog::at(dir.path());
        let s1 = take("2026-10-19T10:00:00Z", &[p("a", "1")]);
        log.save_snapshot("/w", &s1).expect("save");
        log.save_snapshot("/w", &take("2026-10-19T10:00:05Z", &[p("a", "1")]))
            .expect("same set is not stored twice");
        assert_eq!(log.snapshots("/w").len(), 1);
        for i in 0..20 {
            log.save_snapshot(
                "/w",
                &take(
                    &format!("2026-10-19T11:{i:02}:00Z"),
                    &[p("a", &format!("{}", i + 2))],
                ),
            )
            .expect("save");
        }
        let all = log.snapshots("/w");
        assert_eq!(all.len(), KEEP);
        assert_eq!(all.last().expect("last").packages["npm a"], vec!["21"]);
        assert!(log.snapshots("/other").is_empty());
    }
}
