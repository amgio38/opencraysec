//! Local advisory store, database updates and the online OSV fallback.
//!
//! The store keeps one JSONL file per ecosystem under the data directory. Each line starts with
//! the package names the advisory affects, so a scan can skip unrelated advisories without
//! parsing them.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use opencraysec_core::Ecosystem;
use opencraysec_core::osv::OsvRecord;
use serde::{Deserialize, Serialize};

pub mod cwe;
pub mod net;
pub mod nvd;
pub mod online;
pub mod update;

#[cfg(any(test, feature = "testutil"))]
pub mod testutil;

/// Error type for the store and the network helpers.
#[derive(Debug)]
pub struct DbError(pub String);

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DbError {}

impl From<io::Error> for DbError {
    fn from(e: io::Error) -> Self {
        DbError(e.to_string())
    }
}

impl From<serde_json::Error> for DbError {
    fn from(e: serde_json::Error) -> Self {
        DbError(e.to_string())
    }
}

/// Separator between the name prefix and the JSON body of a JSONL line.
const FIELD_SEP: char = '\t';
/// Separator between package names in the prefix.
const NAME_SEP: char = '\u{1f}';

/// Per-ecosystem metadata written next to the JSONL file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EcoMeta {
    /// RFC 3339 UTC time of the last successful update.
    pub updated_at: String,
    /// Number of advisories stored.
    pub records: usize,
    /// Dataset layout version: 2 adds the symbol data that reachability needs.
    #[serde(default = "schema_v1")]
    pub schema: u32,
}

fn schema_v1() -> u32 {
    1
}

/// Current dataset layout version.
pub const SCHEMA: u32 = 2;

/// Snapshot of what the store holds.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Status {
    /// Data directory.
    pub dir: String,
    /// Per-ecosystem metadata for ecosystems that were downloaded.
    pub ecosystems: Vec<(String, EcoMeta)>,
    /// When the CISA KEV list was last fetched.
    pub kev_updated_at: Option<String>,
    /// When the EPSS scores were last fetched.
    pub epss_updated_at: Option<String>,
    /// When the MITRE CWE catalog was last fetched.
    pub cwe_updated_at: Option<String>,
}

/// Where datasets and lookups come from. The defaults are the public services; override them to
/// use a mirror (environment variables below) or, in tests, a local mock server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoints {
    /// Base of the OSV per-ecosystem dumps (`<base>/<ecosystem>/all.zip`).
    pub osv_dump: String,
    /// Base of the OSV API (`<base>/querybatch`, `<base>/vulns/<id>`).
    pub osv_api: String,
    /// CISA KEV feed.
    pub kev: String,
    /// EPSS scores (gzip CSV).
    pub epss: String,
    /// MITRE CWE catalog (zip).
    pub cwe: String,
    /// NVD CVE API 2.0.
    pub nvd: String,
    /// Minimum pause between NVD requests, in milliseconds (default: 6500, or 700 with a key).
    pub nvd_gap_ms: Option<u64>,
}

impl Default for Endpoints {
    fn default() -> Self {
        Endpoints {
            osv_dump: "https://osv-vulnerabilities.storage.googleapis.com".into(),
            osv_api: "https://api.osv.dev/v1".into(),
            kev: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json".into(),
            epss: "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz".into(),
            cwe: "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip".into(),
            nvd: "https://services.nvd.nist.gov/rest/json/cves/2.0".into(),
            nvd_gap_ms: None,
        }
    }
}

impl Endpoints {
    /// Defaults, overridden by `OPENCRAYSEC_OSV_DUMP_URL`, `OPENCRAYSEC_OSV_API_URL`,
    /// `OPENCRAYSEC_KEV_URL`, `OPENCRAYSEC_EPSS_URL`, `OPENCRAYSEC_CWE_URL`, `OPENCRAYSEC_NVD_URL`.
    pub fn from_env() -> Endpoints {
        Endpoints::from_lookup(|k| std::env::var(k).ok())
    }

    /// Like [`Endpoints::from_env`], reading variables through `get` (empty values are ignored).
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Endpoints {
        let mut e = Endpoints::default();
        let get = |k: &str| get(k).filter(|v| !v.is_empty());
        let slots: [(&str, &mut String); 6] = [
            ("OPENCRAYSEC_OSV_DUMP_URL", &mut e.osv_dump),
            ("OPENCRAYSEC_OSV_API_URL", &mut e.osv_api),
            ("OPENCRAYSEC_KEV_URL", &mut e.kev),
            ("OPENCRAYSEC_EPSS_URL", &mut e.epss),
            ("OPENCRAYSEC_CWE_URL", &mut e.cwe),
            ("OPENCRAYSEC_NVD_URL", &mut e.nvd),
        ];
        for (name, slot) in slots {
            if let Some(v) = get(name) {
                *slot = v;
            }
        }
        e
    }
}

/// The advisory store rooted at a data directory.
#[derive(Debug, Clone)]
pub struct Store {
    root: PathBuf,
    endpoints: Endpoints,
}

/// Default data directory: `$OPENCRAYSEC_HOME`, else `$XDG_DATA_HOME/opencraysec`, else
/// `~/.local/share/opencraysec`.
pub fn default_dir() -> Result<PathBuf, DbError> {
    default_dir_from(|k| std::env::var_os(k))
}

/// Like [`default_dir`], reading variables through `get`.
pub fn default_dir_from(
    get: impl Fn(&str) -> Option<std::ffi::OsString>,
) -> Result<PathBuf, DbError> {
    let get = |k: &str| get(k).filter(|p| !p.is_empty());
    if let Some(p) = get("OPENCRAYSEC_HOME") {
        return Ok(PathBuf::from(p));
    }
    if let Some(p) = get("XDG_DATA_HOME") {
        return Ok(PathBuf::from(p).join("opencraysec"));
    }
    let home = get("HOME")
        .ok_or_else(|| DbError("cannot find a data directory: set OPENCRAYSEC_HOME".into()))?;
    Ok(PathBuf::from(home).join(".local/share/opencraysec"))
}

/// Current UTC time as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_epoch(secs)
}

/// Formats Unix seconds as RFC 3339 UTC.
pub fn format_epoch(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Reads the `#updated_at=...` first line of a TSV data file.
fn header_stamp(path: &Path) -> Option<String> {
    let file = fs::File::open(path).ok()?;
    let mut first = String::new();
    BufReader::new(file).read_line(&mut first).ok()?;
    first
        .trim()
        .strip_prefix("#updated_at=")
        .map(str::to_string)
}

/// Builds the JSONL line for a record, or `None` if it names no package of `eco`.
pub fn encode_line(eco: Ecosystem, rec: &OsvRecord) -> Result<Option<String>, DbError> {
    let mut names: Vec<String> = rec
        .affected
        .iter()
        .filter_map(|a| a.package.as_ref())
        .filter(|p| Ecosystem::from_osv_name(&p.ecosystem) == Some(eco))
        .map(|p| eco.normalize_name(&p.name))
        .collect();
    names.sort();
    names.dedup();
    if names.is_empty() {
        return Ok(None);
    }
    let prefix = names.join(&NAME_SEP.to_string());
    Ok(Some(format!(
        "{prefix}{FIELD_SEP}{}",
        serde_json::to_string(rec)?
    )))
}

impl Store {
    /// A store at an explicit directory (created on first write).
    pub fn at(root: impl Into<PathBuf>) -> Store {
        Store {
            root: root.into(),
            endpoints: Endpoints::default(),
        }
    }

    /// The same store using different download and lookup endpoints.
    pub fn with_endpoints(mut self, endpoints: Endpoints) -> Store {
        self.endpoints = endpoints;
        self
    }

    /// Endpoints in use.
    pub fn endpoints(&self) -> &Endpoints {
        &self.endpoints
    }

    /// The store at [`default_dir`].
    pub fn open_default() -> Result<Store, DbError> {
        Ok(Store::at(default_dir()?).with_endpoints(Endpoints::from_env()))
    }

    /// Data directory.
    pub fn dir(&self) -> &Path {
        &self.root
    }

    pub(crate) fn osv_dir(&self) -> PathBuf {
        self.root.join("osv")
    }

    pub(crate) fn jsonl_path(&self, eco: Ecosystem) -> PathBuf {
        self.osv_dir().join(format!("{}.jsonl", eco.osv_name()))
    }

    pub(crate) fn meta_path(&self, eco: Ecosystem) -> PathBuf {
        self.osv_dir().join(format!("{}.meta.json", eco.osv_name()))
    }

    pub(crate) fn online_cache_dir(&self) -> PathBuf {
        self.root.join("osv-online")
    }

    pub(crate) fn nvd_dir(&self) -> PathBuf {
        self.root.join("nvd")
    }

    pub(crate) fn cwe_path(&self) -> PathBuf {
        self.root.join("cwe.tsv")
    }

    pub(crate) fn kev_path(&self) -> PathBuf {
        self.root.join("kev.json")
    }

    pub(crate) fn epss_path(&self) -> PathBuf {
        self.root.join("epss.tsv")
    }

    /// Metadata for an ecosystem, if it was downloaded.
    pub fn meta(&self, eco: Ecosystem) -> Option<EcoMeta> {
        let text = fs::read_to_string(self.meta_path(eco)).ok()?;
        serde_json::from_str(&text).ok()
    }

    /// True if the ecosystem's advisories are stored locally.
    pub fn has(&self, eco: Ecosystem) -> bool {
        self.meta(eco).is_some() && self.jsonl_path(eco).is_file()
    }

    /// Summary of the store's contents.
    pub fn status(&self) -> Status {
        let stamp = |p: PathBuf| {
            fs::read_to_string(p)
                .ok()
                .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
                .and_then(|v| {
                    v.get("updated_at")
                        .and_then(|x| x.as_str())
                        .map(str::to_string)
                })
        };
        Status {
            dir: self.root.display().to_string(),
            ecosystems: Ecosystem::ALL
                .into_iter()
                .filter_map(|e| self.meta(e).map(|m| (e.osv_name().to_string(), m)))
                .collect(),
            kev_updated_at: stamp(self.kev_path()),
            epss_updated_at: header_stamp(&self.epss_path()),
            cwe_updated_at: header_stamp(&self.cwe_path()),
        }
    }

    /// Loads the advisories that mention any of `wanted` (normalised package names).
    pub fn load_for(
        &self,
        eco: Ecosystem,
        wanted: &HashSet<String>,
    ) -> Result<HashMap<String, Vec<OsvRecord>>, DbError> {
        let mut out: HashMap<String, Vec<OsvRecord>> = HashMap::new();
        let file = fs::File::open(self.jsonl_path(eco))?;
        for line in BufReader::new(file).lines() {
            let line = line?;
            let Some((prefix, body)) = line.split_once(FIELD_SEP) else {
                continue;
            };
            let hits: Vec<&str> = prefix
                .split(NAME_SEP)
                .filter(|n| wanted.contains(*n))
                .collect();
            if hits.is_empty() {
                continue;
            }
            let rec: OsvRecord = serde_json::from_str(body)?;
            for n in hits {
                out.entry(n.to_string()).or_default().push(rec.clone());
            }
        }
        Ok(out)
    }

    /// CVE ids on the CISA KEV list (empty if never fetched).
    pub fn kev(&self) -> HashSet<String> {
        fs::read_to_string(self.kev_path())
            .ok()
            .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
            .and_then(|v| {
                v.get("ids").and_then(|x| x.as_array()).map(|a| {
                    a.iter()
                        .filter_map(|i| i.as_str().map(str::to_string))
                        .collect()
                })
            })
            .unwrap_or_default()
    }

    /// EPSS scores for the requested CVE ids (empty if never fetched).
    pub fn epss(&self, ids: &HashSet<String>) -> HashMap<String, f32> {
        let mut out = HashMap::new();
        let Ok(file) = fs::File::open(self.epss_path()) else {
            return out;
        };
        for line in BufReader::new(file).lines().map_while(Result::ok) {
            if let Some((id, score)) = line.split_once('\t')
                && ids.contains(id)
                && let Ok(s) = score.parse::<f32>()
            {
                out.insert(id.to_string(), s);
            }
        }
        out
    }

    pub(crate) fn write_atomic(&self, path: &Path, bytes: &[u8]) -> Result<(), DbError> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("tmp");
        let mut f = fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        fs::rename(&tmp, path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn epoch_formatting() {
        assert_eq!(format_epoch(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_epoch(1_792_000_000), "2026-10-14T17:46:40Z");
        assert_eq!(format_epoch(951_782_400), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn lines_roundtrip_and_filter() {
        let rec: OsvRecord = serde_json::from_str(
            r#"{"id":"A","affected":[{"package":{"ecosystem":"npm","name":"lodash"}},
                 {"package":{"ecosystem":"npm","name":"underscore"}}]}"#,
        )
        .expect("json");
        let line = encode_line(Ecosystem::Npm, &rec)
            .expect("ok")
            .expect("some");
        assert!(line.starts_with("lodash\u{1f}underscore\t"));
        assert!(encode_line(Ecosystem::Go, &rec).expect("ok").is_none());

        let dir = tempfile::tempdir().expect("tmp");
        let store = Store::at(dir.path());
        fs::create_dir_all(store.osv_dir()).expect("mkdir");
        fs::write(store.jsonl_path(Ecosystem::Npm), format!("{line}\n")).expect("write");
        let want: HashSet<String> = ["lodash".to_string()].into();
        let got = store.load_for(Ecosystem::Npm, &want).expect("load");
        assert_eq!(got["lodash"][0].id, "A");
        let none: HashSet<String> = ["x".to_string()].into();
        assert!(
            store
                .load_for(Ecosystem::Npm, &none)
                .expect("load")
                .is_empty()
        );
    }

    #[test]
    fn kev_and_epss_readers() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = Store::at(dir.path());
        assert!(store.kev().is_empty());
        fs::write(
            store.kev_path(),
            r#"{"updated_at":"t","ids":["CVE-1","CVE-2"]}"#,
        )
        .expect("w");
        assert!(store.kev().contains("CVE-2"));
        fs::write(store.epss_path(), "#updated_at=t\nCVE-1\t0.5\nCVE-9\t0.1\n").expect("w");
        let ids: HashSet<String> = ["CVE-1".to_string()].into();
        let e = store.epss(&ids);
        assert_eq!(e.len(), 1);
        assert!((e["CVE-1"] - 0.5).abs() < 1e-6);
        assert_eq!(store.status().epss_updated_at.as_deref(), Some("t"));
    }

    #[test]
    fn endpoints_and_data_dir_come_from_the_environment_in_the_right_order() {
        let env = |pairs: Vec<(&'static str, &'static str)>| {
            move |k: &str| {
                pairs
                    .iter()
                    .find(|(n, _)| *n == k)
                    .map(|(_, v)| v.to_string())
            }
        };
        assert_eq!(Endpoints::from_lookup(|_| None), Endpoints::default());
        let e = Endpoints::from_lookup(env(vec![
            ("OPENCRAYSEC_OSV_DUMP_URL", "http://a"),
            ("OPENCRAYSEC_OSV_API_URL", "http://b"),
            ("OPENCRAYSEC_KEV_URL", "http://c"),
            ("OPENCRAYSEC_EPSS_URL", "http://d"),
            ("OPENCRAYSEC_CWE_URL", "http://e"),
            ("OPENCRAYSEC_NVD_URL", ""),
        ]));
        assert_eq!(
            (
                e.osv_dump.as_str(),
                e.osv_api.as_str(),
                e.kev.as_str(),
                e.epss.as_str(),
                e.cwe.as_str()
            ),
            ("http://a", "http://b", "http://c", "http://d", "http://e")
        );
        assert_eq!(e.nvd, Endpoints::default().nvd, "an empty value is ignored");

        let dir = |pairs: Vec<(&'static str, &'static str)>| {
            default_dir_from(move |k| {
                pairs
                    .iter()
                    .find(|(n, _)| *n == k)
                    .map(|(_, v)| (*v).into())
            })
        };
        let home = dir(vec![
            ("OPENCRAYSEC_HOME", "/h"),
            ("XDG_DATA_HOME", "/x"),
            ("HOME", "/u"),
        ])
        .expect("dir");
        assert_eq!(home, PathBuf::from("/h"));
        let xdg = dir(vec![("XDG_DATA_HOME", "/x"), ("HOME", "/u")]).expect("dir");
        assert_eq!(xdg, PathBuf::from("/x/opencraysec"));
        let fallback = dir(vec![("OPENCRAYSEC_HOME", ""), ("HOME", "/u")]).expect("dir");
        assert_eq!(fallback, PathBuf::from("/u/.local/share/opencraysec"));
        assert!(dir(vec![]).is_err(), "no HOME means no default location");
    }

    #[test]
    fn errors_convert_and_display() {
        let io: DbError = io::Error::new(io::ErrorKind::NotFound, "gone").into();
        assert!(io.to_string().contains("gone"));
        let json: DbError = serde_json::from_str::<Value>("{")
            .expect_err("bad json")
            .into();
        assert!(!json.to_string().is_empty());
        let boxed: Box<dyn std::error::Error> = Box::new(DbError("x".into()));
        assert_eq!(boxed.to_string(), "x");
    }

    #[test]
    fn store_paths_status_and_atomic_writes() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = Store::at(dir.path().join("data"));
        assert_eq!(store.dir(), dir.path().join("data"));
        assert_eq!(store.endpoints(), &Endpoints::default());
        assert!(!store.has(Ecosystem::Go));
        assert!(
            store.load_for(Ecosystem::Go, &HashSet::new()).is_err(),
            "no data file yet"
        );
        store
            .write_atomic(&store.dir().join("deep/er/file.txt"), b"hi")
            .expect("write");
        assert_eq!(
            fs::read(store.dir().join("deep/er/file.txt")).expect("read"),
            b"hi"
        );
        assert!(
            !store.dir().join("deep/er/file.tmp").exists(),
            "the temporary file is renamed away"
        );
        let st = store.status();
        assert!(
            st.ecosystems.is_empty() && st.kev_updated_at.is_none() && st.epss_updated_at.is_none()
        );
        assert!(default_dir().is_ok() || std::env::var_os("HOME").is_none());
        assert!(Ecosystem::ALL.iter().all(|e| store.meta(*e).is_none()));
    }
}
