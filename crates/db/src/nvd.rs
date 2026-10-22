//! NVD enrichment: CVSS base score (v3.0, v3.1, v4.0) and CWE ids for CVEs the advisory databases
//! left unscored. Results are cached; requests respect NVD's rate limit.

use std::fs;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::{DbError, Store, net};

/// Scores can be revised, so cached answers older than this are fetched again.
const TTL_SECS: u64 = 30 * 24 * 3600;

/// What NVD says about one CVE.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NvdInfo {
    /// CVSS base score, preferring the primary v3.1 score, then v4.0, then v3.0.
    pub cvss: Option<f32>,
    /// CWE ids such as `CWE-79` (placeholders like `NVD-CWE-Other` are dropped).
    pub cwes: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct Cached {
    fetched_at: u64,
    info: NvdInfo,
}

/// True for `CVE-YYYY-NNNN...`.
pub fn is_cve_id(id: &str) -> bool {
    let mut parts = id.split('-');
    parts.next() == Some("CVE")
        && parts
            .next()
            .is_some_and(|y| y.len() == 4 && y.chars().all(|c| c.is_ascii_digit()))
        && parts
            .next()
            .is_some_and(|n| n.len() >= 4 && n.chars().all(|c| c.is_ascii_digit()))
        && parts.next().is_none()
}

/// Reads score and CWEs from an NVD 2.0 response body.
pub fn parse_response(v: &serde_json::Value) -> NvdInfo {
    let mut info = NvdInfo::default();
    let Some(cve) = v
        .get("vulnerabilities")
        .and_then(|x| x.get(0))
        .and_then(|x| x.get("cve"))
    else {
        return info;
    };
    let (cvss, cwes) = opencraysec_runtime::score_and_cwes(cve);
    info.cvss = cvss;
    info.cwes = cwes;
    info
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn cache_path(store: &Store, cve: &str) -> std::path::PathBuf {
    store.nvd_dir().join(format!("{cve}.json"))
}

/// The cached answer for `cve`, if there is one (`fresh_only` ignores entries past the TTL).
pub fn cached(store: &Store, cve: &str, fresh_only: bool) -> Option<NvdInfo> {
    if !is_cve_id(cve) {
        return None;
    }
    let c: Cached = serde_json::from_str(&fs::read_to_string(cache_path(store, cve)).ok()?).ok()?;
    if fresh_only && now_secs().saturating_sub(c.fetched_at) > TTL_SECS {
        return None;
    }
    Some(c.info)
}

static LAST_REQUEST: Mutex<Option<Instant>> = Mutex::new(None);

fn wait_for_rate_limit(has_key: bool, override_ms: Option<u64>) {
    // NVD allows 5 requests per 30 s without a key and 50 with one.
    let gap = Duration::from_millis(override_ms.unwrap_or(if has_key { 700 } else { 6500 }));
    if let Ok(mut last) = LAST_REQUEST.lock() {
        if let Some(t) = *last {
            let elapsed = t.elapsed();
            if elapsed < gap {
                std::thread::sleep(gap - elapsed);
            }
        }
        *last = Some(Instant::now());
    }
}

/// Fetches `cve` from NVD and caches the answer. `api_key` is optional (`NVD_API_KEY`).
pub fn fetch(store: &Store, cve: &str, api_key: Option<&str>) -> Result<NvdInfo, DbError> {
    if !is_cve_id(cve) {
        return Err(DbError(format!("not a CVE id: {cve:?}")));
    }
    wait_for_rate_limit(api_key.is_some(), store.endpoints().nvd_gap_ms);
    let url = format!("{}?cveId={cve}", store.endpoints().nvd);
    let headers: Vec<(&str, &str)> = api_key.map(|k| vec![("apiKey", k)]).unwrap_or_default();
    let bytes = net::get_bytes_with_headers(&url, &headers, 8 * 1024 * 1024)?;
    let info = parse_response(&serde_json::from_slice(&bytes)?);
    let doc = Cached {
        fetched_at: now_secs(),
        info: info.clone(),
    };
    store.write_atomic(
        &cache_path(store, cve),
        serde_json::to_string(&doc)?.as_bytes(),
    )?;
    Ok(info)
}

/// Answers to a CPE lookup are cached for this long. New CVEs appear every day, unlike score revisions.
const CPE_TTL_SECS: u64 = 12 * 3600;

#[derive(Serialize, Deserialize)]
struct CachedCpe {
    fetched_at: u64,
    doc: serde_json::Value,
}

/// `cpe:2.3:a:vendor:product` and nothing else. The name comes from downloaded data and is put
/// into a URL and a file name, so it is checked rather than trusted.
fn valid_cpe(cpe: &str) -> bool {
    cpe.starts_with("cpe:2.3:a:")
        && cpe.split(':').count() == 5
        && cpe.chars().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | '-' | ':')
        })
}

fn valid_version(v: &str) -> bool {
    !v.is_empty() && v.len() <= 40 && v.chars().all(|c| c.is_ascii_digit() || c == '.')
}

fn cpe_cache_path(store: &Store, cpe: &str, version: &str) -> std::path::PathBuf {
    store
        .nvd_dir()
        .join(format!("cpe-{}-{version}.json", cpe.replace(':', "_")))
}

/// The cached NVD answer for `cpe` at `version`, if there is one (`fresh_only` ignores old ones).
pub fn cached_cpe(
    store: &Store,
    cpe: &str,
    version: &str,
    fresh_only: bool,
) -> Option<serde_json::Value> {
    if !valid_cpe(cpe) || !valid_version(version) {
        return None;
    }
    let c: CachedCpe =
        serde_json::from_str(&fs::read_to_string(cpe_cache_path(store, cpe, version)).ok()?)
            .ok()?;
    if fresh_only && now_secs().saturating_sub(c.fetched_at) > CPE_TTL_SECS {
        return None;
    }
    Some(c.doc)
}

/// Asks NVD which CVEs apply to `cpe` (`cpe:2.3:a:php:php`) at `version`, and caches the answer.
/// One response carries up to 2000 CVEs; the caller sees `totalResults` to tell if there were more.
pub fn fetch_cpe(
    store: &Store,
    cpe: &str,
    version: &str,
    api_key: Option<&str>,
) -> Result<serde_json::Value, DbError> {
    if !valid_cpe(cpe) {
        return Err(DbError(format!("not a CPE product name: {cpe:?}")));
    }
    if !valid_version(version) {
        return Err(DbError(format!("not a plain dotted version: {version:?}")));
    }
    wait_for_rate_limit(api_key.is_some(), store.endpoints().nvd_gap_ms);
    let url = format!(
        "{}?cpeName={cpe}:{version}:*:*:*:*:*:*:*&isVulnerable&resultsPerPage=2000",
        store.endpoints().nvd
    );
    let headers: Vec<(&str, &str)> = api_key.map(|k| vec![("apiKey", k)]).unwrap_or_default();
    let bytes = net::get_bytes_with_headers(&url, &headers, 32 * 1024 * 1024)?;
    let doc: serde_json::Value = serde_json::from_slice(&bytes)?;
    if doc.get("vulnerabilities").is_none() {
        return Err(DbError(
            "NVD answered without a `vulnerabilities` list".into(),
        ));
    }
    let cached = CachedCpe {
        fetched_at: now_secs(),
        doc: doc.clone(),
    };
    store.write_atomic(
        &cpe_cache_path(store, cpe, version),
        serde_json::to_string(&cached)?.as_bytes(),
    )?;
    Ok(doc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const PHP: &str = "cpe:2.3:a:php:php";
    const URL: &str =
        "/nvd?cpeName=cpe:2.3:a:php:php:8.4.26:*:*:*:*:*:*:*&isVulnerable&resultsPerPage=2000";

    fn mock_store(dir: &std::path::Path, server: &crate::testutil::MockServer) -> Store {
        Store::at(dir).with_endpoints(crate::Endpoints {
            nvd: format!("{}/nvd", server.base),
            nvd_gap_ms: Some(0),
            ..crate::Endpoints::default()
        })
    }

    #[test]
    fn a_cpe_lookup_is_fetched_once_then_served_from_the_cache() {
        use crate::testutil::{MockServer, Route};
        let dir = tempfile::tempdir().expect("tmp");
        let server = MockServer::start(vec![Route::get(
            URL,
            r#"{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2026-109618"}}]}"#,
        )]);
        let store = mock_store(dir.path(), &server);
        assert!(cached_cpe(&store, PHP, "8.4.26", true).is_none());
        let doc = fetch_cpe(&store, PHP, "8.4.26", None).expect("fetches");
        assert_eq!(doc["totalResults"], 1);
        assert_eq!(
            cached_cpe(&store, PHP, "8.4.26", true).expect("cached"),
            doc
        );
        assert_eq!(server.requests().len(), 1);
        assert!(
            cached_cpe(&store, PHP, "8.4.27", true).is_none(),
            "per version"
        );
    }

    #[test]
    fn a_stale_cpe_answer_is_not_fresh_but_is_still_readable() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = Store::at(dir.path());
        fs::create_dir_all(store.nvd_dir()).expect("mkdir");
        let old = CachedCpe {
            fetched_at: 1,
            doc: json!({"vulnerabilities":[]}),
        };
        fs::write(
            cpe_cache_path(&store, PHP, "1.0"),
            serde_json::to_string(&old).expect("j"),
        )
        .expect("w");
        assert!(cached_cpe(&store, PHP, "1.0", true).is_none());
        assert!(cached_cpe(&store, PHP, "1.0", false).is_some());
    }

    #[test]
    fn names_from_downloaded_data_are_checked_before_they_reach_a_url_or_a_path() {
        use crate::testutil::MockServer;
        let dir = tempfile::tempdir().expect("tmp");
        let server = MockServer::start(vec![]);
        let store = mock_store(dir.path(), &server);
        for bad in [
            "cpe:/a:php:php",
            "cpe:2.3:a:php:php:8.4",
            "cpe:2.3:a:php:php&x=1",
            "cpe:2.3:a:ph p:php",
            "cpe:2.3:a:../../x:y",
            "cpe:2.3:o:linux:kernel",
            "",
        ] {
            assert!(fetch_cpe(&store, bad, "1.0", None).is_err(), "{bad}");
        }
        for bad in ["", "1.0;x", "1.0 2", "../1", "8.4.26-1"] {
            assert!(fetch_cpe(&store, PHP, bad, None).is_err(), "{bad}");
        }
        assert!(
            server.requests().is_empty(),
            "nothing was sent for a bad name"
        );
    }

    #[test]
    fn cve_id_shapes() {
        assert!(is_cve_id("CVE-2021-44228"));
        assert!(is_cve_id("CVE-2026-102764"));
        for bad in [
            "CVE-21-1",
            "GHSA-1",
            "CVE-2021-12",
            "CVE-2021-1234-5",
            "../CVE-2021-1234",
            "",
        ] {
            assert!(!is_cve_id(bad), "{bad}");
        }
    }

    #[test]
    fn parses_scores_and_weaknesses() {
        let v = json!({"vulnerabilities":[{"cve":{
            "metrics":{"cvssMetricV31":[
                {"type":"Secondary","cvssData":{"baseScore":8.0}},
                {"type":"Primary","cvssData":{"baseScore":10.0}}]},
            "weaknesses":[{"description":[{"value":"CWE-20"},{"value":"NVD-CWE-Other"}]},
                          {"description":[{"value":"CWE-20"},{"value":"CWE-502"}]}]}}]});
        let i = parse_response(&v);
        assert_eq!(i.cvss, Some(10.0));
        assert_eq!(i.cwes, vec!["CWE-20", "CWE-502"]);
        let v4 = json!({"vulnerabilities":[{"cve":{"metrics":{"cvssMetricV40":[{"type":"Primary","cvssData":{"baseScore":9.3}}]}}}]});
        assert_eq!(parse_response(&v4).cvss, Some(9.3));
        assert_eq!(parse_response(&json!({})), NvdInfo::default());
    }

    #[test]
    fn cache_respects_ttl() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = Store::at(dir.path());
        assert!(cached(&store, "CVE-2021-44228", false).is_none());
        fs::create_dir_all(store.nvd_dir()).expect("mkdir");
        let fresh = Cached {
            fetched_at: now_secs(),
            info: NvdInfo {
                cvss: Some(9.0),
                cwes: vec![],
            },
        };
        fs::write(
            cache_path(&store, "CVE-2021-44228"),
            serde_json::to_string(&fresh).expect("j"),
        )
        .expect("w");
        assert_eq!(
            cached(&store, "CVE-2021-44228", true).expect("fresh").cvss,
            Some(9.0)
        );
        let old = Cached {
            fetched_at: 1,
            info: NvdInfo::default(),
        };
        fs::write(
            cache_path(&store, "CVE-2021-44229"),
            serde_json::to_string(&old).expect("j"),
        )
        .expect("w");
        assert!(cached(&store, "CVE-2021-44229", true).is_none());
        assert!(cached(&store, "CVE-2021-44229", false).is_some());
        assert!(cached(&store, "not-a-cve", false).is_none());
    }
}
