//! Release and end-of-life data for runtime products: downloaded by `update`, read by
//! `scan-runtime` without the network.
//!
//! Two feeds: endoflife.date (every product, one file) and php.net (the newest PHP patch
//! releases, which appear there before the aggregator has them). The aggregator is required; the
//! vendor feed is a bonus, so its failure is reported but does not fail the update.

use std::fs;
use std::path::PathBuf;

use opencraysec_runtime::{Lifecycle, VendorLatest, parse_endoflife, parse_php_active};

use crate::{DbError, Store, net, now_rfc3339};

/// What an update stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeUpdate {
    /// Products in the end-of-life dataset.
    pub products: usize,
    /// PHP release lines stored from php.net, or `None` when that feed failed.
    pub php_lines: Option<usize>,
    /// Why the php.net feed failed, if it did.
    pub php_error: Option<String>,
}

/// Largest feed accepted (bytes); the endoflife.date document is about 3 MB.
const MAX_FEED: u64 = 64 * 1024 * 1024;

impl Store {
    pub(crate) fn runtime_dir(&self) -> PathBuf {
        self.dir().join("runtime")
    }

    pub(crate) fn runtime_lifecycle_path(&self) -> PathBuf {
        self.runtime_dir().join("endoflife.json")
    }

    fn runtime_vendor_path(&self, product: &str) -> PathBuf {
        self.runtime_dir().join(format!("vendor-{product}.json"))
    }

    /// The stored end-of-life dataset and vendor feeds. Missing or unreadable files give `None`
    /// and an empty list, so a scan can say "no data" instead of failing.
    pub fn runtime_data(&self) -> (Option<Lifecycle>, Vec<VendorLatest>) {
        let lifecycle = fs::read_to_string(self.runtime_lifecycle_path())
            .ok()
            .and_then(|t| serde_json::from_str::<Lifecycle>(&t).ok());
        let vendor = ["php"]
            .into_iter()
            .filter_map(|p| {
                fs::read_to_string(self.runtime_vendor_path(p))
                    .ok()
                    .and_then(|t| serde_json::from_str::<VendorLatest>(&t).ok())
            })
            .collect();
        (lifecycle, vendor)
    }
}

/// Downloads both feeds and stores them.
pub fn update_runtime(store: &Store) -> Result<RuntimeUpdate, DbError> {
    let bytes = net::get_bytes(&store.endpoints().eol, MAX_FEED)?;
    let lifecycle = parse_endoflife(&bytes, now_rfc3339()).map_err(DbError)?;
    store.write_atomic(
        &store.runtime_lifecycle_path(),
        serde_json::to_string(&lifecycle)?.as_bytes(),
    )?;

    let vendor = net::get_bytes(&store.endpoints().php_releases, MAX_FEED)
        .map_err(|e| e.0)
        .and_then(|b| parse_php_active(&b, now_rfc3339()));
    let (php_lines, php_error) = match vendor {
        Ok(v) => {
            store.write_atomic(
                &store.runtime_vendor_path("php"),
                serde_json::to_string(&v)?.as_bytes(),
            )?;
            (Some(v.latest.len()), None)
        }
        Err(e) => (None, Some(e)),
    };
    Ok(RuntimeUpdate {
        products: lifecycle.products.len(),
        php_lines,
        php_error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Endpoints;
    use crate::testutil::{MockServer, Route};

    const EOL: &str = r#"{"result":[{"name":"php","releases":[
        {"name":"7.4","eolFrom":"2022-11-28","isEol":true,"latest":{"name":"7.4.33"}}]}]}"#;
    const PHP: &str = r#"{"8":{"8.4":{"version":"8.4.27"}}}"#;

    fn store(dir: &std::path::Path, server: &MockServer) -> Store {
        Store::at(dir).with_endpoints(Endpoints {
            eol: format!("{}/eol", server.base),
            php_releases: format!("{}/php", server.base),
            ..Endpoints::default()
        })
    }

    #[test]
    fn update_stores_both_feeds_and_scans_can_read_them_back() {
        let dir = tempfile::tempdir().expect("tmp");
        let server = MockServer::start(vec![Route::get("/eol", EOL), Route::get("/php", PHP)]);
        let s = store(dir.path(), &server);
        assert_eq!(
            s.runtime_data(),
            (None, vec![]),
            "nothing before the first update"
        );
        let u = update_runtime(&s).expect("updates");
        assert_eq!((u.products, u.php_lines, u.php_error), (1, Some(1), None));
        let (life, vendor) = s.runtime_data();
        assert_eq!(life.expect("lifecycle").products[0].name, "php");
        assert_eq!(
            vendor[0].latest.get("8.4").map(String::as_str),
            Some("8.4.27")
        );
        assert!(s.status().runtime_updated_at.is_some());
    }

    #[test]
    fn a_failing_vendor_feed_does_not_fail_the_update() {
        let dir = tempfile::tempdir().expect("tmp");
        let server = MockServer::start(vec![Route::get("/eol", EOL)]);
        let u = update_runtime(&store(dir.path(), &server)).expect("still updates");
        assert_eq!(u.products, 1);
        assert!(u.php_lines.is_none() && u.php_error.is_some());
    }

    #[test]
    fn a_bad_aggregator_feed_fails_and_leaves_old_data_alone() {
        let dir = tempfile::tempdir().expect("tmp");
        let good = MockServer::start(vec![Route::get("/eol", EOL), Route::get("/php", PHP)]);
        update_runtime(&store(dir.path(), &good)).expect("first update");
        let bad = MockServer::start(vec![Route::get("/eol", r#"{"result":[]}"#)]);
        assert!(update_runtime(&store(dir.path(), &bad)).is_err());
        assert_eq!(
            store(dir.path(), &bad)
                .runtime_data()
                .0
                .expect("kept")
                .products
                .len(),
            1
        );
    }
}
