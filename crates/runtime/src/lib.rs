//! Runtime products: which of PHP, nginx, Node.js, a database, ... are installed, and whether
//! their release line is still supported and on its newest patch.
//!
//! Lockfiles only describe a project's libraries; the interpreter and the servers underneath it
//! are not in any lockfile, so a flaw in them (a PHP core bug, say) is invisible to a dependency
//! scan. This crate is the answer for those: it looks at versions and at the public release and
//! end-of-life data, and it never claims more than that. It does not know which CVEs affect a
//! version; it knows whether upstream still fixes that release line and how far behind it is.
//!
//! The crate does no networking. `opencraysec-db` downloads the feeds; the engine joins the two.

pub mod cve;
pub mod detect;
pub mod evaluate;
pub mod lifecycle;

pub use cve::{NvdOutcome, RuntimeCve, parse_cpe_response, rank, score_and_cwes};
pub use detect::{DETECTORS, Detector, detect_all, extract_version, parse_given, run_version};
pub use evaluate::{Input, ProductResult, Status, compare, evaluate, segments};
pub use lifecycle::{Lifecycle, Product, Release, VendorLatest, parse_endoflife, parse_php_active};

use serde::Serialize;

/// Age of the data a runtime scan used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DataInfo {
    /// When the end-of-life dataset was downloaded; `None` when there is none.
    pub lifecycle_updated_at: Option<String>,
    /// When each vendor feed was downloaded (`php`: time).
    pub vendor_updated_at: Vec<(String, String)>,
}

/// The result of a runtime scan.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RuntimeReport {
    /// RFC 3339 UTC time of the scan.
    pub scanned_at: String,
    /// What the verdicts were based on.
    pub data: DataInfo,
    /// One verdict per product found or given.
    pub results: Vec<ProductResult>,
    /// What was and was not checked, and what the verdicts cannot tell.
    pub notes: Vec<String>,
}
