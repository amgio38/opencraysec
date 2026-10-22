//! Runtime scan: find the installed interpreters, servers and databases (or take versions the
//! caller gives) and judge them against the stored release and end-of-life data.
//!
//! This is the check that lockfiles cannot do: PHP itself, nginx or Node.js are not in any
//! lockfile, so a dependency scan never sees them. It reads local data only; `update` is what
//! downloads it.

use std::collections::HashSet;

use opencraysec_db::{Store, now_rfc3339};
use opencraysec_runtime::{
    DETECTORS, DataInfo, Input, NvdOutcome, RuntimeReport, detect_all, evaluate,
    parse_cpe_response, parse_given, rank,
};

use crate::EngineError;

/// What to check.
#[derive(Debug, Clone, Default)]
pub struct RuntimeOptions {
    /// `product@version` entries (`php@8.2.30`). When empty, the installed products are detected
    /// instead. Given versions are the way to check a machine or container you are not on.
    pub products: Vec<String>,
    /// Also ask NVD which CVEs apply to each product at its version. Needs the network (answers
    /// are cached for 12 hours) and is slow without `NVD_API_KEY`: NVD allows 5 requests per 30 s.
    pub nvd: bool,
}

/// Products asked of NVD in one scan; answers already cached do not count.
const MAX_NVD_LOOKUPS: usize = 10;

/// Judges runtime products. Never uses the network.
pub fn scan_runtime(store: &Store, opts: &RuntimeOptions) -> Result<RuntimeReport, EngineError> {
    let scanned_at = now_rfc3339();
    let today = scanned_at.get(..10).unwrap_or("0000-00-00").to_string();
    let (lifecycle, vendor) = store.runtime_data();

    let mut notes = Vec::new();
    let inputs: Vec<Input> = if opts.products.is_empty() {
        let (found, installed) = detect_all();
        notes.push(format!(
            "Looked for {} known programs on PATH and found {installed}. Products that are not on PATH, or that run in a container or on another machine, were not checked; give them as product@version.",
            DETECTORS.len()
        ));
        if found.is_empty() {
            notes.push("No known runtime product was found, so nothing was judged.".into());
        }
        found
    } else {
        opts.products
            .iter()
            .map(|p| parse_given(p))
            .collect::<Result<_, _>>()
            .map_err(EngineError)?
    };

    if lifecycle.is_none() {
        notes.push(
            "No end-of-life data is stored, so every verdict is `unknown`. Run `opencraysec update` while online."
                .into(),
        );
    }
    notes.push(if opts.nvd {
        "`eol` means upstream no longer fixes the release line and `outdated` means a newer patch release exists; the CVEs listed are NVD's. OS packages often backport fixes without changing the upstream version number, so confirm with your OS vendor's tracker; `current` says nothing about flaws published after the data was downloaded."
    } else {
        "These verdicts are about release lines, not CVEs: `eol` means upstream no longer fixes the line, `outdated` means a newer patch release exists. Add --nvd to list the CVEs NVD records for each version. OS packages often backport fixes without changing the upstream version number, so confirm with your OS vendor's tracker; `current` says nothing about flaws published after the data was downloaded."
    }
    .into());

    let mut results = evaluate(lifecycle.as_ref(), &vendor, &inputs, &today);
    if opts.nvd {
        ask_nvd(store, lifecycle.as_ref(), &mut results, &mut notes);
    }
    Ok(RuntimeReport {
        scanned_at,
        data: DataInfo {
            lifecycle_updated_at: lifecycle.map(|l| l.updated_at),
            vendor_updated_at: vendor
                .into_iter()
                .map(|v| (v.product, v.updated_at))
                .collect(),
        },
        results,
        notes,
    })
}

/// Fills in `nvd` for every result: the CVEs NVD lists for the product at that version, ranked with
/// the local CISA KEV and EPSS data. A product NVD cannot be asked about says why.
fn ask_nvd(
    store: &Store,
    lifecycle: Option<&opencraysec_runtime::Lifecycle>,
    results: &mut [opencraysec_runtime::ProductResult],
    notes: &mut Vec<String>,
) {
    let key = std::env::var("NVD_API_KEY").ok().filter(|k| !k.is_empty());
    let kev = store.kev();
    let (mut fetched, mut deferred) = (0usize, 0usize);
    for r in results.iter_mut() {
        let cpe = lifecycle
            .and_then(|l| l.find(&r.product))
            .and_then(|p| p.cpe.first())
            .cloned();
        let Some(cpe) = cpe else {
            r.nvd = Some(NvdOutcome::failed(
                "no CPE name is known for this product (run `opencraysec update` to refresh the release data)",
            ));
            continue;
        };
        let doc = match opencraysec_db::nvd::cached_cpe(store, &cpe, &r.version, true) {
            Some(d) => Ok(d),
            None if fetched >= MAX_NVD_LOOKUPS => {
                deferred += 1;
                r.nvd = Some(NvdOutcome::failed(format!(
                    "not asked: at most {MAX_NVD_LOOKUPS} NVD lookups per scan; run it again, answers already fetched are cached"
                )));
                continue;
            }
            None => {
                fetched += 1;
                opencraysec_db::nvd::fetch_cpe(store, &cpe, &r.version, key.as_deref())
            }
        };
        r.nvd = Some(match doc {
            Ok(d) => {
                let mut out = parse_cpe_response(&d, &cpe, &r.version);
                let ids: HashSet<String> = out.cves.iter().map(|c| c.id.clone()).collect();
                let epss = store.epss(&ids);
                for c in &mut out.cves {
                    c.known_exploited = kev.contains(&c.id);
                    c.epss = epss.get(&c.id).copied();
                }
                rank(&mut out.cves);
                out
            }
            Err(e) => NvdOutcome::failed(format!("NVD lookup failed: {e}")),
        });
    }
    if deferred > 0 {
        notes.push(format!(
            "NVD: {deferred} product(s) were not looked up (limit {MAX_NVD_LOOKUPS} per scan)."
        ));
    }
    notes.push(
        "NVD lists a CVE for a version when its configuration says so; entries that name every version of a product are counted but not shown. NVD can lag behind a disclosure and its ranges can be wrong.".into(),
    );
}
