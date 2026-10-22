//! Runtime scan: find the installed interpreters, servers and databases (or take versions the
//! caller gives) and judge them against the stored release and end-of-life data.
//!
//! This is the check that lockfiles cannot do: PHP itself, nginx or Node.js are not in any
//! lockfile, so a dependency scan never sees them. It reads local data only; `update` is what
//! downloads it.

use opencraysec_db::{Store, now_rfc3339};
use opencraysec_runtime::{
    DETECTORS, DataInfo, Input, RuntimeReport, detect_all, evaluate, parse_given,
};

use crate::EngineError;

/// What to check.
#[derive(Debug, Clone, Default)]
pub struct RuntimeOptions {
    /// `product@version` entries (`php@8.2.30`). When empty, the installed products are detected
    /// instead. Given versions are the way to check a machine or container you are not on.
    pub products: Vec<String>,
}

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
    notes.push(
        "This checks release lines, not CVEs: `eol` means upstream no longer fixes the line, `outdated` means a newer patch release exists. OS packages often backport fixes without changing the upstream version number, so confirm with your OS vendor's tracker; `current` says nothing about flaws published after the data was downloaded."
            .into(),
    );

    let results = evaluate(lifecycle.as_ref(), &vendor, &inputs, &today);
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
