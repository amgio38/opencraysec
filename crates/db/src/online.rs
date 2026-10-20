//! Online fallback: ask api.osv.dev about specific package versions. Only package names and
//! versions are sent, never source code.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::sync::Mutex;

use opencraysec_core::osv::OsvRecord;
use opencraysec_core::{Ecosystem, Package};

use crate::{DbError, Store, net};

const BATCH: usize = 500;
const WORKERS: usize = 8;
const RESPONSE_LIMIT: u64 = 64 * 1024 * 1024;

/// An advisory the OSV API says affects a package.
#[derive(Debug, Clone)]
pub struct OnlineHit {
    /// Index into the package slice passed to [`query`].
    pub package_index: usize,
    /// The full advisory record.
    pub record: OsvRecord,
}

fn query_name(p: &Package) -> String {
    p.ecosystem.normalize_name(&p.name)
}

/// Builds the request body for `querybatch`.
pub fn batch_body(pkgs: &[&Package], tokens: &[Option<String>]) -> serde_json::Value {
    let queries: Vec<_> = pkgs
        .iter()
        .zip(tokens)
        .map(|(p, t)| {
            let mut q = serde_json::json!({
                "package": { "name": query_name(p), "ecosystem": p.ecosystem.osv_name() },
                "version": p.version,
            });
            if let Some(t) = t {
                q["page_token"] = serde_json::Value::String(t.clone());
            }
            q
        })
        .collect();
    serde_json::json!({ "queries": queries })
}

fn fetch_record(store: &Store, id: &str, modified: Option<&str>) -> Result<OsvRecord, DbError> {
    let safe: String = id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || "-_.".contains(*c))
        .collect();
    let path = store.online_cache_dir().join(format!("{safe}.json"));
    if let Ok(text) = fs::read_to_string(&path)
        && let Ok(rec) = serde_json::from_str::<OsvRecord>(&text)
        && (modified.is_none() || rec.modified.as_deref() == modified)
    {
        return Ok(rec);
    }
    let bytes = net::get_bytes(
        &format!("{}/vulns/{safe}", store.endpoints().osv_api),
        RESPONSE_LIMIT,
    )?;
    let rec: OsvRecord = serde_json::from_slice(&bytes)?;
    store.write_atomic(&path, serde_json::to_string(&rec)?.as_bytes())?;
    Ok(rec)
}

/// Asks the OSV API which advisories affect each package. Results are cached per advisory id.
pub fn query(store: &Store, pkgs: &[Package]) -> Result<Vec<OnlineHit>, DbError> {
    // advisory id -> (modified, package indices)
    let mut found: BTreeMap<String, (Option<String>, BTreeSet<usize>)> = BTreeMap::new();
    let indices: Vec<usize> = (0..pkgs.len()).collect();
    for chunk in indices.chunks(BATCH) {
        let mut pending: Vec<(usize, Option<String>)> = chunk.iter().map(|i| (*i, None)).collect();
        while !pending.is_empty() {
            let refs: Vec<&Package> = pending.iter().map(|(i, _)| &pkgs[*i]).collect();
            let tokens: Vec<Option<String>> = pending.iter().map(|(_, t)| t.clone()).collect();
            let resp = net::post_json(
                &format!("{}/querybatch", store.endpoints().osv_api),
                &batch_body(&refs, &tokens),
                RESPONSE_LIMIT,
            )?;
            let v: serde_json::Value = serde_json::from_slice(&resp)?;
            let results = v
                .get("results")
                .and_then(|x| x.as_array())
                .ok_or_else(|| DbError("OSV querybatch: no `results`".into()))?;
            let mut next = Vec::new();
            for ((idx, _), r) in pending.iter().zip(results) {
                for vuln in r
                    .get("vulns")
                    .and_then(|x| x.as_array())
                    .into_iter()
                    .flatten()
                {
                    if let Some(id) = vuln.get("id").and_then(|x| x.as_str()) {
                        let modified = vuln
                            .get("modified")
                            .and_then(|x| x.as_str())
                            .map(str::to_string);
                        let e = found
                            .entry(id.to_string())
                            .or_insert((modified, BTreeSet::new()));
                        e.1.insert(*idx);
                    }
                }
                if let Some(t) = r.get("next_page_token").and_then(|x| x.as_str()) {
                    next.push((*idx, Some(t.to_string())));
                }
            }
            pending = next;
        }
    }
    let ids: Vec<(String, Option<String>)> = found
        .iter()
        .map(|(k, (m, _))| (k.clone(), m.clone()))
        .collect();
    let records: Mutex<BTreeMap<String, OsvRecord>> = Mutex::new(BTreeMap::new());
    let errors: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let cursor = Mutex::new(0usize);
    std::thread::scope(|s| {
        for _ in 0..WORKERS.min(ids.len().max(1)) {
            s.spawn(|| {
                loop {
                    let i = {
                        let Ok(mut c) = cursor.lock() else { return };
                        let i = *c;
                        *c += 1;
                        i
                    };
                    let Some((id, modified)) = ids.get(i) else {
                        return;
                    };
                    match fetch_record(store, id, modified.as_deref()) {
                        Ok(r) => {
                            if let Ok(mut m) = records.lock() {
                                m.insert(id.clone(), r);
                            }
                        }
                        Err(e) => {
                            if let Ok(mut m) = errors.lock() {
                                m.push(format!("{id}: {e}"));
                            }
                        }
                    }
                }
            });
        }
    });
    if let Ok(errs) = errors.lock()
        && let Some(first) = errs.first()
    {
        return Err(DbError(format!(
            "{} advisory fetches failed, first: {first}",
            errs.len()
        )));
    }
    let records = records
        .into_inner()
        .map_err(|_| DbError("poisoned lock".into()))?;
    let mut hits = Vec::new();
    for (id, (_, idxs)) in found {
        if let Some(rec) = records.get(&id) {
            for i in idxs {
                hits.push(OnlineHit {
                    package_index: i,
                    record: rec.clone(),
                });
            }
        }
    }
    Ok(hits)
}

/// Ecosystems with at least one package, in a stable order.
pub fn ecosystems_of(pkgs: &[Package]) -> Vec<Ecosystem> {
    let set: BTreeSet<Ecosystem> = pkgs.iter().map(|p| p.ecosystem).collect();
    set.into_iter().collect()
}

/// Fetches one advisory by id (`GHSA-...`, `CVE-...`, `RUSTSEC-...`) from api.osv.dev, using the
/// on-disk cache when present.
pub fn fetch_by_id(store: &Store, id: &str) -> Result<OsvRecord, DbError> {
    fetch_record(store, id, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_shape() {
        let p = Package {
            ecosystem: Ecosystem::PyPI,
            name: "Django_X".into(),
            version: "3.0".into(),
            source: "r".into(),
            dev: false,
        };
        let b = batch_body(&[&p], &[Some("tok".into())]);
        assert_eq!(b["queries"][0]["package"]["name"], "django-x");
        assert_eq!(b["queries"][0]["package"]["ecosystem"], "PyPI");
        assert_eq!(b["queries"][0]["page_token"], "tok");
        let b = batch_body(&[&p], &[None]);
        assert!(b["queries"][0].get("page_token").is_none());
    }
}
