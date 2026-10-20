//! Dependency scan: lockfiles in, ranked findings out.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::Path;

use opencraysec_core::osv::OsvRecord;
use opencraysec_core::{Ecosystem, Finding, Package, Severity};
use opencraysec_db::{Store, online};
use serde::Serialize;

use crate::{EngineError, reach};

/// Options for [`scan`].
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Limit to these ecosystems (all found when `None`).
    pub ecosystems: Option<Vec<Ecosystem>>,
    /// Include development-only dependencies.
    pub include_dev: bool,
    /// Never touch the network; ecosystems without local data are reported as unscanned.
    pub offline: bool,
    /// Drop findings below this severity.
    pub min_severity: Severity,
    /// Check whether the project's own source uses each vulnerable package.
    pub reachability: bool,
    /// Ask NVD for the score of findings that have none (network; cached; rate limited).
    pub enrich_nvd: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions {
            ecosystems: None,
            include_dev: true,
            offline: false,
            min_severity: Severity::Unknown,
            reachability: true,
            enrich_nvd: false,
        }
    }
}

/// Where the advisories for one ecosystem came from.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DataSource {
    /// OSV ecosystem name.
    pub ecosystem: String,
    /// `local` (downloaded dump), `online` (api.osv.dev) or `none`.
    pub mode: String,
    /// When the local dump was last updated.
    pub updated_at: Option<String>,
    /// Packages checked against this source.
    pub packages: usize,
}

/// Everything a scan found and everything it did not check.
#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    /// Scanned path.
    pub root: String,
    /// Scan time (UTC, RFC 3339).
    pub scanned_at: String,
    /// Lockfiles that were read.
    pub lockfiles: Vec<String>,
    /// Lockfiles that could not be read, with the reason.
    pub skipped: Vec<(String, String)>,
    /// Lockfiles that were read but contain dependencies that could not be checked.
    pub unchecked: Vec<(String, String)>,
    /// Number of packages checked.
    pub packages_checked: usize,
    /// Advisory source used per ecosystem.
    pub data_sources: Vec<DataSource>,
    /// Caveats the reader must not miss (unscanned ecosystems, missing enrichment).
    pub notes: Vec<String>,
    /// RustSec-style notices that are not vulnerabilities (unmaintained crates and similar).
    pub informational_omitted: usize,
    /// Findings, most urgent first.
    pub findings: Vec<Finding>,
    /// Every package checked (used for SBOM output, not serialised in JSON).
    #[serde(skip)]
    pub packages: Vec<Package>,
    /// Every dependency found under the scanned path, whatever the options (not serialised).
    #[serde(skip)]
    pub all_packages: Vec<Package>,
}

impl ScanReport {
    /// True when something that should have been checked was not, so "no findings" is not a clean
    /// result. This is the one definition the report text and `verify_fix` use. It contains
    /// [`ScanReport::unscanned`]: every case that fails a CI gate is also incomplete, and in
    /// addition any requirement line the scan could not match makes the result incomplete.
    pub fn is_incomplete(&self) -> bool {
        self.unscanned() || !self.unchecked.is_empty()
    }

    /// True when a CI gate must not pass: nothing was checked, or a whole part of the project got
    /// no verdict.
    ///
    /// - no lockfile was found;
    /// - a lockfile could not be read;
    /// - an ecosystem has packages but no advisory data;
    /// - the only dependencies found were requirement lines the scan cannot match.
    ///
    /// Some unmatched requirement lines next to dependencies that *were* checked do not fail a
    /// gate (a project with one `flask>=2` line would then never pass); they are listed in the
    /// report and make it incomplete.
    pub fn unscanned(&self) -> bool {
        self.lockfiles.is_empty()
            || !self.skipped.is_empty()
            || self.data_sources.iter().any(|d| d.mode == "none")
            || (self.packages_checked == 0 && !self.unchecked.is_empty())
    }
}

const SUMMARY_MAX: usize = 200;
const MAX_REFS: usize = 5;

fn summary_of(rec: &OsvRecord) -> String {
    let text = rec
        .summary
        .clone()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            rec.details
                .as_deref()
                .and_then(|d| d.lines().find(|l| !l.trim().is_empty()))
                .map(str::to_string)
        })
        .unwrap_or_default();
    text.chars().take(SUMMARY_MAX).collect()
}

fn build_finding(rec: &OsvRecord, pkg: &Package, fixed_in: Vec<String>) -> Finding {
    let eco = pkg.ecosystem;
    Finding {
        id: rec.id.clone(),
        aliases: rec.aliases.clone(),
        package: pkg.clone(),
        summary: summary_of(rec),
        severity: rec.severity_bucket(),
        cvss: rec.cvss_score(),
        cwes: rec.cwes(),
        known_exploited: false,
        epss: None,
        fixed_in,
        references: rec
            .references
            .iter()
            .map(|r| r.url.clone())
            .filter(|u| !u.is_empty())
            .take(MAX_REFS)
            .collect(),
        reachability: None,
        symbol_refs: rec.symbol_refs(eco, &eco.normalize_name(&pkg.name)),
    }
}

/// Merges findings for the same package that share an id or alias (GHSA + RUSTSEC + CVE).
fn merge_same_issue(findings: Vec<Finding>) -> Vec<Finding> {
    let mut by_pkg: BTreeMap<(Ecosystem, String, String), Vec<Finding>> = BTreeMap::new();
    for f in findings {
        let key = (
            f.package.ecosystem,
            f.package.name.clone(),
            f.package.version.clone(),
        );
        by_pkg.entry(key).or_default().push(f);
    }
    let mut out = Vec::new();
    for (_, group) in by_pkg {
        let mut merged: Vec<(HashSet<String>, Finding)> = Vec::new();
        for f in group {
            let ids: HashSet<String> = std::iter::once(f.id.clone())
                .chain(f.aliases.iter().cloned())
                .collect();
            if let Some((set, existing)) = merged.iter_mut().find(|(s, _)| !s.is_disjoint(&ids)) {
                set.extend(ids);
                absorb(existing, f);
            } else {
                merged.push((ids, f));
            }
        }
        out.extend(merged.into_iter().map(|(_, f)| f));
    }
    out
}

fn absorb(into: &mut Finding, other: Finding) {
    let (mut keep, drop) = if other.rank_key() > into.rank_key() {
        (other, into.clone())
    } else {
        (into.clone(), other)
    };
    let mut aliases: BTreeSet<String> = keep.aliases.iter().cloned().collect();
    aliases.extend(drop.aliases);
    aliases.insert(drop.id);
    aliases.remove(&keep.id);
    keep.aliases = aliases.into_iter().collect();
    for c in drop.cwes {
        if !keep.cwes.contains(&c) {
            keep.cwes.push(c);
        }
    }
    // Sources can disagree about the fix (RustSec marks 0.2.0 safe, GHSA says 0.2.23). Keep the
    // list whose lowest fix is highest: that is the version every source agrees is safe.
    let eco = keep.package.ecosystem;
    let stricter = match (keep.fixed_in.first(), drop.fixed_in.first()) {
        (None, Some(_)) => true,
        (Some(a), Some(b)) => opencraysec_core::version::compare(eco, b, a).is_gt(),
        _ => false,
    };
    if stricter {
        keep.fixed_in = drop.fixed_in;
    }
    keep.fixed_in
        .sort_by(|a, b| opencraysec_core::version::compare(eco, a, b));
    for r in drop.symbol_refs {
        if !keep.symbol_refs.contains(&r) {
            keep.symbol_refs.push(r);
        }
    }
    if keep.summary.is_empty() {
        keep.summary = drop.summary;
    }
    *into = keep;
}

/// Most NVD requests one scan may make; the rest are reported, not silently dropped.
const MAX_NVD_FETCHES: usize = 15;

fn cve_of(f: &Finding) -> Option<String> {
    std::iter::once(&f.id)
        .chain(f.aliases.iter())
        .find(|i| opencraysec_db::nvd::is_cve_id(i))
        .cloned()
}

/// Fills in missing CVSS scores and CWEs from NVD: always from the cache, from the network only
/// when `opts.enrich_nvd` is set and the scan is not offline.
fn enrich_from_nvd(
    store: &Store,
    findings: &mut [Finding],
    opts: &ScanOptions,
    notes: &mut Vec<String>,
) {
    let key = std::env::var("NVD_API_KEY").ok().filter(|k| !k.is_empty());
    let (mut fetched, mut deferred, mut failed) = (0usize, 0usize, 0usize);
    let mut still_unscored = 0usize;
    for f in findings.iter_mut().filter(|f| f.cvss.is_none()) {
        let Some(cve) = cve_of(f) else { continue };
        let mut info = opencraysec_db::nvd::cached(store, &cve, true);
        if info.is_none() && opts.enrich_nvd && !opts.offline {
            if fetched >= MAX_NVD_FETCHES {
                deferred += 1;
            } else {
                fetched += 1;
                match opencraysec_db::nvd::fetch(store, &cve, key.as_deref()) {
                    Ok(i) => info = Some(i),
                    Err(_) => failed += 1,
                }
            }
        }
        match info {
            Some(i) => {
                if let Some(score) = i.cvss {
                    f.cvss = Some(score);
                    f.severity = Severity::from_score(score);
                }
                for c in i.cwes {
                    if !f.cwes.contains(&c) {
                        f.cwes.push(c);
                    }
                }
            }
            None => still_unscored += 1,
        }
    }
    if deferred > 0 {
        notes.push(format!("NVD: {deferred} unscored finding(s) were not looked up (limit {MAX_NVD_FETCHES} per scan); run the scan again to continue."));
    }
    if failed > 0 {
        notes.push(format!(
            "NVD: {failed} lookup(s) failed (network or rate limit); those findings stay unscored."
        ));
    }
    if still_unscored > 0 && !opts.enrich_nvd {
        notes.push(format!("{still_unscored} finding(s) have a CVE id but no score; enable NVD enrichment (`--enrich-nvd` / enrich_nvd) to score them."));
    }
}

fn sources_lack_symbols(store: &Store, sources: &[DataSource]) -> bool {
    sources.iter().any(|s| {
        s.mode == "local"
            && matches!(s.ecosystem.as_str(), "Go" | "crates.io")
            && Ecosystem::from_osv_name(&s.ecosystem)
                .and_then(|e| store.meta(e))
                .is_some_and(|m| m.schema < opencraysec_db::SCHEMA)
    })
}

/// Scans every lockfile under `root` against the advisory data.
pub fn scan(store: &Store, root: &Path, opts: &ScanOptions) -> Result<ScanReport, EngineError> {
    if !root.exists() {
        return Err(EngineError(format!(
            "path does not exist: {}",
            root.display()
        )));
    }
    // Everything is discovered; the options only narrow what is *checked*. The full set is kept so
    // the activity log can snapshot the whole dependency state.
    let disc = opencraysec_lockfile::discover(root, None);
    let all_packages = disc.packages.clone();
    let packages: Vec<Package> = disc
        .packages
        .into_iter()
        .filter(|p| {
            opts.ecosystems
                .as_ref()
                .is_none_or(|e| e.contains(&p.ecosystem))
        })
        .filter(|p| opts.include_dev || !p.dev)
        .collect();
    let mut notes = Vec::new();
    if disc.parsed.is_empty() {
        notes.push(
            "No supported lockfile found (Cargo.lock, package-lock.json, yarn.lock, pnpm-lock.yaml, \
             composer.lock, go.mod, poetry.lock, uv.lock, Pipfile.lock, requirements*.txt). \
             Nothing was checked."
                .to_string(),
        );
    }
    let mut findings: Vec<(Finding, Vec<String>)> = Vec::new();
    let mut informational = 0usize;
    let mut sources = Vec::new();

    for eco in online::ecosystems_of(&packages) {
        let pkgs: Vec<&Package> = packages.iter().filter(|p| p.ecosystem == eco).collect();
        let mut src = DataSource {
            ecosystem: eco.osv_name().to_string(),
            mode: "none".into(),
            updated_at: None,
            packages: pkgs.len(),
        };
        if store.has(eco) {
            let wanted: HashSet<String> =
                pkgs.iter().map(|p| eco.normalize_name(&p.name)).collect();
            let by_name = store.load_for(eco, &wanted)?;
            for p in &pkgs {
                let name = eco.normalize_name(&p.name);
                for rec in by_name.get(&name).into_iter().flatten() {
                    if let Some(m) = rec.affects(eco, &name, &p.version) {
                        if rec.is_informational_only() {
                            informational += 1;
                            continue;
                        }
                        let f = build_finding(rec, p, m.fixed_in);
                        findings.push((f, rec.cve_ids()));
                    }
                }
            }
            src.mode = "local".into();
            src.updated_at = store.meta(eco).map(|m| m.updated_at);
        } else if !opts.offline {
            let owned: Vec<Package> = pkgs.iter().map(|p| (*p).clone()).collect();
            let hits = online::query(store, &owned)?;
            for h in hits {
                let p = &owned[h.package_index];
                let name = eco.normalize_name(&p.name);
                if h.record.is_informational_only() {
                    informational += 1;
                    continue;
                }
                let fixed = h
                    .record
                    .affects(eco, &name, &p.version)
                    .map(|m| m.fixed_in)
                    .unwrap_or_default();
                findings.push((build_finding(&h.record, p, fixed), h.record.cve_ids()));
            }
            src.mode = "online".into();
            notes.push(format!(
                "{}: no local data, so package names and versions were sent to api.osv.dev. \
                 Run `opencraysec update {}` for offline scans.",
                eco.osv_name(),
                eco.osv_name()
            ));
        } else {
            notes.push(format!(
                "{}: NOT scanned (offline and no local data). Run `opencraysec update {}`.",
                eco.osv_name(),
                eco.osv_name()
            ));
        }
        sources.push(src);
    }

    let kev = store.kev();
    let cve_ids: HashSet<String> = findings
        .iter()
        .flat_map(|(_, c)| c.iter().cloned())
        .collect();
    let epss: HashMap<String, f32> = store.epss(&cve_ids);
    if !findings.is_empty() {
        if kev.is_empty() {
            notes.push("CISA KEV list not downloaded: exploited-in-the-wild flags are missing. Run `opencraysec update --enrich`.".into());
        }
        if epss.is_empty() {
            notes.push("EPSS scores not downloaded: exploit-probability ranking is missing. Run `opencraysec update --enrich`.".into());
        }
    }
    let mut enriched = Vec::new();
    for (mut f, cves) in findings {
        f.known_exploited = cves.iter().any(|c| kev.contains(c));
        f.epss = cves
            .iter()
            .filter_map(|c| epss.get(c))
            .copied()
            .fold(None, |a: Option<f32>, x| Some(a.map_or(x, |y| y.max(x))));
        enriched.push(f);
    }
    let mut merged = merge_same_issue(enriched);
    enrich_from_nvd(store, &mut merged, opts, &mut notes);
    merged.retain(|f| f.severity >= opts.min_severity);
    if opts.reachability {
        let base = if root.is_file() {
            root.parent().unwrap_or(root)
        } else {
            root
        };
        reach::annotate(base, &mut merged, &mut notes);
        if sources_lack_symbols(store, &sources) {
            notes.push("Symbol-level usage checks need the dataset layout v2: run `opencraysec update` again for Go and Rust.".into());
        }
    }
    let not_found = |f: &Finding| {
        f.reachability
            .as_ref()
            .is_some_and(|r| r.level == "not_found")
    };
    merged.sort_by(|a, b| {
        // Exploited in the wild always leads; otherwise code the project does not import sinks.
        let lead = |f: &Finding| (f.known_exploited, !not_found(f));
        lead(b)
            .cmp(&lead(a))
            .then_with(|| b.rank_key().cmp(&a.rank_key()))
            .then_with(|| a.package.name.cmp(&b.package.name))
            .then_with(|| a.id.cmp(&b.id))
    });
    Ok(ScanReport {
        root: root
            .canonicalize()
            .unwrap_or_else(|_| root.to_path_buf())
            .display()
            .to_string(),
        scanned_at: opencraysec_db::now_rfc3339(),
        lockfiles: disc.parsed,
        skipped: disc.skipped,
        unchecked: disc.unchecked,
        packages_checked: packages.len(),
        data_sources: sources,
        notes,
        informational_omitted: informational,
        findings: merged,
        packages,
        all_packages,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn seed_store(dir: &Path) -> Store {
        let store = Store::at(dir.join("data"));
        let rec: OsvRecord = serde_json::from_str(
            r#"{"id":"GHSA-aaaa","aliases":["CVE-2026-100"],"summary":"bad lodash",
              "affected":[{"package":{"ecosystem":"npm","name":"lodash"},
                "ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}],
              "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
              "database_specific":{"cwe_ids":["CWE-1321"]}}"#,
        )
        .expect("json");
        let dup: OsvRecord = serde_json::from_str(
            r#"{"id":"OTHER-1","aliases":["CVE-2026-100"],
              "affected":[{"package":{"ecosystem":"npm","name":"lodash"},
                "ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.20"}]}]}]}"#,
        )
        .expect("json");
        let info: OsvRecord = serde_json::from_str(
            r#"{"id":"RUSTSEC-1","affected":[{"package":{"ecosystem":"npm","name":"lodash"},
                "ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}],
              "database_specific":{"informational":"unmaintained"}}"#,
        )
        .expect("json");
        fs::create_dir_all(dir.join("data/osv")).expect("mkdir");
        let lines: Vec<String> = [rec, dup, info]
            .iter()
            .filter_map(|r| opencraysec_db::encode_line(Ecosystem::Npm, r).expect("enc"))
            .collect();
        fs::write(dir.join("data/osv/npm.jsonl"), lines.join("\n") + "\n").expect("w");
        fs::write(
            dir.join("data/osv/npm.meta.json"),
            r#"{"updated_at":"2026-10-19T00:00:00Z","records":3}"#,
        )
        .expect("w");
        fs::write(
            dir.join("data/kev.json"),
            r#"{"updated_at":"t","ids":["CVE-2026-100"]}"#,
        )
        .expect("w");
        fs::write(
            dir.join("data/epss.tsv"),
            "#updated_at=t\nCVE-2026-100\t0.42\n",
        )
        .expect("w");
        store
    }

    #[test]
    fn end_to_end_local_scan() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = seed_store(dir.path());
        let proj = dir.path().join("proj");
        fs::create_dir_all(&proj).expect("mkdir");
        fs::write(
            proj.join("package-lock.json"),
            r#"{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.4"},
               "node_modules/safe":{"version":"1.0.0"}}}"#,
        )
        .expect("w");
        let opts = ScanOptions {
            offline: true,
            ..ScanOptions::default()
        };
        let r = scan(&store, &proj, &opts).expect("scan");
        assert_eq!(r.packages_checked, 2);
        assert_eq!(
            r.findings.len(),
            1,
            "same-CVE advisories merge into one finding"
        );
        let f = &r.findings[0];
        assert_eq!(f.package.name, "lodash");
        assert_eq!(f.severity, Severity::Critical);
        assert!(f.known_exploited);
        assert_eq!(f.epss, Some(0.42));
        assert!(f.fixed_in.contains(&"4.17.21".to_string()));
        assert!(f.aliases.contains(&"OTHER-1".to_string()) || f.id == "OTHER-1");
        assert_eq!(r.informational_omitted, 1);
        assert_eq!(r.data_sources[0].mode, "local");
        let high = ScanOptions {
            min_severity: Severity::Critical,
            offline: true,
            ..ScanOptions::default()
        };
        assert_eq!(scan(&store, &proj, &high).expect("scan").findings.len(), 1);
    }

    #[test]
    fn merged_findings_keep_the_stricter_fix() {
        let mk = |id: &str, fixed: &[&str]| Finding {
            id: id.into(),
            aliases: vec!["CVE-1".into()],
            package: Package {
                ecosystem: Ecosystem::CratesIo,
                name: "time".into(),
                version: "0.1.43".into(),
                source: "Cargo.lock".into(),
                dev: false,
            },
            summary: String::new(),
            severity: Severity::Medium,
            cvss: None,
            cwes: vec![],
            known_exploited: false,
            epss: None,
            fixed_in: fixed.iter().map(|s| s.to_string()).collect(),
            references: vec![],
            reachability: None,
            symbol_refs: vec![],
        };
        let merged = merge_same_issue(vec![
            mk("RUSTSEC-1", &["0.2.0", "0.2.1", "0.2.23"]),
            mk("GHSA-1", &["0.2.23"]),
        ]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].fixed_in, vec!["0.2.23"]);
    }

    #[test]
    fn offline_without_data_is_loud() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = Store::at(dir.path().join("empty"));
        let proj = dir.path().join("p");
        fs::create_dir_all(&proj).expect("mkdir");
        fs::write(
            proj.join("go.mod"),
            "module x\nrequire github.com/a/b v1.0.0\n",
        )
        .expect("w");
        let opts = ScanOptions {
            offline: true,
            ..ScanOptions::default()
        };
        let r = scan(&store, &proj, &opts).expect("scan");
        assert!(r.findings.is_empty());
        assert!(r.notes.iter().any(|n| n.contains("NOT scanned")));
        assert_eq!(r.data_sources[0].mode, "none");
    }

    #[test]
    fn no_lockfile_and_missing_path() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = Store::at(dir.path().join("d"));
        let r = scan(&store, dir.path(), &ScanOptions::default()).expect("scan");
        assert!(r.notes[0].contains("No supported lockfile"));
        assert!(scan(&store, &dir.path().join("nope"), &ScanOptions::default()).is_err());
    }
}
