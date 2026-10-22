//! Fix planning and verification. opencraysec never edits a project; it tells the caller exactly
//! what to run and then re-scans to prove the finding is gone.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::path::Path;

use opencraysec_core::version::compare;
use opencraysec_core::{Ecosystem, Finding, Severity};
use opencraysec_db::Store;
use serde::Serialize;

use crate::EngineError;
use crate::scan::{ScanOptions, scan};

/// One dependency upgrade.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct FixStep {
    /// Package name.
    pub package: String,
    /// OSV ecosystem name.
    pub ecosystem: String,
    /// Installed version.
    pub from: String,
    /// Lowest version that clears every fixable finding for this package.
    pub to: String,
    /// `patch`, `minor`, `major` or `unknown`.
    pub bump: String,
    /// Advisory ids this step resolves.
    pub findings: Vec<String>,
    /// Lockfile the package was read from.
    pub lockfile: String,
    /// Commands to run, in order. None are executed by opencraysec.
    pub commands: Vec<String>,
    /// True when the upgrade may break callers and needs a human decision.
    pub needs_confirmation: bool,
    /// Extra guidance.
    pub note: String,
}

/// A finding with no known fixed version.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Unfixable {
    /// Package name.
    pub package: String,
    /// Installed version.
    pub version: String,
    /// Advisory id.
    pub finding: String,
    /// True for a malicious package: it is removed, not upgraded.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub malicious: bool,
}

/// The plan for a set of findings.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct FixPlan {
    /// Upgrades to perform.
    pub steps: Vec<FixStep>,
    /// Findings that have no published fix; mitigate or replace the dependency.
    pub unfixable: Vec<Unfixable>,
    /// Always-true reminders.
    pub caveats: Vec<String>,
}

fn nums(v: &str) -> Vec<u64> {
    let v = v.trim().trim_start_matches(['v', 'V']);
    let core = v.split(['-', '+']).next().unwrap_or(v);
    core.split('.').map_while(|p| p.parse().ok()).collect()
}

/// Classifies the jump between two versions. `0.x` minor bumps count as breaking.
pub fn bump_kind(from: &str, to: &str) -> (&'static str, bool) {
    let (a, b) = (nums(from), nums(to));
    let (Some(a0), Some(b0)) = (a.first(), b.first()) else {
        return ("unknown", true);
    };
    if a0 != b0 {
        return ("major", true);
    }
    let (a1, b1) = (
        a.get(1).copied().unwrap_or(0),
        b.get(1).copied().unwrap_or(0),
    );
    if a1 != b1 {
        return ("minor", *a0 == 0);
    }
    ("patch", false)
}

fn lockfile_kind(source: &str) -> &str {
    source.rsplit('/').next().unwrap_or(source)
}

fn commands(
    eco: Ecosystem,
    name: &str,
    from: &str,
    to: &str,
    lockfile: &str,
) -> (Vec<String>, String) {
    let lf = lockfile_kind(lockfile);
    match eco {
        Ecosystem::CratesIo => (
            vec![format!("cargo update -p {name}@{from} --precise {to}")],
            "If Cargo.toml pins a requirement that excludes the new version, raise that requirement first.".into(),
        ),
        Ecosystem::Npm => {
            let cmd = match lf {
                "yarn.lock" => format!("yarn upgrade {name}@{to}"),
                "pnpm-lock.yaml" => format!("pnpm update {name}@{to} -r"),
                _ => format!("npm install {name}@{to}"),
            };
            (
                vec![cmd],
                format!("If `{name}` is only a transitive dependency, update its parent, or force it with `overrides` (npm), `resolutions` (yarn) or `pnpm.overrides`."),
            )
        }
        Ecosystem::Packagist => (
            vec![format!("composer update {name} --with {name}:{to}")],
            "If composer.json constrains the package below the fixed version, widen the constraint.".into(),
        ),
        Ecosystem::Go => (
            vec![format!("go get {name}@v{}", to.trim_start_matches('v')), "go mod tidy".into()],
            "Use `go mod why -m` to see which module pulls this one in if it is indirect.".into(),
        ),
        Ecosystem::PyPI => {
            let cmd = match lf {
                "poetry.lock" => format!("poetry add \"{name}>={to}\""),
                "uv.lock" => format!("uv lock --upgrade-package {name}"),
                "Pipfile.lock" => format!("pipenv install \"{name}>={to}\""),
                _ => format!("pip install \"{name}>={to}\"   # and update the pin in {lf}"),
            };
            (vec![cmd], "Re-export the lockfile or requirements file afterwards.".into())
        }
    }
}

/// Builds an upgrade plan for `findings`, optionally restricted to one advisory id or package.
pub fn plan_fix(findings: &[Finding], only: Option<&str>) -> FixPlan {
    let mut groups: BTreeMap<(Ecosystem, String, String), Vec<&Finding>> = BTreeMap::new();
    for f in findings {
        if let Some(sel) = only
            && f.id != sel
            && !f.aliases.iter().any(|a| a == sel)
            && f.package.name != sel
        {
            continue;
        }
        groups
            .entry((
                f.package.ecosystem,
                f.package.name.clone(),
                f.package.version.clone(),
            ))
            .or_default()
            .push(f);
    }
    let mut steps = Vec::new();
    let mut unfixable = Vec::new();
    for ((eco, name, version), fs) in groups {
        let mut target: Option<&str> = None;
        let mut resolved = Vec::new();
        for f in &fs {
            match f.fixed_in.first() {
                Some(min) => {
                    resolved.push(f.id.clone());
                    if target.is_none_or(|t| compare(eco, min, t) == Ordering::Greater) {
                        target = Some(min);
                    }
                }
                None => unfixable.push(Unfixable {
                    package: name.clone(),
                    version: version.clone(),
                    finding: f.id.clone(),
                    malicious: f.malicious,
                }),
            }
        }
        let Some(to) = target else { continue };
        let lockfile = fs[0].package.source.clone();
        let (bump, confirm) = bump_kind(&version, to);
        let (cmds, note) = commands(eco, &name, &version, to, &lockfile);
        steps.push(FixStep {
            package: name,
            ecosystem: eco.osv_name().to_string(),
            from: version,
            to: to.to_string(),
            bump: bump.to_string(),
            findings: resolved,
            lockfile,
            commands: cmds,
            needs_confirmation: confirm,
            note,
        });
    }
    let mut caveats = vec![
        "opencraysec does not modify your project; run the commands yourself or have the assistant run them after you approve.".into(),
        "Run the project's tests after upgrading, then call verify_fix to prove the findings are gone.".into(),
        "Steps marked needs_confirmation cross a major version (or a 0.x minor) and may break callers.".into(),
    ];
    if findings.iter().any(|f| f.malicious) {
        caveats.push(
            "A malicious package is not fixed by an upgrade. Remove it (or move to a version the advisory does not list), check whether its install scripts already ran on this machine or in CI, and rotate any secret those could reach.".into(),
        );
    }
    FixPlan {
        steps,
        unfixable,
        caveats,
    }
}

/// Result of re-scanning after a fix.
#[derive(Debug, Clone, Serialize)]
pub struct VerifyOutcome {
    /// Expected ids that no longer appear.
    pub resolved: Vec<String>,
    /// Expected ids that no earlier scan of this workspace reported (a typo, an invented id, an
    /// advisory that never applied here, or no scan was logged). A finding that was never seen
    /// cannot be shown to be gone, so these are never counted as resolved.
    pub unknown: Vec<String>,
    /// Findings that are still present.
    pub remaining: Vec<Finding>,
    /// Total findings left in the whole project.
    pub total_findings_now: usize,
    /// False when part of the project could not be scanned or checked, so "resolved" proves nothing.
    pub trustworthy: bool,
    /// Caveats from the re-scan.
    pub notes: Vec<String>,
}

/// Re-scans `root` and checks that each id in `expected` (advisory id or alias) is gone.
///
/// `seen_before` holds the ids and aliases that earlier scans of this same workspace reported
/// (from the activity log). An id is only `resolved` when it was seen before and is absent now;
/// otherwise there is nothing to prove, and it is `unknown`.
///
/// The re-scan always covers the whole project: `opts` only supplies `offline`, `reachability` and
/// `enrich_nvd`, never a filter that could hide a remaining finding.
pub fn verify_fix(
    store: &Store,
    root: &Path,
    opts: &ScanOptions,
    expected: &[String],
    seen_before: &[String],
) -> Result<VerifyOutcome, EngineError> {
    // Verification must not be narrowed by what the caller chose to display: a finding below
    // `min_severity`, in a dev dependency or in another ecosystem is still a finding.
    let full = ScanOptions {
        ecosystems: None,
        include_dev: true,
        min_severity: Severity::Unknown,
        ..opts.clone()
    };
    let report = scan(store, root, &full)?;
    let mut resolved = Vec::new();
    let mut unknown = Vec::new();
    let mut remaining = Vec::new();
    for id in expected {
        let still: Vec<&Finding> = report
            .findings
            .iter()
            .filter(|f| &f.id == id || f.aliases.contains(id))
            .collect();
        if !still.is_empty() {
            remaining.extend(still.into_iter().cloned());
        } else if seen_before.contains(id) {
            resolved.push(id.clone());
        } else {
            unknown.push(id.clone());
        }
    }
    let trustworthy = !report.is_incomplete();
    let mut notes = report.notes;
    if !unknown.is_empty() {
        notes.push(format!(
            "{} not reported by any earlier scan of this exact path in the activity log, so nothing shows it was ever present here. Run scan_dependencies on this path before fixing and keep logging on.",
            unknown.join(", ")
        ));
    }
    Ok(VerifyOutcome {
        resolved,
        unknown,
        remaining,
        total_findings_now: report.findings.len(),
        trustworthy,
        notes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use opencraysec_core::Package;

    fn finding(id: &str, name: &str, ver: &str, fixed: &[&str]) -> Finding {
        Finding {
            id: id.into(),
            aliases: vec![],
            package: Package {
                ecosystem: Ecosystem::Npm,
                name: name.into(),
                version: ver.into(),
                source: "web/package-lock.json".into(),
                dev: false,
            },
            summary: String::new(),
            severity: Severity::High,
            cvss: None,
            cwes: vec![],
            known_exploited: false,
            malicious: false,
            epss: None,
            fixed_in: fixed.iter().map(|s| s.to_string()).collect(),
            references: vec![],
            reachability: None,
            symbol_refs: vec![],
        }
    }

    #[test]
    fn a_malicious_package_is_removed_not_upgraded() {
        let mut bad = finding("MAL-2026-7", "evil-pkg", "1.0.0", &[]);
        bad.malicious = true;
        let plan = plan_fix(&[bad, finding("A", "lodash", "4.17.4", &["4.17.21"])], None);
        assert_eq!(plan.steps.len(), 1, "only lodash gets an upgrade command");
        assert_eq!(plan.unfixable.len(), 1);
        assert!(plan.unfixable[0].malicious);
        assert!(
            plan.caveats
                .iter()
                .any(|c| c.contains("malicious package is not fixed by an upgrade"))
        );
        let json = serde_json::to_value(&plan).expect("json");
        assert_eq!(json["unfixable"][0]["malicious"], true);
    }

    #[test]
    fn a_compromised_release_with_a_clean_version_still_gets_the_warning() {
        let mut bad = finding("MAL-2026-8", "popular-lib", "2.0.1", &["2.0.2"]);
        bad.malicious = true;
        let plan = plan_fix(&[bad], None);
        assert_eq!(plan.steps.len(), 1);
        assert_eq!(plan.steps[0].to, "2.0.2");
        assert!(plan.caveats.iter().any(|c| c.contains("malicious")));
    }

    #[test]
    fn an_ordinary_plan_carries_no_malicious_wording() {
        let plan = plan_fix(&[finding("C", "left-pad", "1.0.0", &[])], None);
        assert!(!plan.caveats.iter().any(|c| c.contains("malicious")));
        let json = serde_json::to_value(&plan).expect("json");
        assert!(json["unfixable"][0].get("malicious").is_none());
    }

    #[test]
    fn bump_classification() {
        assert_eq!(bump_kind("1.2.3", "1.2.9"), ("patch", false));
        assert_eq!(bump_kind("1.2.3", "1.3.0"), ("minor", false));
        assert_eq!(bump_kind("0.2.3", "0.3.0"), ("minor", true));
        assert_eq!(bump_kind("v1.9.0", "v2.0.0"), ("major", true));
        assert_eq!(bump_kind("x", "1.0.0"), ("unknown", true));
    }

    #[test]
    fn one_step_covers_all_findings_of_a_package() {
        let fs = vec![
            finding("A", "lodash", "4.17.4", &["4.17.12", "5.0.0"]),
            finding("B", "lodash", "4.17.4", &["4.17.21"]),
            finding("C", "left-pad", "1.0.0", &[]),
        ];
        let plan = plan_fix(&fs, None);
        assert_eq!(plan.steps.len(), 1);
        let s = &plan.steps[0];
        assert_eq!((s.to.as_str(), s.bump.as_str()), ("4.17.21", "patch"));
        assert_eq!(s.findings, vec!["A", "B"]);
        assert!(!s.needs_confirmation);
        assert_eq!(s.commands, vec!["npm install lodash@4.17.21"]);
        assert_eq!(plan.unfixable.len(), 1);
        assert_eq!(plan.unfixable[0].finding, "C");
        assert_eq!(plan_fix(&fs, Some("B")).steps[0].findings, vec!["B"]);
        assert!(plan_fix(&fs, Some("nothing")).steps.is_empty());
    }

    #[test]
    fn per_ecosystem_commands() {
        for (eco, name, lock, expect) in [
            (
                Ecosystem::CratesIo,
                "time",
                "Cargo.lock",
                "cargo update -p time@1.0.0 --precise 2.0.0",
            ),
            (
                Ecosystem::Go,
                "golang.org/x/net",
                "go.mod",
                "go get golang.org/x/net@v2.0.0",
            ),
            (
                Ecosystem::Packagist,
                "a/b",
                "composer.lock",
                "composer update a/b --with a/b:2.0.0",
            ),
            (
                Ecosystem::PyPI,
                "django",
                "poetry.lock",
                "poetry add \"django>=2.0.0\"",
            ),
            (Ecosystem::Npm, "x", "app/yarn.lock", "yarn upgrade x@2.0.0"),
        ] {
            let (cmds, _) = commands(eco, name, "1.0.0", "2.0.0", lock);
            assert_eq!(cmds[0], expect);
        }
    }
}
