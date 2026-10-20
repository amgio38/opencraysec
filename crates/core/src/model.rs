//! Core data model.

use serde::{Deserialize, Serialize};

/// A package ecosystem whose advisories we know how to match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Ecosystem {
    /// Rust crates (crates.io).
    CratesIo,
    /// npm packages (JavaScript / TypeScript).
    Npm,
    /// Composer packages (PHP, Packagist).
    Packagist,
    /// Go modules.
    Go,
    /// Python packages (PyPI).
    PyPI,
}

impl Ecosystem {
    /// Every supported ecosystem.
    pub const ALL: [Ecosystem; 5] = [
        Ecosystem::CratesIo,
        Ecosystem::Npm,
        Ecosystem::Packagist,
        Ecosystem::Go,
        Ecosystem::PyPI,
    ];

    /// The ecosystem name used by OSV (`affected[].package.ecosystem`).
    pub fn osv_name(self) -> &'static str {
        match self {
            Ecosystem::CratesIo => "crates.io",
            Ecosystem::Npm => "npm",
            Ecosystem::Packagist => "Packagist",
            Ecosystem::Go => "Go",
            Ecosystem::PyPI => "PyPI",
        }
    }

    /// Parses an OSV ecosystem name, ignoring any `:suffix` such as `Debian:11`.
    pub fn from_osv_name(name: &str) -> Option<Ecosystem> {
        let base = name.split(':').next().unwrap_or(name);
        Ecosystem::ALL.into_iter().find(|e| e.osv_name() == base)
    }

    /// Parses a user-facing name (`rust`, `js`, `php`, ...) or an OSV name.
    pub fn parse(name: &str) -> Option<Ecosystem> {
        match name.to_ascii_lowercase().as_str() {
            "crates.io" | "cargo" | "rust" | "crates" => Some(Ecosystem::CratesIo),
            "npm" | "js" | "ts" | "node" | "javascript" | "typescript" => Some(Ecosystem::Npm),
            "packagist" | "composer" | "php" => Some(Ecosystem::Packagist),
            "go" | "golang" => Some(Ecosystem::Go),
            "pypi" | "python" | "pip" => Some(Ecosystem::PyPI),
            _ => None,
        }
    }

    /// Normalises a package name the way the advisory databases key it.
    pub fn normalize_name(self, name: &str) -> String {
        match self {
            Ecosystem::Packagist => name.to_ascii_lowercase(),
            Ecosystem::PyPI => {
                let mut out = String::with_capacity(name.len());
                let mut prev_sep = false;
                for c in name.chars() {
                    if matches!(c, '-' | '_' | '.') {
                        if !prev_sep {
                            out.push('-');
                        }
                        prev_sep = true;
                    } else {
                        out.push(c.to_ascii_lowercase());
                        prev_sep = false;
                    }
                }
                out
            }
            _ => name.to_string(),
        }
    }
}

/// One resolved dependency read from a lockfile.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Package {
    /// Ecosystem the package belongs to.
    pub ecosystem: Ecosystem,
    /// Package name as written in the lockfile.
    pub name: String,
    /// Resolved version.
    pub version: String,
    /// Lockfile (relative to the scan root) the package came from.
    pub source: String,
    /// True when the lockfile marks it as a development-only dependency.
    pub dev: bool,
}

/// Severity bucket, ordered from least to most severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// No severity information in the advisory.
    Unknown,
    /// CVSS below 4.0.
    Low,
    /// CVSS 4.0 to 6.9.
    Medium,
    /// CVSS 7.0 to 8.9.
    High,
    /// CVSS 9.0 and above.
    Critical,
}

impl Severity {
    /// Bucket for a CVSS base score.
    pub fn from_score(score: f32) -> Severity {
        if score >= 9.0 {
            Severity::Critical
        } else if score >= 7.0 {
            Severity::High
        } else if score >= 4.0 {
            Severity::Medium
        } else if score > 0.0 {
            Severity::Low
        } else {
            Severity::Unknown
        }
    }

    /// Parses `low`/`moderate`/`medium`/`high`/`critical` (case-insensitive).
    pub fn parse(label: &str) -> Option<Severity> {
        match label.to_ascii_lowercase().as_str() {
            "low" => Some(Severity::Low),
            "moderate" | "medium" => Some(Severity::Medium),
            "high" | "important" => Some(Severity::High),
            "critical" => Some(Severity::Critical),
            "unknown" | "none" => Some(Severity::Unknown),
            _ => None,
        }
    }

    /// Lower-case label.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Unknown => "unknown",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// Evidence about whether the project's own code uses a vulnerable dependency.
///
/// This is source-level evidence (imports and, for Rust and Go, named symbols), not a call graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reachability {
    /// `used_symbol`, `imported`, `not_found` or `unknown`.
    pub level: String,
    /// `file:line` locations that back the level.
    pub evidence: Vec<String>,
    /// What the level does and does not prove.
    pub note: String,
}

/// One vulnerable dependency, enriched and ready to report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    /// Advisory id (`GHSA-...`, `RUSTSEC-...`, `CVE-...`, `GO-...`).
    pub id: String,
    /// Other ids for the same issue, usually CVE ids.
    pub aliases: Vec<String>,
    /// The affected dependency.
    pub package: Package,
    /// One-line summary.
    pub summary: String,
    /// Severity bucket.
    pub severity: Severity,
    /// CVSS base score when it could be computed.
    pub cvss: Option<f32>,
    /// CWE ids such as `CWE-79`.
    pub cwes: Vec<String>,
    /// True when CISA lists the issue as exploited in the wild.
    pub known_exploited: bool,
    /// EPSS probability of exploitation in the next 30 days (0..1).
    pub epss: Option<f32>,
    /// Versions that fix the issue, lowest first.
    pub fixed_in: Vec<String>,
    /// Advisory links.
    pub references: Vec<String>,
    /// Source-level usage evidence, when it was requested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reachability: Option<Reachability>,
    /// Vulnerable symbols named by the advisories (used by reachability; not serialised).
    #[serde(skip)]
    pub symbol_refs: Vec<crate::osv::SymbolRef>,
}

impl Finding {
    /// Sort key, most urgent last: exploited in the wild, then a meaningful EPSS (10% or more),
    /// then CVSS, then the raw EPSS as a tie-breaker. Tiny EPSS differences are noise, so they
    /// never outrank a higher CVSS score.
    pub fn rank_key(&self) -> (bool, bool, i64, i64) {
        let epss = self.epss.unwrap_or(0.0);
        (
            self.known_exploited,
            epss >= 0.1,
            (self.cvss.unwrap_or(0.0) * 10.0) as i64,
            (epss * 1_000_000.0) as i64,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecosystem_names_round_trip_and_aliases_resolve() {
        for e in Ecosystem::ALL {
            assert_eq!(Ecosystem::from_osv_name(e.osv_name()), Some(e));
            assert_eq!(Ecosystem::parse(e.osv_name()), Some(e));
        }
        assert_eq!(Ecosystem::from_osv_name("Debian:11"), None);
        assert_eq!(Ecosystem::from_osv_name("npm:extra"), Some(Ecosystem::Npm));
        for (alias, want) in [
            ("Rust", Ecosystem::CratesIo),
            ("cargo", Ecosystem::CratesIo),
            ("TypeScript", Ecosystem::Npm),
            ("node", Ecosystem::Npm),
            ("php", Ecosystem::Packagist),
            ("composer", Ecosystem::Packagist),
            ("golang", Ecosystem::Go),
            ("python", Ecosystem::PyPI),
            ("pip", Ecosystem::PyPI),
        ] {
            assert_eq!(Ecosystem::parse(alias), Some(want), "{alias}");
        }
        assert_eq!(Ecosystem::parse("cobol"), None);
    }

    #[test]
    fn names_are_normalised_the_way_each_database_keys_them() {
        assert_eq!(
            Ecosystem::PyPI.normalize_name("Foo_Bar.baz--qux"),
            "foo-bar-baz-qux"
        );
        assert_eq!(
            Ecosystem::Packagist.normalize_name("Symfony/Http"),
            "symfony/http"
        );
        assert_eq!(Ecosystem::Npm.normalize_name("@Scope/Pkg"), "@Scope/Pkg");
        assert_eq!(
            Ecosystem::Go.normalize_name("Example.com/M"),
            "Example.com/M"
        );
    }

    #[test]
    fn severity_buckets_labels_and_ordering() {
        for (score, want) in [
            (10.0, Severity::Critical),
            (9.0, Severity::Critical),
            (8.9, Severity::High),
            (7.0, Severity::High),
            (6.9, Severity::Medium),
            (4.0, Severity::Medium),
            (3.9, Severity::Low),
            (0.1, Severity::Low),
            (0.0, Severity::Unknown),
        ] {
            assert_eq!(Severity::from_score(score), want, "{score}");
        }
        for (label, want) in [
            ("LOW", Severity::Low),
            ("moderate", Severity::Medium),
            ("Medium", Severity::Medium),
            ("important", Severity::High),
            ("high", Severity::High),
            ("critical", Severity::Critical),
            ("none", Severity::Unknown),
            ("unknown", Severity::Unknown),
        ] {
            assert_eq!(Severity::parse(label), Some(want), "{label}");
            assert_eq!(Severity::parse(want.as_str()), Some(want));
        }
        assert_eq!(Severity::parse("urgent"), None);
        assert!(
            Severity::Critical > Severity::High
                && Severity::High > Severity::Medium
                && Severity::Medium > Severity::Low
                && Severity::Low > Severity::Unknown
        );
    }

    #[test]
    fn ranking_prefers_exploited_then_likely_then_score() {
        let base = Finding {
            id: "A".into(),
            aliases: vec![],
            package: Package {
                ecosystem: Ecosystem::Npm,
                name: "p".into(),
                version: "1".into(),
                source: "l".into(),
                dev: false,
            },
            summary: String::new(),
            severity: Severity::High,
            cvss: Some(7.0),
            cwes: vec![],
            known_exploited: false,
            epss: None,
            fixed_in: vec![],
            references: vec![],
            reachability: None,
            symbol_refs: vec![],
        };
        let kev = Finding {
            known_exploited: true,
            cvss: Some(4.0),
            ..base.clone()
        };
        let likely = Finding {
            epss: Some(0.5),
            cvss: Some(5.0),
            ..base.clone()
        };
        let noisy = Finding {
            epss: Some(0.001),
            cvss: Some(9.0),
            ..base.clone()
        };
        assert!(kev.rank_key() > likely.rank_key());
        assert!(
            likely.rank_key() > noisy.rank_key(),
            "a meaningful EPSS outranks a higher CVSS"
        );
        let tiny_a = Finding {
            epss: Some(0.002),
            ..noisy.clone()
        };
        assert!(
            noisy.rank_key() < tiny_a.rank_key(),
            "raw EPSS only breaks ties"
        );
        assert!(base.rank_key() < noisy.rank_key());
    }
}
