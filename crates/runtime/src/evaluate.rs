//! Judging an installed version against the lifecycle data: is its release line past end of life,
//! and is there a newer patch release in the same line?

use std::cmp::Ordering;

use serde::Serialize;

use crate::lifecycle::{Lifecycle, Product, Release, VendorLatest};

/// One product at one version, to be judged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Input {
    /// The product, by feed slug or alias (`php`, `node` is `nodejs`).
    pub product: String,
    /// The installed version (`7.4.33`).
    pub version: String,
    /// Where the version came from: `detected: php --version`, or `given`.
    pub source: String,
}

/// What the data says about an installed version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// The release line no longer gets upstream fixes.
    Eol,
    /// A newer patch release exists in the same line.
    Outdated,
    /// On the newest patch of a line that is not end of life, as far as the data knows.
    Current,
    /// The data cannot say (no data, unknown product, version outside every known line).
    Unknown,
}

/// The verdict for one input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductResult {
    /// The product as asked.
    pub product: String,
    /// The version judged.
    pub version: String,
    /// Where the version came from.
    pub source: String,
    /// The verdict.
    pub status: Status,
    /// The release line the version belongs to.
    pub cycle: Option<String>,
    /// First day the line is end of life.
    pub eol_from: Option<String>,
    /// Newest patch release of the line, from whichever feed is ahead.
    pub latest: Option<String>,
    /// How many patch releases behind, when that can be counted.
    pub patches_behind: Option<u64>,
    /// One sentence a person can act on.
    pub advice: String,
}

/// Leading numeric segments of a version: `8.2.30-1+deb12u1` is `[8, 2, 30]`.
pub fn segments(v: &str) -> Vec<u64> {
    let mut out = Vec::new();
    for part in v.trim_start_matches('v').split('.') {
        let digits: String = part.chars().take_while(char::is_ascii_digit).collect();
        match digits.parse::<u64>() {
            Ok(n) => out.push(n),
            Err(_) => break,
        }
        if digits.len() != part.len() {
            break;
        }
    }
    out
}

/// Compares two dotted versions numerically; missing segments count as zero.
pub fn compare(a: &str, b: &str) -> Ordering {
    let (a, b) = (segments(a), segments(b));
    for i in 0..a.len().max(b.len()) {
        let (x, y) = (
            a.get(i).copied().unwrap_or(0),
            b.get(i).copied().unwrap_or(0),
        );
        match x.cmp(&y) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    Ordering::Equal
}

/// The release line `version` belongs to: the longest line name that is the version or a dotted
/// prefix of it (`8.2` for `8.2.30`, `22` for `22.11.0`).
fn line_of<'a>(product: &'a Product, version: &str) -> Option<&'a Release> {
    product
        .releases
        .iter()
        .filter(|r| {
            version == r.name
                || version
                    .strip_prefix(r.name.as_str())
                    .is_some_and(|rest| rest.starts_with('.'))
        })
        .max_by_key(|r| r.name.len())
}

/// How many patch releases `version` is behind `latest`, when they differ only in the last number.
fn patches_between(version: &str, latest: &str) -> Option<u64> {
    let (v, l) = (segments(version), segments(latest));
    if v.len() == l.len() && v.len() >= 2 && v[..v.len() - 1] == l[..l.len() - 1] {
        l.last()?.checked_sub(*v.last()?)
    } else {
        None
    }
}

fn unknown(i: &Input, why: String) -> ProductResult {
    ProductResult {
        product: i.product.clone(),
        version: i.version.clone(),
        source: i.source.clone(),
        status: Status::Unknown,
        cycle: None,
        eol_from: None,
        latest: None,
        patches_behind: None,
        advice: why,
    }
}

/// Judges every input. `today` is `YYYY-MM-DD`; it is passed in so the verdict does not depend on
/// the clock and so a dataset that went stale since it was downloaded still dates correctly.
pub fn evaluate(
    lifecycle: Option<&Lifecycle>,
    vendor: &[VendorLatest],
    inputs: &[Input],
    today: &str,
) -> Vec<ProductResult> {
    inputs
        .iter()
        .map(|i| judge(lifecycle, vendor, i, today))
        .collect()
}

fn judge(
    lifecycle: Option<&Lifecycle>,
    vendor: &[VendorLatest],
    i: &Input,
    today: &str,
) -> ProductResult {
    let Some(lifecycle) = lifecycle else {
        return unknown(
            i,
            "no release data is stored; run `opencraysec update` while online".into(),
        );
    };
    let Some(product) = lifecycle.find(&i.product) else {
        return unknown(
            i,
            format!(
                "the release feed does not know a product called {:?}",
                i.product
            ),
        );
    };
    let Some(line) = line_of(product, &i.version) else {
        return unknown(
            i,
            format!(
                "{} {} is not in any release line the feed lists; it may be older than the feed goes back or newer than its last update",
                product.name, i.version
            ),
        );
    };

    // The vendor's own feed is ahead of the aggregator for the days after a release.
    let from_vendor = vendor
        .iter()
        .find(|v| v.product.eq_ignore_ascii_case(&product.name))
        .and_then(|v| v.latest.get(&line.name));
    let latest = match (line.latest.as_ref(), from_vendor) {
        (Some(a), Some(b)) => Some(if compare(b, a) == Ordering::Greater {
            b
        } else {
            a
        }),
        (a, b) => a.or(b),
    }
    .cloned();

    let past_date = line
        .eol_from
        .as_deref()
        .is_some_and(|d| d.len() == 10 && d <= today);
    let eol = line.is_eol || past_date;
    let behind = latest
        .as_deref()
        .is_some_and(|l| compare(&i.version, l) == Ordering::Less);
    let patches_behind = latest
        .as_deref()
        .filter(|_| behind)
        .and_then(|l| patches_between(&i.version, l));

    let (status, advice) = if eol {
        (
            Status::Eol,
            format!(
                "{} {} is end of life{}: upstream no longer publishes security fixes for it. Move to a supported release line{}.",
                product.name,
                line.name,
                line.eol_from
                    .as_deref()
                    .map(|d| format!(" (since {d})"))
                    .unwrap_or_default(),
                if behind {
                    String::new()
                } else {
                    " (a patched build from your OS vendor may still exist; check their tracker)"
                        .to_string()
                }
            ),
        )
    } else if behind {
        (
            Status::Outdated,
            format!(
                "newer patch release {} exists in the {} line{}; upgrade, or confirm your OS vendor backported its fixes.",
                latest.as_deref().unwrap_or("?"),
                line.name,
                patches_behind
                    .map(|n| format!(" ({n} behind)"))
                    .unwrap_or_default()
            ),
        )
    } else if latest.is_some() {
        (
            Status::Current,
            format!(
                "on the newest known patch of the {} line, which is supported. This says nothing about vulnerabilities published after the data was downloaded.",
                line.name
            ),
        )
    } else {
        (
            Status::Unknown,
            format!(
                "the {} line is supported but the feed names no latest patch release, so the version cannot be compared.",
                line.name
            ),
        )
    };

    ProductResult {
        product: product.name.clone(),
        version: i.version.clone(),
        source: i.source.clone(),
        status,
        cycle: Some(line.name.clone()),
        eol_from: line.eol_from.clone(),
        latest,
        patches_behind,
        advice,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn rel(name: &str, eol: Option<&str>, is_eol: bool, latest: &str) -> Release {
        Release {
            name: name.into(),
            eol_from: eol.map(str::to_string),
            is_eol,
            latest: Some(latest.into()),
        }
    }

    fn data() -> Lifecycle {
        Lifecycle {
            updated_at: "2026-10-22T06:00:00Z".into(),
            products: vec![
                Product {
                    name: "php".into(),
                    aliases: vec!["php-fpm".into()],
                    releases: vec![
                        rel("8.4", Some("2028-12-31"), false, "8.4.26"),
                        rel("8.2", Some("2026-12-31"), false, "8.2.31"),
                        rel("7.4", Some("2022-11-28"), true, "7.4.33"),
                    ],
                },
                Product {
                    name: "nodejs".into(),
                    aliases: vec!["node".into()],
                    releases: vec![rel("22", Some("2027-04-30"), false, "22.11.0")],
                },
                Product {
                    name: "oldthing".into(),
                    aliases: vec![],
                    releases: vec![rel("1", Some("2020-01-01"), false, "1.9.9")],
                },
            ],
        }
    }

    fn php_feed() -> Vec<VendorLatest> {
        vec![VendorLatest {
            product: "php".into(),
            updated_at: "2026-10-22T06:00:00Z".into(),
            latest: BTreeMap::from([
                ("8.4".into(), "8.4.27".into()),
                ("8.2".into(), "8.2.35".into()),
            ]),
        }]
    }

    fn one(product: &str, version: &str, vendor: &[VendorLatest]) -> ProductResult {
        let i = Input {
            product: product.into(),
            version: version.into(),
            source: "given".into(),
        };
        evaluate(Some(&data()), vendor, &[i], "2026-10-22").remove(0)
    }

    #[test]
    fn php_7_4_33_is_end_of_life() {
        let r = one("php", "7.4.33", &php_feed());
        assert_eq!(r.status, Status::Eol);
        assert_eq!(r.cycle.as_deref(), Some("7.4"));
        assert_eq!(r.eol_from.as_deref(), Some("2022-11-28"));
        assert!(r.advice.contains("end of life"), "{}", r.advice);
        assert!(
            r.advice.contains("OS vendor"),
            "a distro may still patch an EOL line"
        );
    }

    #[test]
    fn a_vendor_feed_ahead_of_the_aggregator_wins() {
        // The aggregator still says 8.4.26 is the newest; php.net already shipped 8.4.27.
        let r = one("php", "8.4.26", &php_feed());
        assert_eq!(r.status, Status::Outdated);
        assert_eq!(r.latest.as_deref(), Some("8.4.27"));
        assert_eq!(r.patches_behind, Some(1));
        // Without the vendor feed the aggregator's own value is used.
        assert_eq!(one("php", "8.4.26", &[]).status, Status::Current);
    }

    #[test]
    fn counts_patch_releases_behind() {
        let r = one("php-fpm", "8.2.30", &php_feed());
        assert_eq!((r.status, r.patches_behind), (Status::Outdated, Some(5)));
        assert_eq!(r.product, "php", "alias resolves to the slug");
        let ok = one("php", "8.2.35", &php_feed());
        assert_eq!(ok.status, Status::Current);
    }

    #[test]
    fn a_past_eol_date_counts_even_when_the_flag_is_stale() {
        // The dataset was downloaded before the date arrived; `today` decides.
        let r = one("oldthing", "1.9.9", &[]);
        assert_eq!(r.status, Status::Eol);
    }

    #[test]
    fn unknowns_say_why_and_never_pass_as_current() {
        assert_eq!(
            one("nodejs", "18.0.0", &[]).status,
            Status::Unknown,
            "no 18 line in the data"
        );
        assert_eq!(one("nosuch", "1.0", &[]).status, Status::Unknown);
        let none = evaluate(
            None,
            &[],
            &[Input {
                product: "php".into(),
                version: "8.4.1".into(),
                source: "given".into(),
            }],
            "2026-10-22",
        );
        assert_eq!(none[0].status, Status::Unknown);
        assert!(none[0].advice.contains("opencraysec update"));
    }

    #[test]
    fn line_matching_respects_dotted_boundaries() {
        // `2` must not claim `22.11.0`, and `8.2` must not claim `8.20.1`.
        let p = Product {
            name: "x".into(),
            aliases: vec![],
            releases: vec![
                rel("2", None, false, "2.9"),
                rel("8.2", None, false, "8.2.9"),
            ],
        };
        assert!(line_of(&p, "22.11.0").is_none());
        assert!(line_of(&p, "8.20.1").is_none());
        assert_eq!(line_of(&p, "8.2.1").map(|r| r.name.as_str()), Some("8.2"));
        assert_eq!(line_of(&p, "2").map(|r| r.name.as_str()), Some("2"));
    }

    #[test]
    fn dotted_versions_compare_numerically() {
        assert_eq!(compare("8.4.9", "8.4.10"), Ordering::Less);
        assert_eq!(compare("8.2", "8.2.0"), Ordering::Equal);
        assert_eq!(compare("8.2.30-1+deb12u1", "8.2.30"), Ordering::Equal);
        assert_eq!(compare("v22.11.0", "22.9.9"), Ordering::Greater);
        assert_eq!(segments("7.4.33"), vec![7, 4, 33]);
        assert_eq!(segments("rc1"), Vec::<u64>::new());
    }
}
