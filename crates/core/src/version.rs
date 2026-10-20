//! Version ordering per ecosystem: semver (crates.io, npm, Go), a PEP 440 subset (PyPI) and
//! a Composer-flavoured semver (Packagist, where `RC` sorts above `beta`).

use std::cmp::Ordering;

use crate::model::Ecosystem;

/// Compares two version strings under the ordering rules of `eco`.
pub fn compare(eco: Ecosystem, a: &str, b: &str) -> Ordering {
    match eco {
        Ecosystem::PyPI => cmp_pep440(a, b),
        Ecosystem::Packagist => cmp_semver(a, b, true),
        _ => cmp_semver(a, b, false),
    }
}

struct Semver {
    core: Vec<u64>,
    pre: Option<Vec<String>>,
}

fn parse_semver(s: &str) -> Semver {
    let s = s.trim().trim_start_matches(['v', 'V']);
    let s = s.split('+').next().unwrap_or(s);
    let (core, pre) = match s.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (s, None),
    };
    Semver {
        core: core.split('.').map(|p| p.parse().unwrap_or(0)).collect(),
        pre: pre.map(|p| {
            p.split(['.', '-'])
                .filter(|x| !x.is_empty())
                .map(str::to_string)
                .collect()
        }),
    }
}

fn stability_rank(alpha: &str) -> u8 {
    match alpha.to_ascii_lowercase().as_str() {
        "dev" => 0,
        "alpha" | "a" => 1,
        "beta" | "b" => 2,
        "rc" => 3,
        "patch" | "p" | "pl" => 5,
        _ => 1,
    }
}

fn split_ident(id: &str) -> (&str, u64) {
    let cut = id.find(|c: char| c.is_ascii_digit()).unwrap_or(id.len());
    (&id[..cut], id[cut..].parse().unwrap_or(0))
}

fn cmp_ident(a: &str, b: &str, loose: bool) -> Ordering {
    if loose {
        let ((aa, an), (ba, bn)) = (split_ident(a), split_ident(b));
        return stability_rank(aa)
            .cmp(&stability_rank(ba))
            .then(an.cmp(&bn));
    }
    match (a.parse::<u64>(), b.parse::<u64>()) {
        (Ok(x), Ok(y)) => x.cmp(&y),
        (Ok(_), Err(_)) => Ordering::Less,
        (Err(_), Ok(_)) => Ordering::Greater,
        (Err(_), Err(_)) => a.cmp(b),
    }
}

fn is_patch(pre: &[String]) -> bool {
    pre.first()
        .is_some_and(|f| stability_rank(split_ident(f).0) == 5)
}

fn cmp_semver(a: &str, b: &str, loose: bool) -> Ordering {
    let (a, b) = (parse_semver(a), parse_semver(b));
    let n = a.core.len().max(b.core.len());
    for i in 0..n {
        let (x, y) = (
            a.core.get(i).copied().unwrap_or(0),
            b.core.get(i).copied().unwrap_or(0),
        );
        if x != y {
            return x.cmp(&y);
        }
    }
    match (&a.pre, &b.pre) {
        (None, None) => Ordering::Equal,
        (None, Some(p)) => {
            if loose && is_patch(p) {
                Ordering::Less
            } else {
                Ordering::Greater
            }
        }
        (Some(p), None) => {
            if loose && is_patch(p) {
                Ordering::Greater
            } else {
                Ordering::Less
            }
        }
        (Some(p), Some(q)) => {
            for (x, y) in p.iter().zip(q.iter()) {
                let o = cmp_ident(x, y, loose);
                if o != Ordering::Equal {
                    return o;
                }
            }
            p.len().cmp(&q.len())
        }
    }
}

struct Pep {
    epoch: u64,
    release: Vec<u64>,
    pre: Option<(u8, u64)>,
    post: Option<u64>,
    dev: Option<u64>,
}

fn take_number(r: &str) -> (u64, &str) {
    let end = r.find(|c: char| !c.is_ascii_digit()).unwrap_or(r.len());
    (r[..end].parse().unwrap_or(0), &r[end..])
}

fn parse_pep(s: &str) -> Pep {
    let lower = s.trim().to_ascii_lowercase();
    let s = lower.trim_start_matches('v');
    let s = s.split('+').next().unwrap_or(s);
    let (epoch, s) = match s.split_once('!') {
        Some((e, rest)) => (e.parse().unwrap_or(0), rest),
        None => (0, s),
    };
    let rel_end = {
        let mut end = 0;
        let bytes = s.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i].is_ascii_digit() {
                i += 1;
                end = i;
            } else if bytes[i] == b'.' && bytes.get(i + 1).is_some_and(u8::is_ascii_digit) {
                i += 1;
            } else {
                break;
            }
        }
        end
    };
    let mut release: Vec<u64> = s[..rel_end]
        .split('.')
        .map(|p| p.parse().unwrap_or(0))
        .collect();
    while release.len() > 1 && release.last() == Some(&0) {
        release.pop();
    }
    let mut p = Pep {
        epoch,
        release,
        pre: None,
        post: None,
        dev: None,
    };
    let mut rest = &s[rel_end..];
    loop {
        rest = rest.trim_start_matches(['.', '-', '_']);
        if rest.is_empty() {
            break;
        }
        let phases: [(&str, u8); 8] = [
            ("alpha", 0),
            ("beta", 1),
            ("preview", 2),
            ("pre", 2),
            ("rc", 2),
            ("a", 0),
            ("b", 1),
            ("c", 2),
        ];
        if let Some((name, phase)) = phases.iter().find(|(n, _)| rest.starts_with(n)) {
            let (n, r) = take_number(rest[name.len()..].trim_start_matches(['.', '-', '_']));
            p.pre = Some((*phase, n));
            rest = r;
        } else if let Some(r) = ["post", "rev", "r"]
            .iter()
            .find_map(|n| rest.strip_prefix(n))
        {
            let (n, r) = take_number(r.trim_start_matches(['.', '-', '_']));
            p.post = Some(n);
            rest = r;
        } else if let Some(r) = rest.strip_prefix("dev") {
            let (n, r) = take_number(r.trim_start_matches(['.', '-', '_']));
            p.dev = Some(n);
            rest = r;
        } else if rest.starts_with(|c: char| c.is_ascii_digit()) {
            let (n, r) = take_number(rest);
            p.post = Some(n);
            rest = r;
        } else {
            break;
        }
    }
    p
}

fn cmp_pep440(a: &str, b: &str) -> Ordering {
    let (a, b) = (parse_pep(a), parse_pep(b));
    let key = |p: &Pep| {
        let pre = match (p.pre, p.post, p.dev) {
            (None, None, Some(_)) => (-1_i32, 0_u64),
            (Some((ph, n)), _, _) => (i32::from(ph), n),
            (None, _, _) => (i32::MAX, 0),
        };
        (
            p.epoch,
            p.release.clone(),
            pre,
            p.post.map_or(-1_i64, |x| x as i64),
            p.dev.map_or(i64::MAX, |x| x as i64),
        )
    };
    key(&a).cmp(&key(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use Ecosystem::*;
    use std::cmp::Ordering::*;

    #[test]
    fn semver_basics() {
        assert_eq!(compare(CratesIo, "1.2.3", "1.2.10"), Less);
        assert_eq!(compare(Npm, "v2.0.0", "2.0.0"), Equal);
        assert_eq!(compare(Npm, "1.0.0-alpha", "1.0.0"), Less);
        assert_eq!(compare(Npm, "1.0.0-alpha.2", "1.0.0-alpha.10"), Less);
        assert_eq!(compare(Npm, "1.0.0-alpha.1", "1.0.0-alpha"), Greater);
        assert_eq!(compare(Npm, "1.0.0-1", "1.0.0-alpha"), Less);
        assert_eq!(compare(Go, "v1.5.0+incompatible", "v1.5.0"), Equal);
        assert_eq!(compare(Go, "v0.0.0-20200101-abcdef", "v0.1.0"), Less);
        assert_eq!(compare(CratesIo, "1.2", "1.2.0"), Equal);
    }

    #[test]
    fn composer_stability() {
        assert_eq!(compare(Packagist, "1.0.0-RC1", "1.0.0-beta2"), Greater);
        assert_eq!(compare(Packagist, "1.0.0-beta1", "1.0.0-alpha3"), Greater);
        assert_eq!(compare(Packagist, "1.0.0-RC1", "1.0.0"), Less);
        assert_eq!(compare(Packagist, "1.0.0-p1", "1.0.0"), Greater);
        assert_eq!(compare(Packagist, "v6.4.1", "6.4.0"), Greater);
    }

    #[test]
    fn pep440() {
        assert_eq!(compare(PyPI, "1.0", "1.0.0"), Equal);
        assert_eq!(compare(PyPI, "1.0rc1", "1.0"), Less);
        assert_eq!(compare(PyPI, "1.0.dev1", "1.0a1"), Less);
        assert_eq!(compare(PyPI, "1.0a1", "1.0b1"), Less);
        assert_eq!(compare(PyPI, "1.0b2", "1.0rc1"), Less);
        assert_eq!(compare(PyPI, "1.0", "1.0.post1"), Less);
        assert_eq!(compare(PyPI, "2.0", "1!1.0"), Less);
        assert_eq!(compare(PyPI, "1.10", "1.9"), Greater);
        assert_eq!(compare(PyPI, "1.0+local", "1.0"), Equal);
        assert_eq!(compare(PyPI, "1.0-1", "1.0.post1"), Equal);
    }
}
