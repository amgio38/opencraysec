//! CVSS v3.x base score from a vector string. v2 and v4 vectors are not scored.

fn roundup(x: f64) -> f64 {
    let int = (x * 100_000.0).round() as i64;
    if int % 10_000 == 0 {
        int as f64 / 100_000.0
    } else {
        ((int / 10_000) + 1) as f64 / 10.0
    }
}

/// Base score (0.0 to 10.0) for a `CVSS:3.0/...` or `CVSS:3.1/...` vector, or `None`.
pub fn base_score(vector: &str) -> Option<f32> {
    let mut parts = vector.split('/');
    let head = parts.next()?;
    if head != "CVSS:3.0" && head != "CVSS:3.1" {
        return None;
    }
    let (mut av, mut ac, mut pr, mut ui, mut s, mut c, mut i, mut a) =
        (None, None, None, None, None, None, None, None);
    for part in parts {
        let (k, v) = part.split_once(':')?;
        let v = v.chars().next()?;
        match k {
            "AV" => av = Some(v),
            "AC" => ac = Some(v),
            "PR" => pr = Some(v),
            "UI" => ui = Some(v),
            "S" => s = Some(v),
            "C" => c = Some(v),
            "I" => i = Some(v),
            "A" => a = Some(v),
            _ => {}
        }
    }
    let changed = match s? {
        'U' => false,
        'C' => true,
        _ => return None,
    };
    let av = match av? {
        'N' => 0.85,
        'A' => 0.62,
        'L' => 0.55,
        'P' => 0.2,
        _ => return None,
    };
    let ac = match ac? {
        'L' => 0.77,
        'H' => 0.44,
        _ => return None,
    };
    let pr = match (pr?, changed) {
        ('N', _) => 0.85,
        ('L', false) => 0.62,
        ('L', true) => 0.68,
        ('H', false) => 0.27,
        ('H', true) => 0.5,
        _ => return None,
    };
    let ui = match ui? {
        'N' => 0.85,
        'R' => 0.62,
        _ => return None,
    };
    let cia = |m: Option<char>| -> Option<f64> {
        match m? {
            'H' => Some(0.56),
            'L' => Some(0.22),
            'N' => Some(0.0),
            _ => None,
        }
    };
    let (c, i, a) = (cia(c)?, cia(i)?, cia(a)?);
    let iss: f64 = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a);
    let impact = if changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15)
    } else {
        6.42 * iss
    };
    if impact <= 0.0 {
        return Some(0.0);
    }
    let expl = 8.22 * av * ac * pr * ui;
    let raw: f64 = if changed {
        1.08 * (impact + expl)
    } else {
        impact + expl
    };
    Some(roundup(raw.min(10.0)) as f32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_scores() {
        assert_eq!(
            base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            Some(9.8)
        );
        assert_eq!(
            base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
            Some(6.1)
        );
        assert_eq!(
            base_score("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"),
            Some(5.5)
        );
        assert_eq!(
            base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
            Some(0.0)
        );
    }

    #[test]
    fn every_privilege_and_scope_combination_is_scored() {
        let v = |pr: &str, s: &str| format!("CVSS:3.0/AV:A/AC:H/PR:{pr}/UI:R/S:{s}/C:L/I:L/A:L");
        let scores: Vec<Option<f32>> = [("N", "U"), ("L", "U"), ("H", "U"), ("L", "C"), ("H", "C")]
            .iter()
            .map(|(pr, s)| base_score(&v(pr, s)))
            .collect();
        assert!(scores.iter().all(|s| s.is_some()), "{scores:?}");
        let (n, l, h) = (
            scores[0].expect("n"),
            scores[1].expect("l"),
            scores[2].expect("h"),
        );
        assert!(
            n > l && l > h,
            "more privileges required means a lower score"
        );
        assert!(scores[3].expect("lc") > l, "a changed scope scores higher");
        assert_eq!(
            base_score("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"),
            Some(1.6)
        );
    }

    #[test]
    fn rejects_each_malformed_metric() {
        let ok = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
        assert!(base_score(ok).is_some());
        for (from, to) in [
            ("AV:N", "AV:Z"),
            ("AC:L", "AC:Z"),
            ("PR:N", "PR:Z"),
            ("UI:N", "UI:Z"),
            ("S:U", "S:Z"),
            ("C:H", "C:Z"),
            ("I:H", "I:Z"),
            ("A:H", "A:Z"),
            ("AV:N", "AV"),
        ] {
            assert_eq!(base_score(&ok.replace(from, to)), None, "{to}");
        }
        for missing in ["AV:N/", "AC:L/", "PR:N/", "UI:N/", "S:U/", "C:H/", "I:H/"] {
            assert_eq!(
                base_score(&ok.replace(missing, "")),
                None,
                "without {missing}"
            );
        }
        assert_eq!(base_score(""), None);
    }

    #[test]
    fn rejects_other_versions_and_garbage() {
        assert_eq!(base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N"), None);
        assert_eq!(base_score("AV:N/AC:L/Au:N/C:P/I:P/A:P"), None);
        assert_eq!(base_score("CVSS:3.1/AV:N"), None);
        assert_eq!(
            base_score("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            None
        );
    }
}
