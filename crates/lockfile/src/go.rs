use std::collections::BTreeSet;

use opencraysec_core::{Ecosystem, Package};

use crate::pkg;

/// `go.mod`: every `require`d module at its selected version.
pub fn go_mod(text: &str, source: &str) -> Vec<Package> {
    let mut out = Vec::new();
    let mut in_block = false;
    for raw in text.lines() {
        let line = raw.split("//").next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let body = if in_block {
            if line == ")" {
                in_block = false;
                continue;
            }
            line
        } else if let Some(rest) = line.strip_prefix("require") {
            let rest = rest.trim();
            if rest == "(" {
                in_block = true;
                continue;
            }
            rest
        } else {
            continue;
        };
        let mut it = body.split_whitespace();
        if let (Some(name), Some(version)) = (it.next(), it.next())
            && version.starts_with('v')
        {
            out.push(pkg(Ecosystem::Go, name, version, source, false));
        }
    }
    out
}

/// `go.sum`: used only when there is no `go.mod`; the `/go.mod` hash lines are ignored.
pub fn go_sum(text: &str, source: &str) -> Vec<Package> {
    let mut seen = BTreeSet::new();
    for line in text.lines() {
        let mut it = line.split_whitespace();
        if let (Some(name), Some(version)) = (it.next(), it.next())
            && !version.ends_with("/go.mod")
        {
            seen.insert((name.to_string(), version.to_string()));
        }
    }
    seen.into_iter()
        .map(|(n, v)| pkg(Ecosystem::Go, &n, &v, source, false))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mod_block_and_single() {
        let t = "module x\n\ngo 1.22\n\nrequire github.com/a/b v1.2.3\n\nrequire (\n\tgolang.org/x/net v0.17.0 // indirect\n\tgithub.com/c/d v0.0.0-2020-abc\n)\n";
        let p = go_mod(t, "go.mod");
        assert_eq!(p.len(), 3);
        assert_eq!(p[1].name, "golang.org/x/net");
        assert_eq!(p[1].version, "v0.17.0");
    }

    #[test]
    fn sum_skips_gomod_lines() {
        let t = "a/b v1.0.0 h1:xx=\na/b v1.0.0/go.mod h1:yy=\n";
        assert_eq!(go_sum(t, "go.sum").len(), 1);
    }
}
