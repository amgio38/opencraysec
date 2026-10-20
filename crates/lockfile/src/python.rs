use opencraysec_core::{Ecosystem, Package};

use crate::pkg;

fn py(name: &str, version: &str, source: &str, dev: bool) -> Package {
    pkg(
        Ecosystem::PyPI,
        &Ecosystem::PyPI.normalize_name(name),
        version,
        source,
        dev,
    )
}

/// `poetry.lock` / `uv.lock`: `[[package]]` tables. Local (editable, virtual, path) packages are skipped.
pub fn toml_lock(text: &str, source: &str, uv: bool) -> Result<Vec<Package>, String> {
    let v: toml::Value = toml::from_str(text).map_err(|e| format!("invalid lockfile: {e}"))?;
    let mut out = Vec::new();
    for p in v
        .get("package")
        .and_then(|p| p.as_array())
        .into_iter()
        .flatten()
    {
        let (Some(name), Some(version)) = (
            p.get("name").and_then(|x| x.as_str()),
            p.get("version").and_then(|x| x.as_str()),
        ) else {
            continue;
        };
        if uv {
            let registry = p.get("source").and_then(|s| s.get("registry")).is_some();
            if !registry {
                continue;
            }
        }
        let dev = p.get("category").and_then(|c| c.as_str()) == Some("dev");
        out.push(py(name, version, source, dev));
    }
    Ok(out)
}

/// `Pipfile.lock`: `default` and `develop` sections with `==` pins.
pub fn pipfile_lock(text: &str, source: &str) -> Result<Vec<Package>, String> {
    let v: serde_json::Value =
        serde_json::from_str(text).map_err(|e| format!("invalid Pipfile.lock: {e}"))?;
    let mut out = Vec::new();
    for (key, dev) in [("default", false), ("develop", true)] {
        let Some(map) = v.get(key).and_then(|x| x.as_object()) else {
            continue;
        };
        for (name, info) in map {
            if let Some(ver) = info.get("version").and_then(|x| x.as_str())
                && let Some(ver) = ver.strip_prefix("==")
            {
                out.push(py(name, ver, source, dev));
            }
        }
    }
    Ok(out)
}

/// What one `requirements*.txt` line means for a scan.
enum Requirement<'a> {
    /// Blank, comment or a pip option that names no package (`--index-url`, `--hash`).
    Ignored,
    /// An exact `name==version` pin.
    Pinned(&'a str, &'a str),
    /// A dependency the scan cannot check: a range, a VCS or URL requirement, an editable install.
    Unchecked,
    /// `-r other.txt`: more requirements live in that file. It is only unchecked when that file is
    /// not itself scanned, which the caller decides.
    Include(&'a str),
}

fn classify(raw: &str) -> Requirement<'_> {
    let line = raw
        .split(" #")
        .next()
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .trim_end_matches('\\')
        .trim();
    if line.is_empty() || line.starts_with('#') {
        return Requirement::Ignored;
    }
    if let Some(option) = line.strip_prefix('-') {
        // `-r file`, `-rfile`, `-e .`, `-e.`, `--requirement=file`: the value follows the option
        // letter or name with or without a separator.
        let (name, value) = match option.strip_prefix('-') {
            Some(long) => {
                let (n, v) = long.split_once([' ', '=']).unwrap_or((long, ""));
                (n, v.trim())
            }
            None => {
                let mut chars = option.chars();
                let letter = chars.next().map_or(0, char::len_utf8);
                (&option[..letter], chars.as_str().trim())
            }
        };
        return match name {
            "r" | "requirement" if !value.is_empty() => Requirement::Include(value),
            "r" | "requirement" | "e" | "editable" => Requirement::Unchecked,
            // A constraints file only limits versions; it adds no dependency to check.
            "c" | "constraint" => Requirement::Ignored,
            // `--index-url https://x flask==1.0` puts a requirement on an option line. It is not
            // parsed (the option's own value would have to be told apart), but it is not dropped.
            _ if ["==", ">=", "<=", "~=", "!="]
                .iter()
                .any(|op| line.contains(op)) =>
            {
                Requirement::Unchecked
            }
            _ => Requirement::Ignored,
        };
    }
    // `name==1.0 --hash=sha256:...` (pip-compile --generate-hashes): options after the pin are not
    // part of the version.
    let line = line.split(" --").next().unwrap_or(line).trim();
    let Some((name, ver)) = line.split_once("==") else {
        return Requirement::Unchecked;
    };
    let name = name.split('[').next().unwrap_or(name).trim();
    // `===` is PEP 440 arbitrary equality; the version follows it.
    let ver = ver.trim().trim_start_matches('=');
    if !name.is_empty() && !ver.is_empty() && !ver.contains([',', ' ', '*']) {
        Requirement::Pinned(name, ver)
    } else {
        Requirement::Unchecked
    }
}

/// `requirements*.txt`: only exact `name==version` pins can be matched.
pub fn requirements(text: &str, source: &str) -> Vec<Package> {
    text.lines()
        .filter_map(|raw| match classify(raw) {
            Requirement::Pinned(name, ver) => Some(py(name, ver, source, false)),
            _ => None,
        })
        .collect()
}

/// How many requirement lines [`requirements`] could not check (ranges, URLs, editable installs).
/// `-r` includes are not counted here: see [`requirements_includes`].
pub fn requirements_unchecked(text: &str) -> usize {
    text.lines()
        .filter(|raw| matches!(classify(raw), Requirement::Unchecked))
        .count()
}

/// The files named by `-r`/`--requirement` lines, as written.
pub fn requirements_includes(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|raw| match classify(raw) {
            Requirement::Include(target) => Some(target.to_string()),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requirements_pins_only() {
        let t = "# c\nDjango==3.2.0\nrequests[security]==2.0 ; python_version>'3'\nflask>=2\n-r other.txt\nfoo==1.*\n";
        let p = requirements(t, "requirements.txt");
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].name, "django");
        assert_eq!(p[1].name, "requests");
        // `flask>=2` and `foo==1.*` were not checked; `-r other.txt` is reported as an include.
        assert_eq!(requirements_unchecked(t), 2);
        assert_eq!(requirements_includes(t), vec!["other.txt".to_string()]);
    }

    #[test]
    fn requirement_options_and_hashes() {
        // Options that name no package are not packages; includes and VCS lines are unchecked.
        let skipped = "--index-url https://x\n-i https://y\n--no-binary :all:\n";
        assert_eq!(requirements_unchecked(skipped), 0);
        for line in [
            "-e .",
            "-e.",
            "--editable ./pkg",
            "git+https://x/y.git",
            "-r",
            "--requirement=",
        ] {
            assert_eq!(requirements_unchecked(line), 1, "{line}");
            assert!(requirements_includes(line).is_empty(), "{line}");
            assert!(requirements(line, "r.txt").is_empty(), "{line}");
        }
        // Includes name the file; a constraints file adds nothing to check.
        for (line, target) in [
            ("-r other.txt", "other.txt"),
            ("-rother.txt", "other.txt"),
            ("-r  ../base/requirements.txt", "../base/requirements.txt"),
            ("--requirement=a.txt", "a.txt"),
            ("--requirement a.txt", "a.txt"),
        ] {
            assert_eq!(
                requirements_includes(line),
                vec![target.to_string()],
                "{line}"
            );
            assert_eq!(requirements_unchecked(line), 0, "{line}");
        }
        for line in [
            "-c c.txt",
            "-cc.txt",
            "--constraint c.txt",
            "--constraint=c.txt",
        ] {
            assert_eq!(requirements_unchecked(line), 0, "{line}");
            assert!(requirements_includes(line).is_empty(), "{line}");
        }
        // pip-compile --generate-hashes output is a normal pin; its hash lines are options.
        let hashed = "django==4.2.0 \\\n    --hash=sha256:aa \\\n    --hash=sha256:bb\nrequests==2.0 --hash=sha256:cc\n";
        let p = requirements(hashed, "requirements.txt");
        assert_eq!(
            p.iter()
                .map(|x| (x.name.as_str(), x.version.as_str()))
                .collect::<Vec<_>>(),
            vec![("django", "4.2.0"), ("requests", "2.0")]
        );
        assert_eq!(requirements_unchecked(hashed), 0);
        // A requirement on an option line is reported, not silently dropped.
        assert_eq!(
            requirements_unchecked("--index-url https://x flask==1.0\n"),
            1
        );
        assert_eq!(requirements_unchecked("--extra-index-url https://x\n"), 0);
        // PEP 440 arbitrary equality.
        let p = requirements("urllib3===1.24.1\n", "r.txt");
        assert_eq!(p[0].version, "1.24.1");
    }

    #[test]
    fn poetry_and_uv() {
        let poetry = "[[package]]\nname = \"Jinja2\"\nversion = \"2.11.0\"\ncategory = \"dev\"\n";
        let p = toml_lock(poetry, "poetry.lock", false).expect("parses");
        assert_eq!((p[0].name.as_str(), p[0].dev), ("jinja2", true));
        let uv = "[[package]]\nname = \"a\"\nversion = \"1\"\nsource = { registry = \"https://pypi.org/simple\" }\n[[package]]\nname = \"me\"\nversion = \"0\"\nsource = { editable = \".\" }\n";
        assert_eq!(toml_lock(uv, "uv.lock", true).expect("parses").len(), 1);
    }

    #[test]
    fn pipfile() {
        let t = r#"{"default":{"requests":{"version":"==2.19.0"}},"develop":{"x":{"git":"u"}}}"#;
        let p = pipfile_lock(t, "Pipfile.lock").expect("parses");
        assert_eq!(p.len(), 1);
    }
}
