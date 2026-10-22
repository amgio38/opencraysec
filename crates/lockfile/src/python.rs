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

/// The dependencies a `pyproject.toml` declares.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PyProject {
    /// Exact `name==version` pins: the only dependencies an advisory can be matched against.
    pub pinned: Vec<(String, String)>,
    /// The names of dependencies with no exact pin (a range, a bare version, a URL, a path).
    pub others: Vec<String>,
}

/// The name at the start of a requirement string (`requests[socks]>=2` gives `requests`).
fn requirement_name(spec: &str) -> &str {
    let spec = spec.trim();
    let end = spec
        .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')))
        .unwrap_or(spec.len());
    &spec[..end]
}

fn add_requirement(out: &mut PyProject, spec: &str) {
    let name = requirement_name(spec);
    if name.is_empty() {
        return;
    }
    match classify(spec) {
        Requirement::Pinned(n, v) => out.pinned.push((n.to_string(), v.to_string())),
        _ => out.others.push(name.to_string()),
    }
}

fn add_array(out: &mut PyProject, value: Option<&toml::Value>) {
    for item in value.and_then(|v| v.as_array()).into_iter().flatten() {
        if let Some(spec) = item.as_str() {
            add_requirement(out, spec);
        }
    }
}

/// A Poetry dependency table: `name = "^1.2"`, or `name = { version = "==1.2.3" }`. Only an exact
/// `==` pin is read as one; a bare version is not, because Poetry's own reading of it is not ours to guess.
fn add_poetry_table(out: &mut PyProject, table: Option<&toml::Value>) {
    for (name, value) in table.and_then(|t| t.as_table()).into_iter().flatten() {
        if name == "python" {
            continue;
        }
        let version = value
            .as_str()
            .or_else(|| value.get("version").and_then(|v| v.as_str()));
        match version {
            Some(v) if v.trim_start().starts_with("==") => {
                add_requirement(out, &format!("{name}{}", v.trim()));
            }
            _ => out.others.push(name.clone()),
        }
    }
}

/// `pyproject.toml`: the dependencies of `[project]` (PEP 621), its optional groups, the
/// `[dependency-groups]` (PEP 735), `[build-system] requires` and Poetry's tables. Environment markers
/// and extras are ignored. Nothing here resolves a range: only an exact `==` pin is matchable.
pub fn pyproject_dependencies(text: &str) -> Result<PyProject, String> {
    let doc: toml::Value =
        toml::from_str(text).map_err(|e| format!("invalid pyproject.toml: {e}"))?;
    let mut out = PyProject::default();
    add_array(
        &mut out,
        doc.get("project").and_then(|p| p.get("dependencies")),
    );
    for (_, group) in doc
        .get("project")
        .and_then(|p| p.get("optional-dependencies"))
        .and_then(|t| t.as_table())
        .into_iter()
        .flatten()
    {
        add_array(&mut out, Some(group));
    }
    for (_, group) in doc
        .get("dependency-groups")
        .and_then(|t| t.as_table())
        .into_iter()
        .flatten()
    {
        add_array(&mut out, Some(group));
    }
    add_array(
        &mut out,
        doc.get("build-system").and_then(|b| b.get("requires")),
    );
    let poetry = doc.get("tool").and_then(|t| t.get("poetry"));
    add_poetry_table(&mut out, poetry.and_then(|p| p.get("dependencies")));
    add_poetry_table(&mut out, poetry.and_then(|p| p.get("dev-dependencies")));
    for (_, group) in poetry
        .and_then(|p| p.get("group"))
        .and_then(|g| g.as_table())
        .into_iter()
        .flatten()
    {
        add_poetry_table(&mut out, group.get("dependencies"));
    }
    out.pinned.sort();
    out.pinned.dedup();
    out.others.sort();
    out.others.dedup();
    Ok(out)
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

    #[test]
    fn pyproject_pins_are_matchable_and_everything_else_is_named() {
        let t = r#"
[build-system]
requires = ["setuptools==68.0.0", "wheel"]

[project]
name = "demo"
dependencies = [
  "requests==2.31.0",
  "flask>=2.0",
  "Django[argon2]==4.2.1 ; python_version >= '3.9'",
  "click",
  "pkg @ https://example.invalid/pkg.whl",
  "wild==1.*",
  "multi==1.0,<2",
]

[project.optional-dependencies]
docs = ["sphinx==7.0.0"]
test = ["pytest~=7.0"]

[dependency-groups]
dev = ["ruff==0.1.0", { include-group = "docs" }]
"#;
        let p = pyproject_dependencies(t).expect("parses");
        assert_eq!(
            p.pinned,
            vec![
                ("Django".to_string(), "4.2.1".to_string()),
                ("requests".to_string(), "2.31.0".to_string()),
                ("ruff".to_string(), "0.1.0".to_string()),
                ("setuptools".to_string(), "68.0.0".to_string()),
                ("sphinx".to_string(), "7.0.0".to_string()),
            ],
            "extras and environment markers do not stop an exact pin from being one"
        );
        assert_eq!(
            p.others,
            vec!["click", "flask", "multi", "pkg", "pytest", "wheel", "wild"],
            "a range, a bare name, a URL, a wildcard and a pin with a second bound are named, not dropped"
        );
    }

    #[test]
    fn poetry_tables_give_an_exact_pin_only_for_a_double_equals() {
        let t = r#"
[tool.poetry.dependencies]
python = "^3.10"
exact = "==1.2.3"
caret = "^2.0"
bare = "1.2.3"
tabled = { version = "==4.5.6", extras = ["x"] }
ranged = { version = ">=1", optional = true }
gitdep = { git = "https://example.invalid/r.git" }

[tool.poetry.group.dev.dependencies]
devexact = "==0.1.0"

[tool.poetry.dev-dependencies]
olddev = "^1"
"#;
        let p = pyproject_dependencies(t).expect("parses");
        assert_eq!(
            p.pinned,
            vec![
                ("devexact".to_string(), "0.1.0".to_string()),
                ("exact".to_string(), "1.2.3".to_string()),
                ("tabled".to_string(), "4.5.6".to_string()),
            ]
        );
        assert_eq!(
            p.others,
            vec!["bare", "caret", "gitdep", "olddev", "ranged"]
        );
    }

    #[test]
    fn a_pyproject_with_no_dependencies_or_with_broken_toml_is_told_apart() {
        assert_eq!(
            pyproject_dependencies("[project]\nname = \"x\"\n").expect("parses"),
            PyProject::default()
        );
        assert_eq!(
            pyproject_dependencies("").expect("empty parses"),
            PyProject::default()
        );
        let err = pyproject_dependencies("[project\nname = ").expect_err("broken");
        assert!(err.starts_with("invalid pyproject.toml"), "{err}");
        assert_eq!(requirement_name("requests[socks]>=2"), "requests");
        assert_eq!(requirement_name("  a.b_c-d==1"), "a.b_c-d");
        assert_eq!(requirement_name("==1"), "");
        let mut out = PyProject::default();
        add_requirement(&mut out, "==1");
        assert_eq!(
            out,
            PyProject::default(),
            "a requirement with no name adds nothing"
        );
    }
}
