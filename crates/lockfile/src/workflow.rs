//! GitHub Actions workflows: the actions a workflow runs, read from its `uses:` lines.
//!
//! A workflow has no lockfile, so the reference after the `@` is all there is. Only a full release
//! tag (`v4.1.2`) names a version an advisory can be matched against. A commit SHA is the safest
//! way to pin an action, but it names no version; a floating tag (`v4`) and a branch name move
//! under the workflow. None of those three can be checked, and each is reported as such, never
//! dropped.
//!
//! An action is matched by its repository (`owner/repo`): a subfolder action or a reusable workflow
//! in the same repository shares the repository's releases.

use opencraysec_core::{Ecosystem, Package};

/// How a `uses:` reference pins an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pin {
    /// A full release tag such as `v4.1.2`: a version.
    Release,
    /// A full commit SHA: immutable, but no version.
    Sha,
    /// A tag that follows the newest release of a line (`v4`, `v4.1`).
    Floating,
    /// Anything else: a branch name, which moves with every push.
    Branch,
}

/// An action reference that cannot be matched to a release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unmatched {
    /// `owner/repo`.
    pub name: String,
    /// The text after the `@`.
    pub reference: String,
    /// How it is pinned.
    pub pin: Pin,
}

/// What a workflow file yields.
#[derive(Debug, Default)]
pub struct Workflow {
    /// Actions pinned to a full release tag.
    pub packages: Vec<Package>,
    /// Actions that cannot be matched to a release.
    pub unmatched: Vec<Unmatched>,
}

fn is_sha(r: &str) -> bool {
    r.len() == 40 && r.chars().all(|c| c.is_ascii_hexdigit())
}

fn all_digits(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit())
}

/// The release version a tag names, when it is a full `MAJOR.MINOR.PATCH` (with an optional
/// prerelease or build part), without a leading `v`.
fn release_version(r: &str) -> Option<String> {
    let t = r.strip_prefix(['v', 'V']).unwrap_or(r);
    let core = t.split(['-', '+']).next().unwrap_or(t);
    let parts: Vec<&str> = core.split('.').collect();
    (parts.len() == 3 && parts.iter().all(|p| all_digits(p))).then(|| t.to_string())
}

/// Classifies the text after the `@` of a `uses:` reference.
pub fn classify(reference: &str) -> Pin {
    if is_sha(reference) {
        Pin::Sha
    } else if release_version(reference).is_some() {
        Pin::Release
    } else {
        let t = reference.strip_prefix(['v', 'V']).unwrap_or(reference);
        if !t.is_empty() && t.split('.').all(all_digits) {
            Pin::Floating
        } else {
            Pin::Branch
        }
    }
}

/// The value of a `uses:` key on this line, if it has one. Quotes and a trailing comment are removed.
fn uses_value(line: &str) -> Option<&str> {
    let t = line.trim_start();
    let t = t.strip_prefix('-').map_or(t, str::trim_start);
    let v = t.strip_prefix("uses:")?.trim();
    let v = v.split(" #").next().unwrap_or(v).trim();
    let v = v.trim_matches(['"', '\'']);
    (!v.is_empty()).then_some(v)
}

/// The action a `uses:` line names, as its repository (`owner/repo`) and the text after the `@`.
/// Local actions (`./...`), container images (`docker://...`) and references with no `@` are not
/// packages and give `None`.
pub fn uses_reference(line: &str) -> Option<(String, String)> {
    let value = uses_value(line)?;
    if value.starts_with('.') || value.starts_with("docker://") {
        return None;
    }
    let (path, reference) = value.rsplit_once('@')?;
    let mut parts = path.split('/');
    let (owner, repo) = (parts.next()?, parts.next()?);
    if owner.is_empty() || repo.is_empty() || reference.is_empty() {
        return None;
    }
    Some((format!("{owner}/{repo}"), reference.to_string()))
}

/// Reads the actions a workflow uses.
pub fn parse(text: &str, source: &str) -> Workflow {
    let mut out = Workflow::default();
    for line in text.lines() {
        let Some((name, reference)) = uses_reference(line) else {
            continue;
        };
        let reference = reference.as_str();
        match classify(reference) {
            Pin::Release => out.packages.push(Package {
                ecosystem: Ecosystem::GitHubActions,
                name,
                version: release_version(reference).unwrap_or_default(),
                source: source.to_string(),
                dev: false,
            }),
            pin => out.unmatched.push(Unmatched {
                name,
                reference: reference.to_string(),
                pin,
            }),
        }
    }
    out
}

/// One sentence about the references of a file that cannot be checked, or `None` when there are none.
pub fn unmatched_note(unmatched: &[Unmatched]) -> Option<String> {
    if unmatched.is_empty() {
        return None;
    }
    let count = |p: Pin| unmatched.iter().filter(|u| u.pin == p).count();
    let mut kinds: Vec<String> = Vec::new();
    for (pin, what) in [
        (Pin::Sha, "pinned by commit SHA"),
        (Pin::Floating, "on a floating tag"),
        (Pin::Branch, "on a branch"),
    ] {
        let n = count(pin);
        if n > 0 {
            kinds.push(format!("{n} {what}"));
        }
    }
    let mut names: Vec<String> = unmatched
        .iter()
        .map(|u| format!("{}@{}", u.name, u.reference))
        .collect();
    names.sort();
    names.dedup();
    let more = names.len().saturating_sub(5);
    names.truncate(5);
    Some(format!(
        "{} action(s) ({}) name no release version, so they were not checked against advisories: {}{}",
        unmatched.len(),
        kinds.join(", "),
        names.join(", "),
        if more > 0 {
            format!(", and {more} more")
        } else {
            String::new()
        }
    ))
}

/// True for a file that GitHub runs as a workflow: `.yml` or `.yaml` directly in `.github/workflows`.
pub fn is_workflow_path(path: &std::path::Path) -> bool {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);
    if !matches!(ext.as_deref(), Some("yml" | "yaml")) {
        return false;
    }
    let mut dirs = path.parent().into_iter().flat_map(|p| p.components().rev());
    let in_workflows = dirs.next().is_some_and(|c| c.as_os_str() == "workflows");
    in_workflows && dirs.next().is_some_and(|c| c.as_os_str() == ".github")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

    #[test]
    fn a_reference_is_a_release_a_sha_a_floating_tag_or_a_branch() {
        for (r, want) in [
            ("v4.1.2", Pin::Release),
            ("4.1.2", Pin::Release),
            ("v1.0.0-beta.1", Pin::Release),
            ("V2.3.4", Pin::Release),
            (SHA, Pin::Sha),
            ("v4", Pin::Floating),
            ("v4.1", Pin::Floating),
            ("4", Pin::Floating),
            ("main", Pin::Branch),
            ("release/v4", Pin::Branch),
            ("v4.1.x", Pin::Branch),
            ("0123456789abcdef0123456789abcdef0123456", Pin::Branch),
            ("v", Pin::Branch),
        ] {
            assert_eq!(classify(r), want, "{r}");
        }
        assert_eq!(
            release_version("v4.1.2-rc.1+b5"),
            Some("4.1.2-rc.1+b5".to_string())
        );
        assert_eq!(release_version("v4.1"), None);
    }

    #[test]
    fn uses_lines_are_read_whatever_the_yaml_style() {
        for (line, want) in [
            (
                "      - uses: actions/checkout@v4",
                Some(("actions/checkout", "v4")),
            ),
            (
                "    uses: \"org/Repo/sub/dir@v1.2.3\" # note",
                Some(("org/Repo", "v1.2.3")),
            ),
            ("- uses: 'a/b@main'", Some(("a/b", "main"))),
            (
                "  uses: org/repo/.github/workflows/x.yml@v2.0.0",
                Some(("org/repo", "v2.0.0")),
            ),
            ("  uses: ./.github/actions/local", None),
            ("  uses: ../shared", None),
            ("  uses: docker://alpine:3.19", None),
            ("  uses: org/repo", None),
            ("  uses: justone@v1", None),
            ("  uses: org/@v1", None),
            ("  uses: org/repo@", None),
            ("  uses:", None),
            ("  name: uses: x/y@v1", None),
            ("  # uses: x/y@v1", None),
            ("  run: echo uses: x/y@v1", None),
        ] {
            assert_eq!(
                uses_reference(line)
                    .as_ref()
                    .map(|(n, r)| (n.as_str(), r.as_str())),
                want,
                "{line}"
            );
        }
    }

    #[test]
    fn a_workflow_gives_its_pinned_actions_and_names_the_ones_it_cannot_match() {
        let text = format!(
            "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4.2.1\n      - uses: actions/checkout@v4.2.1\n      - uses: org/tool/sub@v1.0.0\n      - uses: a/sha@{SHA}\n      - uses: b/float@v3\n      - uses: c/branch@main\n      - uses: ./local\n"
        );
        let w = parse(&text, ".github/workflows/ci.yml");
        let names: Vec<(&str, &str, &str)> = w
            .packages
            .iter()
            .map(|p| (p.name.as_str(), p.version.as_str(), p.source.as_str()))
            .collect();
        assert_eq!(
            names,
            vec![
                ("actions/checkout", "4.2.1", ".github/workflows/ci.yml"),
                ("actions/checkout", "4.2.1", ".github/workflows/ci.yml"),
                ("org/tool", "1.0.0", ".github/workflows/ci.yml")
            ],
            "a subfolder action is matched by its repository; duplicates are the caller's to merge"
        );
        assert!(
            w.packages
                .iter()
                .all(|p| p.ecosystem == Ecosystem::GitHubActions && !p.dev)
        );
        let pins: Vec<Pin> = w.unmatched.iter().map(|u| u.pin).collect();
        assert_eq!(pins, vec![Pin::Sha, Pin::Floating, Pin::Branch]);
    }

    #[test]
    fn the_note_for_unmatched_actions_counts_each_kind_and_cuts_a_long_list() {
        assert_eq!(unmatched_note(&[]), None);
        let one = |name: &str, r: &str| Unmatched {
            name: name.into(),
            reference: r.into(),
            pin: classify(r),
        };
        let note = unmatched_note(&[
            one("a/b", SHA),
            one("c/d", "v1"),
            one("e/f", "main"),
            one("g/h", "v2"),
        ])
        .expect("note");
        assert!(
            note.starts_with(
                "4 action(s) (1 pinned by commit SHA, 2 on a floating tag, 1 on a branch)"
            ),
            "{note}"
        );
        assert!(
            note.contains("e/f@main") && note.contains("a/b@0123456789abcdef"),
            "{note}"
        );
        let many: Vec<Unmatched> = (0..8).map(|i| one(&format!("o/r{i}"), "main")).collect();
        let note = unmatched_note(&many).expect("note");
        assert!(note.contains(", and 3 more"), "{note}");
        let same = unmatched_note(&[one("a/b", "main"), one("a/b", "main")]).expect("note");
        assert!(
            same.starts_with("2 action(s)") && !same.contains("more"),
            "{same}"
        );
    }

    #[test]
    fn only_yaml_directly_in_github_workflows_is_a_workflow() {
        for (path, want) in [
            (".github/workflows/ci.yml", true),
            ("a/b/.github/workflows/ci.yaml", true),
            (".github/workflows/CI.YML", true),
            (".github/workflows/ci.md", false),
            (".github/workflows/sub/ci.yml", false),
            ("workflows/ci.yml", false),
            (".github/ci.yml", false),
            (".gitlab/workflows/ci.yml", false),
            ("ci.yml", false),
        ] {
            assert_eq!(is_workflow_path(Path::new(path)), want, "{path}");
        }
    }
}
