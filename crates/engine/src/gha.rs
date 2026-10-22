//! Rules of `scan-code` for GitHub Actions workflows (`.github/workflows/*.yml`).
//!
//! The first-hand sources are GitHub's [security hardening guide] and the GitHub Security Lab
//! articles on [untrusted input] and [pwn requests]; `docs/LANGUAGES.md` quotes what each rule
//! rests on. The OWASP Top 10 CI/CD Security Risks entry that fits best is named for each rule.
//!
//! These are patterns read line by line, so every hit is *suspected*. A workflow is YAML and is not
//! parsed: a `run:` block is found by its indentation, and the triggers of a file are found by
//! looking for their names.
//!
//! [security hardening guide]: https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions
//! [untrusted input]: https://securitylab.github.com/resources/github-actions-untrusted-input/
//! [pwn requests]: https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/

use opencraysec_core::Severity;
use opencraysec_lockfile::workflow::{Pin, classify, uses_reference};

use crate::code::{CodeFinding, ignored_at as ignored};

/// One rule: what it looks for and the entry that fits it best.
pub(crate) struct GhaRule {
    pub(crate) id: &'static str,
    pub(crate) title: &'static str,
    pub(crate) severity: Severity,
    pub(crate) cwe: &'static str,
    pub(crate) advice: &'static str,
}

pub(crate) const RULES: &[GhaRule] = &[
    GhaRule {
        id: "gha-script-injection",
        title: "A run script has text an outsider controls pasted into it (an issue or pull request title or body, a branch name, a commit message)",
        severity: Severity::High,
        cwe: "CWE-78",
        advice: "Do not put the expression in the script. Set it as an environment variable (env: TITLE: ${{ ... }}) and read \"$TITLE\" in the script (OWASP CICD-SEC-4 Poisoned Pipeline Execution).",
    },
    GhaRule {
        id: "gha-pwn-request",
        title: "A workflow that runs with the target repository's secrets and write access checks out the pull request's own code",
        severity: Severity::High,
        cwe: "CWE-829",
        advice: "Do not check out or run a pull request's code in a pull_request_target or workflow_run workflow. Build it in an unprivileged pull_request workflow and pass only data on (OWASP CICD-SEC-4 Poisoned Pipeline Execution).",
    },
    GhaRule {
        id: "gha-workflow-run-artifact",
        title: "A workflow_run workflow downloads an artifact that a pull request's workflow may have made",
        severity: Severity::Medium,
        cwe: "CWE-829",
        advice: "Treat the artifact as untrusted input: read it as data, never run it, and check what it holds (OWASP CICD-SEC-4 Poisoned Pipeline Execution).",
    },
    GhaRule {
        id: "gha-unpinned-action",
        title: "An action is not pinned to a full commit SHA, so its author can change what runs",
        severity: Severity::Low,
        cwe: "CWE-1357",
        advice: "Pin the action to the full commit SHA of the release you reviewed, and note the tag in a comment (OWASP CICD-SEC-3 Dependency Chain Abuse).",
    },
    GhaRule {
        id: "gha-broad-permissions",
        title: "A workflow or job gives the token every permission (permissions: write-all)",
        severity: Severity::Medium,
        cwe: "CWE-250",
        advice: "List only the permissions the job needs (for example contents: read) (OWASP CICD-SEC-5 Insufficient PBAC).",
    },
];

/// The OWASP Top 10 CI/CD Security Risks entry that fits each rule best. It is named in each rule's
/// advice, which is what a report shows; a test keeps the docs in step with this table.
#[cfg(test)]
pub(crate) const OWASP: &[(&str, &str)] = &[
    ("gha-script-injection", "CICD-SEC-4"),
    ("gha-pwn-request", "CICD-SEC-4"),
    ("gha-workflow-run-artifact", "CICD-SEC-4"),
    ("gha-unpinned-action", "CICD-SEC-3"),
    ("gha-broad-permissions", "CICD-SEC-5"),
];

fn rule(id: &str) -> &'static GhaRule {
    RULES
        .iter()
        .find(|r| r.id == id)
        .unwrap_or_else(|| unreachable!("unknown workflow rule {id}"))
}

fn finding(id: &str, rel: &str, line: usize, detail: Option<String>) -> CodeFinding {
    let r = rule(id);
    CodeFinding {
        rule: r.id.into(),
        title: match detail {
            Some(d) => format!("{} ({d})", r.title),
            None => r.title.into(),
        },
        cwe: r.cwe.into(),
        severity: r.severity,
        file: rel.into(),
        line,
        snippet: String::new(),
        confidence: "suspected".into(),
        advice: r.advice.into(),
        source: "builtin".into(),
    }
}

/// True when the context an expression reads can be set by someone who does not control the
/// repository: the list in GitHub Security Lab's article on untrusted input.
fn untrusted_context(expr: &str) -> bool {
    let compact: String = expr.chars().filter(|c| !c.is_whitespace()).collect();
    if !compact.starts_with("github.") {
        return false;
    }
    // `commits[0].message` and `commits.*.message` name the same thing.
    let mut e = String::with_capacity(compact.len());
    let mut chars = compact.chars();
    while let Some(c) = chars.next() {
        if c == '[' {
            for d in chars.by_ref() {
                if d == ']' {
                    break;
                }
            }
            e.push_str(".*");
        } else {
            e.push(c);
        }
    }
    const UNTRUSTED: &[&str] = &[
        "github.event.issue.title",
        "github.event.issue.body",
        "github.event.pull_request.title",
        "github.event.pull_request.body",
        "github.event.comment.body",
        "github.event.review.body",
        "github.event.pages.*.page_name",
        "github.event.commits.*.message",
        "github.event.head_commit.message",
        "github.event.head_commit.author.email",
        "github.event.head_commit.author.name",
        "github.event.commits.*.author.email",
        "github.event.commits.*.author.name",
        "github.event.pull_request.head.ref",
        "github.event.pull_request.head.label",
        "github.event.pull_request.head.repo.default_branch",
        "github.head_ref",
    ];
    UNTRUSTED.contains(&e.as_str())
}

/// The `${{ ... }}` expressions on a line.
fn expressions(line: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = line;
    while let Some(start) = rest.find("${{") {
        let after = &rest[start + 3..];
        let Some(end) = after.find("}}") else { break };
        out.push(&after[..end]);
        rest = &after[end + 2..];
    }
    out
}

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// A line that is only a comment, or empty.
fn is_comment(line: &str) -> bool {
    let t = line.trim_start();
    t.is_empty() || t.starts_with('#')
}

/// True when a line, outside a comment, names the trigger (`pull_request_target`, `workflow_run`).
fn names_trigger(lines: &[&str], trigger: &str) -> bool {
    lines.iter().any(|l| {
        let t = l.split(" #").next().unwrap_or(l);
        !is_comment(l)
            && t.match_indices(trigger).any(|(at, _)| {
                let before = t[..at].chars().next_back();
                let after = t[at + trigger.len()..].chars().next();
                !before.is_some_and(|c| c.is_alphanumeric() || c == '_')
                    && !after.is_some_and(|c| c.is_alphanumeric() || c == '_')
            })
    })
}

fn is_checkout(line: &str) -> bool {
    uses_reference(line).is_some_and(|(name, _)| name.eq_ignore_ascii_case("actions/checkout"))
}

fn is_artifact_download(line: &str) -> bool {
    uses_reference(line).is_some_and(|(name, _)| {
        name.eq_ignore_ascii_case("actions/download-artifact")
            || name.eq_ignore_ascii_case("dawidd6/action-download-artifact")
    })
}

/// A `ref:` or `repository:` line that points a checkout at the pull request's own code.
fn checks_out_the_pull_request(line: &str) -> bool {
    let t = line.trim_start().trim_start_matches('-').trim_start();
    (t.starts_with("ref:") || t.starts_with("repository:"))
        && (t.contains("github.event.pull_request.head.")
            || t.contains("github.head_ref")
            || t.contains("github.event.workflow_run.head_")
            || t.contains("github.event.workflow_run.head_repository")
            || (t.contains("refs/pull/") && t.contains("/merge")))
}

/// Reads one workflow file's text.
pub(crate) fn scan_workflow(rel: &str, text: &str, out: &mut Vec<CodeFinding>) {
    let lines: Vec<&str> = text.lines().collect();
    let privileged =
        names_trigger(&lines, "pull_request_target") || names_trigger(&lines, "workflow_run");
    let runs_after_pr = names_trigger(&lines, "workflow_run");
    let has_checkout = lines.iter().any(|l| !is_comment(l) && is_checkout(l));
    // The line range of the `run:` script that is being read, as (first line index, key indent).
    let mut in_script: Option<usize> = None;
    for (i, line) in lines.iter().copied().enumerate() {
        let n = i + 1;
        let skip = is_comment(line) || ignored(&lines, i);
        // Leave a block script when a line is no longer indented under its `run:` key.
        if let Some(key_indent) = in_script
            && !line.trim().is_empty()
            && indent_of(line) <= key_indent
        {
            in_script = None;
        }
        let t = line.trim_start();
        let key = t.strip_prefix('-').map_or(t, str::trim_start);
        let is_run_key = key.starts_with("run:");
        let script_line = in_script.is_some() || is_run_key;
        if is_run_key {
            let value = key["run:".len()..].trim();
            let block = value.starts_with('|') || value.starts_with('>');
            in_script = block.then(|| indent_of(line) + (t.len() - key.len()));
        }
        if skip {
            continue;
        }
        if script_line
            && !t.starts_with('#')
            && let Some(expr) = expressions(line).into_iter().find(|e| untrusted_context(e))
        {
            out.push(finding(
                "gha-script-injection",
                rel,
                n,
                Some(expr.trim().to_string()),
            ));
        }
        if privileged && has_checkout && checks_out_the_pull_request(line) {
            out.push(finding("gha-pwn-request", rel, n, None));
        }
        if runs_after_pr && is_artifact_download(line) {
            out.push(finding("gha-workflow-run-artifact", rel, n, None));
        }
        if let Some((name, reference)) = uses_reference(line)
            && classify(&reference) != Pin::Sha
        {
            out.push(finding(
                "gha-unpinned-action",
                rel,
                n,
                Some(format!("{name}@{reference}")),
            ));
        }
        let value = key
            .strip_prefix("permissions:")
            .map(|v| v.split(" #").next().unwrap_or(v).trim());
        if value == Some("write-all") {
            out.push(finding("gha-broad-permissions", rel, n, None));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code::CodeOptions;
    use crate::code::scan_code;
    use std::collections::BTreeSet;
    use std::fs;

    fn scan(text: &str) -> Vec<(String, usize)> {
        let mut out = Vec::new();
        scan_workflow(".github/workflows/ci.yml", text, &mut out);
        out.into_iter().map(|f| (f.rule, f.line)).collect()
    }

    fn rules(text: &str) -> Vec<String> {
        scan(text).into_iter().map(|(r, _)| r).collect()
    }

    fn has(text: &str, rule: &str) -> bool {
        rules(text).iter().any(|r| r == rule)
    }

    #[test]
    fn text_an_outsider_controls_in_a_run_script_is_reported() {
        let block = "jobs:\n  a:\n    steps:\n      - run: |\n          echo hi\n          echo \"${{ github.event.issue.title }}\"\n";
        assert_eq!(scan(block), vec![("gha-script-injection".to_string(), 6)]);
        for expr in [
            "github.event.issue.body",
            "github.event.pull_request.title",
            "github.event.pull_request.body",
            "github.event.comment.body",
            "github.event.review.body",
            "github.event.pages[0].page_name",
            "github.event.commits[0].message",
            "github.event.commits.*.author.email",
            "github.event.head_commit.message",
            "github.event.head_commit.author.name",
            "github.event.pull_request.head.ref",
            "github.event.pull_request.head.label",
            "github.event.pull_request.head.repo.default_branch",
            "github.head_ref",
            "  github.head_ref  ",
        ] {
            let inline = format!("steps:\n  - run: echo \"${{{{ {expr} }}}}\"\n");
            assert!(has(&inline, "gha-script-injection"), "{expr}");
            let no_space = format!("steps:\n  - run: echo ${{{{{}}}}}\n", expr.trim());
            assert!(
                has(&no_space, "gha-script-injection"),
                "{expr} without spaces"
            );
        }
        let folded = "steps:\n  - run: >\n      echo ${{ github.head_ref }}\n";
        assert!(has(folded, "gha-script-injection"));
        let bare = "steps:\n  - name: x\n    run: |\n      git checkout ${{ github.head_ref }}\n";
        assert!(has(bare, "gha-script-injection"));
    }

    #[test]
    fn the_same_text_where_it_is_safe_or_trusted_is_left_alone() {
        for text in [
            // The recommended fix: the value goes through an environment variable.
            "steps:\n  - run: echo \"$TITLE\"\n    env:\n      TITLE: ${{ github.event.issue.title }}\n",
            "steps:\n  - uses: x/y@0123456789abcdef0123456789abcdef01234567\n    with:\n      title: ${{ github.event.issue.title }}\n",
            "steps:\n  - name: ${{ github.event.issue.title }}\n    run: echo hi\n",
            // Contexts that an outsider does not set.
            "steps:\n  - run: echo ${{ github.sha }} ${{ github.actor }} ${{ github.event.pull_request.number }}\n",
            "steps:\n  - run: echo ${{ secrets.TOKEN }} ${{ github.event.repository.name }}\n",
            // A function of the value, not the value.
            "steps:\n  - run: echo ${{ contains(github.event.issue.title, 'x') }}\n",
            // A comment, in YAML and in the script.
            "# - run: echo ${{ github.head_ref }}\n",
            "steps:\n  - run: |\n      # ${{ github.head_ref }}\n      echo hi\n",
        ] {
            assert!(!has(text, "gha-script-injection"), "{text}");
        }
        // A block ends where the indentation does: the env below is not part of the script.
        let after =
            "steps:\n  - run: |\n      echo hi\n    env:\n      T: ${{ github.head_ref }}\n";
        assert!(!has(after, "gha-script-injection"));
        // The next step's run is read again.
        let next = "steps:\n  - run: |\n      echo hi\n  - run: echo ${{ github.head_ref }}\n";
        assert_eq!(scan(next), vec![("gha-script-injection".to_string(), 4)]);
    }

    #[test]
    fn a_privileged_workflow_that_checks_out_the_pull_request_is_reported() {
        let head = "on:\n  pull_request_target:\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n";
        assert_eq!(scan(head), vec![("gha-pwn-request".to_string(), 8)]);
        for line in [
            "repository: ${{ github.event.pull_request.head.repo.full_name }}",
            "ref: ${{ github.head_ref }}",
            "ref: ${{ github.event.pull_request.head.ref }}",
            "ref: refs/pull/${{ github.event.number }}/merge",
        ] {
            let text = format!(
                "on: [push, pull_request_target]\nsteps:\n  - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567\n    with:\n      {line}\n"
            );
            assert!(has(&text, "gha-pwn-request"), "{line}");
        }
        let run = "on:\n  workflow_run:\n    workflows: [CI]\nsteps:\n  - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567\n    with:\n      ref: ${{ github.event.workflow_run.head_sha }}\n";
        assert!(has(run, "gha-pwn-request"));
    }

    #[test]
    fn checking_out_the_pull_request_is_fine_when_the_workflow_has_no_privilege() {
        let unprivileged = "on:\n  pull_request:\nsteps:\n  - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567\n    with:\n      ref: ${{ github.event.pull_request.head.sha }}\n";
        assert!(!has(unprivileged, "gha-pwn-request"));
        let default_ref = "on:\n  pull_request_target:\nsteps:\n  - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567\n";
        assert!(!has(default_ref, "gha-pwn-request"));
        let no_checkout = "on:\n  pull_request_target:\nsteps:\n  - run: echo\n    env:\n      ref: ${{ github.head_ref }}\n";
        assert!(!has(no_checkout, "gha-pwn-request"));
        let mention = "# on: pull_request_target\non:\n  push:\nsteps:\n  - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567\n    with:\n      ref: ${{ github.head_ref }}\n";
        assert!(
            !has(mention, "gha-pwn-request"),
            "a comment is not a trigger"
        );
        let longer = "on:\n  pull_request_target_extra:\nsteps:\n  - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567\n    with:\n      ref: ${{ github.head_ref }}\n";
        assert!(
            !has(longer, "gha-pwn-request"),
            "a longer word is not the trigger"
        );
    }

    #[test]
    fn an_artifact_downloaded_by_a_workflow_run_workflow_is_reported() {
        let text = "on:\n  workflow_run:\n    workflows: [CI]\nsteps:\n  - uses: actions/download-artifact@0123456789abcdef0123456789abcdef01234567\n  - uses: dawidd6/action-download-artifact@0123456789abcdef0123456789abcdef01234567\n";
        assert_eq!(
            scan(text),
            vec![
                ("gha-workflow-run-artifact".to_string(), 5),
                ("gha-workflow-run-artifact".to_string(), 6)
            ]
        );
        let plain = "on:\n  pull_request:\nsteps:\n  - uses: actions/download-artifact@0123456789abcdef0123456789abcdef01234567\n";
        assert!(scan(plain).is_empty());
    }

    #[test]
    fn an_action_that_is_not_pinned_to_a_commit_sha_is_reported_with_its_name() {
        let mut out = Vec::new();
        scan_workflow(
            ".github/workflows/ci.yml",
            "steps:\n  - uses: actions/checkout@v4\n  - uses: \"org/tool@main\"\n  - uses: org/other/sub@v1.2.3 # pinned\n  - uses: org/sha@0123456789abcdef0123456789abcdef01234567 # v1\n  - uses: ./local\n  - uses: docker://alpine:3\n  - uses: org/noref\n",
            &mut out,
        );
        let hits: Vec<(usize, String)> = out.iter().map(|f| (f.line, f.title.clone())).collect();
        assert_eq!(hits.len(), 3, "{hits:?}");
        assert!(hits[0].1.contains("(actions/checkout@v4)"));
        assert!(hits[1].1.contains("(org/tool@main)"));
        assert!(hits[2].1.contains("(org/other@v1.2.3)"));
        assert!(
            out.iter()
                .all(|f| f.severity == Severity::Low && f.snippet.is_empty())
        );
    }

    #[test]
    fn a_token_with_every_permission_is_reported_but_a_list_is_not() {
        assert_eq!(
            scan("permissions: write-all\n"),
            vec![("gha-broad-permissions".to_string(), 1)]
        );
        assert_eq!(
            scan("jobs:\n  a:\n    permissions: write-all # temporary\n"),
            vec![("gha-broad-permissions".to_string(), 3)]
        );
        for ok in [
            "permissions: read-all\n",
            "permissions:\n  contents: read\n",
            "permissions: {}\n",
            "# permissions: write-all\n",
        ] {
            assert!(scan(ok).is_empty(), "{ok}");
        }
    }

    #[test]
    fn the_ignore_marker_silences_a_line_in_a_workflow() {
        let text = "steps:\n  - run: echo ${{ github.head_ref }} # opencraysec:ignore\n  # opencraysec:ignore\n  - uses: a/b@main\n  - uses: c/d@main\n";
        assert_eq!(scan(text), vec![("gha-unpinned-action".to_string(), 5)]);
    }

    #[test]
    fn scan_code_reads_only_files_in_the_workflows_folder() {
        let dir = tempfile::tempdir().expect("tmp");
        let write = |rel: &str, text: &str| {
            let p = dir.path().join(rel);
            fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
            fs::write(p, text).expect("w");
        };
        let bad = "steps:\n  - run: echo ${{ github.head_ref }}\n  - uses: a/b@main\n";
        write(".github/workflows/ci.yml", bad);
        write(".github/workflows/deploy.yaml", bad);
        write("config/ci.yml", bad);
        write(".github/ISSUE_TEMPLATE/bug.yml", bad);
        write(".github/workflows/notes.md", bad);
        let r = scan_code(dir.path(), &CodeOptions::default()).expect("scan");
        let files: BTreeSet<&str> = r.findings.iter().map(|f| f.file.as_str()).collect();
        assert_eq!(
            files,
            BTreeSet::from([".github/workflows/ci.yml", ".github/workflows/deploy.yaml"])
        );
        let one = scan_code(
            &dir.path().join(".github/workflows/ci.yml"),
            &CodeOptions::default(),
        )
        .expect("scan");
        assert_eq!(one.findings.len(), 2, "a workflow named directly is read");
    }

    #[test]
    fn every_rule_is_documented_with_its_sources() {
        let doc = include_str!("../../../docs/LANGUAGES.md");
        let mut seen = BTreeSet::new();
        for r in RULES {
            assert!(seen.insert(r.id), "duplicate {}", r.id);
            assert!(r.id.starts_with("gha-"));
            assert!(
                doc.contains(&format!("`{}`", r.id)),
                "{} is not in docs/LANGUAGES.md",
                r.id
            );
            assert!(doc.contains(r.cwe), "{} is not named in the docs", r.cwe);
            let owasp = OWASP
                .iter()
                .find(|(i, _)| *i == r.id)
                .map(|(_, o)| *o)
                .expect("an OWASP entry");
            assert!(doc.contains(owasp), "{owasp} is not named in the docs");
            assert!(r.advice.contains(owasp), "{} advice names {owasp}", r.id);
        }
        assert_eq!(OWASP.len(), RULES.len());
        for url in [
            "https://securitylab.github.com/resources/github-actions-untrusted-input/",
            "https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/",
            "https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions",
        ] {
            assert!(doc.contains(url), "{url} is not linked from the docs");
        }
    }
}
