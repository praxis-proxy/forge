//! Extended lint: diff-scoped heuristic checks for common low-quality-code
//! patterns that automated compiler lints can't catch structurally.
//!
//! Clippy already denies the machine-checkable half of this class of issue
//! (`unwrap`/`expect`, `panic`, `todo!()`/`unimplemented!()`, `dead_code`,
//! `missing_docs`, `print`/`dbg` macros, and more, depending on the crate's
//! own lint config). What lint tooling structurally cannot check is comment
//! *content* and diff-local *repetition* -- two common low-effort-code
//! tells. This checks only lines added/changed versus the diff base so
//! pre-existing code is never relitigated.
//!
//! Checks (Block = fails; Warn = printed, does not fail):
//!   - Block: leftover TODO/FIXME/XXX/HACK markers in comments
//!   - Block: commented-out code
//!   - Warn: narrating "what the code does" comments
//!   - Warn: the same numeric/string literal repeated 3+ times without a
//!     named constant
//!   - Warn: weak/generic identifier names introduced by a new let/fn binding
//!   - Warn: new clippy lint suppressions added
//!
//! Diff base resolution: CLI arg, else `EXTENDED_LINT_BASE` env var, else
//! `origin/$GITHUB_BASE_REF` in a GitHub Actions PR, else `origin/main`.

use std::collections::{HashMap, HashSet};
use std::process::Command;
use std::sync::LazyLock;

use anyhow::{Context as _, Result};
use regex::Regex;

/// Per-file set of literals already hoisted into a named `const`/`static`.
type ConstDeclared = HashMap<String, HashSet<String>>;

/// Every `(file, literal)` pair mapped to the `(line content, line number)`
/// sites where that literal appears in the diff.
type LiteralSites = HashMap<(String, String), Vec<(String, usize)>>;

/// Compile a regex pattern known at compile time to be valid.
///
/// # Panics
///
/// Panics if `pattern` fails to compile. All call sites below pass hardcoded
/// literals covered by this module's unit tests, so this only fires on a
/// developer error introduced alongside the pattern itself.
#[expect(
    clippy::unwrap_used,
    reason = "pattern argument is always a hardcoded, test-covered literal"
)]
fn static_regex(pattern: &str) -> Regex {
    Regex::new(pattern).unwrap()
}

/// Minimum number of diff-local occurrences of a literal before it's
/// flagged as worth hoisting into a named constant.
const MIN_LITERAL_REPETITIONS: usize = 3;

/// Matches a `TODO`/`FIXME`/`XXX`/`HACK` marker anywhere in a comment.
static TODO_MARKER_RE: LazyLock<Regex> =
    LazyLock::new(|| static_regex(r"(?i)//.*\b(TODO|FIXME|XXX|HACK)\b"));

/// Matches comment lines that look like commented-out Rust statements
/// rather than prose (doc comments are excluded by the caller).
static COMMENTED_CODE_RE: LazyLock<Regex> = LazyLock::new(|| {
    static_regex(
        r"^//+\s*(let\s+\w|fn\s+\w|if\s*\(|for\s*\(|match\s+\w|return\b|\w+\s*\([^)]*\)\s*;?\s*$|\w+\.\w+\(.*\)\s*;?\s*$|[\w:<>]+\s*=\s*.+;\s*$)",
    )
});

/// Matches a new `let`/`fn` binding introducing a weak, generic identifier
/// name (e.g. `temp`, `foo`, `stuff`).
static WEAK_NAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    static_regex(r"^(let(?:\s+mut)?|fn)\s+(temp|tmp|foo|bar|thing|val|obj|stuff)\b")
});

/// Matches a bare numeric or string literal candidate for the
/// repeated-literal check.
static LIT_RE: LazyLock<Regex> =
    LazyLock::new(|| static_regex(r#"(?:^|[^\w.])(\d{2,}|"[^"]{4,}")(?:$|[^\w])"#));

/// Matches a `const`/`static` declaration line, used to exempt literals
/// that are already hoisted into a named constant.
static CONST_LINE_RE: LazyLock<Regex> = LazyLock::new(|| static_regex(r"\b(const|static)\s+\w+"));

/// Matches a new `#[allow(clippy::...)]`/`#[expect(clippy::...)]`
/// suppression attribute.
static SUPPRESSION_RE: LazyLock<Regex> =
    LazyLock::new(|| static_regex(r"#\[(allow|expect)\(clippy::"));

/// Matches the start of a `#[cfg(test)]` module, used to exclude test code
/// from the repeated-literal check.
static TEST_MODULE_RE: LazyLock<Regex> =
    LazyLock::new(|| static_regex(r"^(#\[cfg\(test\)\]|mod tests\b)"));

/// Matches the start of a hunk header in unified diff output, capturing the
/// starting line number of the new file's hunk.
static HUNK_HEADER_RE: LazyLock<Regex> =
    LazyLock::new(|| static_regex(r"^@@ -\d+(?:,\d+)? \+(\d+)"));

/// Lowercased comment openers that narrate "what" the following code does
/// rather than "why" it exists.
const NARRATING_OPENERS: &[&str] = &[
    "increment",
    "decrement",
    "loop through",
    "iterate over",
    "iterate through",
    "return the",
    "returns the",
    "create a",
    "creates a",
    "initialize",
    "set the",
    "sets the",
    "get the",
    "gets the",
    "parse the",
    "parses the",
    "convert ",
    "converts ",
    "check if",
    "checks if",
    "validate that",
    "validates that",
    "call ",
    "calls ",
    "define ",
    "defines ",
    "import ",
    "imports ",
    "declare ",
    "declares ",
    "instantiate",
    "loop over",
    "append ",
    "appends ",
    "remove ",
    "removes ",
    "add ",
    "adds ",
];

/// A single line added (or changed) by the diff, relative to the diff base.
struct AddedLine {
    /// Path of the file the line belongs to, relative to the repo root.
    file: String,
    /// 1-based line number of this line in the *new* version of the file.
    lineno: usize,
    /// The line's content, with the leading diff `+` marker stripped.
    content: String,
}

/// Findings collected while scanning the diff, split by severity.
#[derive(Default)]
struct Findings {
    /// Findings that fail the check when non-empty.
    blocking: Vec<String>,
    /// Findings printed for human review; never fail the check.
    warnings: Vec<String>,
}

/// Resolve the diff base to compare against, in priority order: an explicit
/// CLI argument, the `EXTENDED_LINT_BASE` environment variable, the GitHub
/// Actions PR base branch, or `origin/main`.
fn resolve_diff_base(cli_arg: Option<&str>) -> String {
    if let Some(base) = cli_arg {
        return base.to_owned();
    }
    if let Ok(base) = std::env::var("EXTENDED_LINT_BASE") {
        return base;
    }
    if let Ok(base_ref) = std::env::var("GITHUB_BASE_REF") {
        return format!("origin/{base_ref}");
    }
    "origin/main".to_owned()
}

/// This module's own source file is excluded from the scan: its doc
/// comments and unit tests legitimately quote the very marker words and
/// comment-like syntax the heuristics below look for (e.g. "TODO" appears
/// in a doc comment describing the TODO check itself), which would
/// otherwise make the tool block on its own, non-offending source forever.
/// The original Python implementation never hit this because `*.rs` never
/// matched a `.py` file; porting to Rust makes the tool a scan target of
/// itself, so the exclusion must be explicit here instead.
const SELF_EXCLUDE_PATHSPEC: &str = ":!xtask/src/lint_extended.rs";

/// Run `git diff` against `diff_base` and collect every added Rust line.
fn run_diff(diff_base: &str) -> Result<Vec<AddedLine>> {
    let output = Command::new("git")
        .args([
            "diff",
            "--unified=0",
            diff_base,
            "--",
            "*.rs",
            SELF_EXCLUDE_PATHSPEC,
        ])
        .output()
        .context("failed to run git diff")?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    let mut added = Vec::new();
    let mut current_file = String::new();
    let mut new_lineno: usize = 0;

    for line in stdout.lines() {
        if let Some(path) = line.strip_prefix("+++ b/") {
            path.clone_into(&mut current_file);
            continue;
        }
        if let Some(caps) = HUNK_HEADER_RE.captures(line) {
            new_lineno = caps.get(1).map_or(0, |m| m.as_str().parse().unwrap_or(0));
            continue;
        }
        if line.starts_with("+++") || line.starts_with("---") {
            continue;
        }
        if let Some(content) = line.strip_prefix('+') {
            added.push(AddedLine {
                file: current_file.clone(),
                lineno: new_lineno,
                content: content.to_owned(),
            });
            new_lineno += 1;
        } else if !line.starts_with('-') {
            new_lineno += 1;
        }
    }
    Ok(added)
}

/// Return the 1-based line number where `file`'s test module starts, or
/// `usize::MAX` if the file has no test module (or can't be read).
fn test_module_start_line(file: &str) -> usize {
    let Ok(text) = std::fs::read_to_string(file) else {
        return usize::MAX;
    };
    for (i, line) in text.lines().enumerate() {
        if TEST_MODULE_RE.is_match(line) {
            return i + 1;
        }
    }
    usize::MAX
}

/// Extract the trailing `//`-style comment from a line, if any.
fn comment_text(content: &str) -> String {
    let Some(idx) = content.find("//") else {
        return String::new();
    };
    content.get(idx..).unwrap_or("").trim().to_owned()
}

/// Block: a leftover `TODO`/`FIXME`/`XXX`/`HACK` marker in a comment.
fn check_todo_marker(line: &AddedLine, stripped: &str, comment: &str, findings: &mut Findings) {
    if !comment.is_empty() && TODO_MARKER_RE.is_match(comment) {
        findings.blocking.push(format!(
            "{}:{}: leftover TODO/FIXME/XXX/HACK marker: {stripped:?}",
            line.file, line.lineno
        ));
    }
}

/// Block: a comment that looks like commented-out code rather than prose.
fn check_commented_out_code(
    line: &AddedLine,
    stripped: &str,
    comment: &str,
    findings: &mut Findings,
) {
    let is_doc_comment = comment.starts_with("///") || comment.starts_with("//!");
    if !comment.is_empty() && !is_doc_comment && COMMENTED_CODE_RE.is_match(comment) {
        findings.blocking.push(format!(
            "{}:{}: looks like commented-out code: {stripped:?}",
            line.file, line.lineno
        ));
    }
}

/// Warn: a comment narrating "what" the following code does.
fn check_narrating_comment(
    line: &AddedLine,
    stripped: &str,
    comment: &str,
    findings: &mut Findings,
) {
    let is_plain_comment =
        comment.starts_with("//") && !comment.starts_with("///") && !comment.starts_with("//!");
    if !is_plain_comment {
        return;
    }
    let body = comment.trim_start_matches('/').trim().to_lowercase();
    let is_narrating = NARRATING_OPENERS
        .iter()
        .any(|opener| body.starts_with(opener));
    if is_narrating {
        findings.warnings.push(format!(
            "{}:{}: narrating 'what' comment, prefer self-explanatory code or a doc comment on why: {stripped:?}",
            line.file, line.lineno
        ));
    }
}

/// Warn: a new `let`/`fn` binding introducing a weak, generic identifier
/// name.
fn check_weak_name(line: &AddedLine, stripped: &str, findings: &mut Findings) {
    let Some(caps) = WEAK_NAME_RE.captures(stripped) else {
        return;
    };
    let name = caps.get(2).map_or("", |m| m.as_str());
    findings.warnings.push(format!(
        "{}:{}: weak/generic identifier name {name:?}: {stripped:?}",
        line.file, line.lineno
    ));
}

/// Warn: a new clippy lint suppression attribute.
fn check_suppression(line: &AddedLine, stripped: &str, findings: &mut Findings) {
    if SUPPRESSION_RE.is_match(stripped) {
        findings.warnings.push(format!(
            "{}:{}: new clippy suppression added, double-check the reason: {stripped:?}",
            line.file, line.lineno
        ));
    }
}

/// Record any literal declared on a `const`/`static` line so it's exempted
/// from the repeated-literal check.
fn collect_const_literal_declarations(
    file: &str,
    stripped: &str,
    const_declared: &mut ConstDeclared,
) {
    if !CONST_LINE_RE.is_match(stripped) {
        return;
    }
    for caps in LIT_RE.captures_iter(stripped) {
        let Some(literal) = caps.get(1) else {
            continue;
        };
        const_declared
            .entry(file.to_owned())
            .or_default()
            .insert(literal.as_str().to_owned());
    }
}

/// Record every literal occurrence on a non-test, non-attribute line, for
/// the repeated-literal check.
fn collect_literal_site(
    file: &str,
    lineno: usize,
    stripped: &str,
    literal_sites: &mut LiteralSites,
) {
    for caps in LIT_RE.captures_iter(stripped) {
        let Some(literal) = caps.get(1) else {
            continue;
        };
        literal_sites
            .entry((file.to_owned(), literal.as_str().to_owned()))
            .or_default()
            .push((stripped.to_owned(), lineno));
    }
}

/// Run every per-line check against one added line, accumulating findings
/// and the state needed for the cross-line repeated-literal check.
fn scan_added_line(
    line: &AddedLine,
    findings: &mut Findings,
    literal_sites: &mut LiteralSites,
    const_declared: &mut ConstDeclared,
) {
    let stripped = line.content.trim();
    let comment = comment_text(&line.content);

    check_todo_marker(line, stripped, &comment, findings);
    check_commented_out_code(line, stripped, &comment, findings);
    check_narrating_comment(line, stripped, &comment, findings);
    check_weak_name(line, stripped, findings);
    check_suppression(line, stripped, findings);
    collect_const_literal_declarations(&line.file, stripped, const_declared);

    if line.lineno < test_module_start_line(&line.file) && !stripped.starts_with("#[") {
        collect_literal_site(&line.file, line.lineno, stripped, literal_sites);
    }
}

/// Build warnings for literals repeated `MIN_LITERAL_REPETITIONS`+ times in
/// the diff without ever being hoisted into a named constant.
fn repeated_literal_warnings(
    literal_sites: &LiteralSites,
    const_declared: &ConstDeclared,
) -> Vec<String> {
    let mut warnings = Vec::new();
    for ((file, literal), sites) in literal_sites {
        let declared = const_declared
            .get(file)
            .is_some_and(|s| s.contains(literal));
        if sites.len() < MIN_LITERAL_REPETITIONS || declared {
            continue;
        }
        let lines: Vec<String> = sites.iter().map(|(_, lineno)| lineno.to_string()).collect();
        warnings.push(format!(
            "{file}: literal {literal} repeated {}x at lines {} without a named constant -- consider hoisting it",
            sites.len(),
            lines.join(", ")
        ));
    }
    warnings
}

/// Report that the diff had no added Rust lines, so there was nothing to
/// check.
#[expect(
    clippy::print_stdout,
    reason = "xtask is a CLI dev-tool; a clean, no-op result is reported on stdout"
)]
fn report_no_added_lines(diff_base: &str) {
    println!("[extended-lint] no added Rust lines vs {diff_base}; nothing to check.");
}

/// Print collected findings to stderr. Returns whether the check passes
/// (i.e. there are no blocking findings).
#[expect(
    clippy::print_stderr,
    reason = "xtask is a CLI dev-tool; findings are reported on stderr for CI log visibility"
)]
fn report_findings(findings: &Findings) -> bool {
    if !findings.warnings.is_empty() {
        eprintln!("[extended-lint] warnings (review, does not block):");
        for warning in &findings.warnings {
            eprintln!("  - {warning}");
        }
        eprintln!();
    }

    if !findings.blocking.is_empty() {
        eprintln!("[extended-lint] BLOCKING findings:");
        for finding in &findings.blocking {
            eprintln!("  - {finding}");
        }
        eprintln!();
        eprintln!(
            "[extended-lint] fix the above, or if a match is a false positive, note why in the PR description."
        );
        return false;
    }

    eprintln!("[extended-lint] no blocking findings.");
    true
}

/// Runs the check; returns `Ok(true)` if clean, `Ok(false)` if blocking
/// findings exist (caller should exit non-zero in that case).
///
/// # Errors
///
/// Returns an error if `git diff` cannot be executed against `cli_arg` (or
/// the resolved default diff base).
pub(crate) fn run(cli_arg: Option<&str>) -> Result<bool> {
    let diff_base = resolve_diff_base(cli_arg);
    let added = run_diff(&diff_base)?;
    if added.is_empty() {
        report_no_added_lines(&diff_base);
        return Ok(true);
    }

    let mut findings = Findings::default();
    let mut literal_sites = HashMap::new();
    let mut const_declared = HashMap::new();
    for line in &added {
        scan_added_line(line, &mut findings, &mut literal_sites, &mut const_declared);
    }
    findings
        .warnings
        .extend(repeated_literal_warnings(&literal_sites, &const_declared));

    Ok(report_findings(&findings))
}

#[cfg(test)]
mod tests {
    use super::{COMMENTED_CODE_RE, NARRATING_OPENERS, TODO_MARKER_RE, WEAK_NAME_RE};

    #[test]
    fn detects_todo_marker() {
        assert!(
            TODO_MARKER_RE.is_match("// TODO: fix this later"),
            "should flag a TODO marker in a comment"
        );
        assert!(
            !TODO_MARKER_RE.is_match("// this is fine"),
            "should not flag an ordinary comment"
        );
    }

    #[test]
    fn detects_commented_out_code_but_not_doc_comments() {
        assert!(
            COMMENTED_CODE_RE.is_match("// let x = compute();"),
            "should flag a commented-out let statement"
        );
        assert!(
            !COMMENTED_CODE_RE.is_match("/// Returns the computed value."),
            "should not flag a doc comment"
        );
    }

    #[test]
    fn detects_weak_names() {
        let name = WEAK_NAME_RE
            .captures("let temp = 5;")
            .and_then(|caps| caps.get(2))
            .map(|m| m.as_str());
        assert_eq!(name, Some("temp"), "should capture the weak name 'temp'");
        assert!(
            WEAK_NAME_RE.captures("let value = 5;").is_none(),
            "should not flag a descriptive name"
        );
    }

    #[test]
    fn detects_narrating_comment_openers() {
        assert!(
            NARRATING_OPENERS
                .iter()
                .any(|o| "increment the counter by one".starts_with(o)),
            "should recognize a narrating opener"
        );
        assert!(
            !NARRATING_OPENERS
                .iter()
                .any(|o| "guards against a torn write".starts_with(o)),
            "should not misfire on a 'why'-style comment"
        );
    }
}
