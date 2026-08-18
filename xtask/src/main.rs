//! `cargo xtask` entry point for forge developer-tooling automation.
//!
//! Add new tasks as subcommands here rather than as standalone scripts, so
//! they build with the same toolchain and lint bar as the rest of the repo.
//! Invoke with `cargo xtask <task> [args]`.

mod lint_extended;

use std::process::ExitCode;

use anyhow::{Result, bail};

fn main() -> ExitCode {
    match run(std::env::args().skip(1)) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(err) => {
            report_error(&err);
            ExitCode::FAILURE
        }
    }
}

/// Print a fatal xtask error to stderr.
#[expect(
    clippy::print_stderr,
    reason = "xtask is a CLI dev-tool; fatal errors are reported on stderr"
)]
fn report_error(err: &anyhow::Error) {
    eprintln!("xtask error: {err:#}");
}

/// Dispatch a task by name; `args` are the remaining CLI arguments after
/// the task name.
///
/// # Errors
///
/// Returns an error if no task name is given, the task name is unknown, or
/// the dispatched task itself fails.
fn run(mut args: impl Iterator<Item = String>) -> Result<bool> {
    let Some(task) = args.next() else {
        bail!("usage: cargo xtask <lint-extended> [diff-base]");
    };
    match task.as_str() {
        "lint-extended" => lint_extended::run(args.next().as_deref()),
        other => bail!("unknown xtask task: {other}"),
    }
}
