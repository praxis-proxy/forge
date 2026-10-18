//! Container runtime detection.
//!
//! Probes for Docker and Podman via [`CommandRunner`] and resolves
//! the `Auto` runtime provider to a concrete provider.

use std::collections::BTreeMap;

use crate::{
    command::runner::{CommandRunner, CommandSpec},
    config::RuntimeProvider,
    error::ForgeError,
};

/// A resolved container runtime with its provider and binary name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedRuntime {
    /// The concrete provider (never `Auto`).
    pub provider: RuntimeProvider,
    /// Name of the runtime binary.
    pub binary: String,
}

/// Resolve a runtime provider, auto-detecting if necessary.
///
/// # Errors
///
/// Returns [`ForgeError::Runtime`] if the requested runtime is not
/// available, or if auto-detection finds neither Docker nor Podman.
pub fn resolve(runner: &dyn CommandRunner, requested: &RuntimeProvider) -> Result<ResolvedRuntime, ForgeError> {
    match requested {
        RuntimeProvider::Docker => require_docker(runner),
        RuntimeProvider::Podman => require_podman(runner),
        RuntimeProvider::Auto => auto_detect(runner),
    }
}

/// The runtime binary an environment uses: the one recorded in state, else a fresh resolve.
///
/// # Errors
///
/// Returns [`ForgeError::Runtime`] if nothing is recorded and resolution fails, or
/// if the config names a runtime other than the recorded one.
pub fn recorded_or_resolved(
    runner: &dyn CommandRunner,
    requested: &RuntimeProvider,
    recorded: Option<&str>,
) -> Result<String, ForgeError> {
    let Some(binary) = recorded else {
        return resolve(runner, requested).map(|rt| rt.binary);
    };
    let wanted = match requested {
        RuntimeProvider::Auto => None,
        RuntimeProvider::Docker => Some("docker"),
        RuntimeProvider::Podman => Some("podman"),
    };
    match wanted {
        Some(want) if want != binary => Err(ForgeError::Runtime(format!(
            "config requests {want} but this environment runs on {binary}; run `forge down` first"
        ))),
        _ => Ok(binary.to_owned()),
    }
}

/// Outcome of probing one runtime binary with `<program> version`.
#[derive(Debug)]
enum ProbeOutcome {
    /// The binary responded successfully.
    Available(ResolvedRuntime),
    /// The binary ran but exited non-zero: present, daemon unreachable.
    NotResponding(String),
    /// The binary could not be executed at all.
    Missing,
}

impl ProbeOutcome {
    /// Describe this outcome for error and warning messages.
    fn describe(&self, program: &str) -> String {
        match self {
            Self::Available(_) => format!("{program} available"),
            Self::NotResponding(stderr) => {
                format!("{program} found but not responding (is the daemon running?): {stderr}")
            },
            Self::Missing => format!("{program} not found"),
        }
    }
}

/// Auto-detect: try Docker first, then Podman.
fn auto_detect(runner: &dyn CommandRunner) -> Result<ResolvedRuntime, ForgeError> {
    let docker = probe_docker(runner);
    if let ProbeOutcome::Available(rt) = docker {
        return Ok(rt);
    }
    match probe_podman(runner) {
        ProbeOutcome::Available(rt) => {
            warn_skipped("docker", &docker);
            Ok(rt)
        },
        podman @ (ProbeOutcome::NotResponding(_) | ProbeOutcome::Missing) => Err(ForgeError::Runtime(format!(
            "no usable container runtime: {}; {}",
            docker.describe("docker"),
            podman.describe("podman"),
        ))),
    }
}

/// Note on stderr when auto-detection skips a present but unresponsive
/// runtime, so users whose images live in that runtime see why the
/// fallback was chosen.
#[expect(clippy::print_stderr, reason = "user-facing CLI warning")]
fn warn_skipped(program: &str, outcome: &ProbeOutcome) {
    if matches!(outcome, ProbeOutcome::NotResponding(_)) {
        eprintln!("warning: {}; falling back", outcome.describe(program));
    }
}

/// Require Docker to be available.
fn require_docker(runner: &dyn CommandRunner) -> Result<ResolvedRuntime, ForgeError> {
    require_runtime(probe_docker(runner), "docker")
}

/// Require Podman to be available.
fn require_podman(runner: &dyn CommandRunner) -> Result<ResolvedRuntime, ForgeError> {
    require_runtime(probe_podman(runner), "podman")
}

/// Turn a probe outcome into a resolved runtime or a precise error.
fn require_runtime(outcome: ProbeOutcome, program: &str) -> Result<ResolvedRuntime, ForgeError> {
    match outcome {
        ProbeOutcome::Available(rt) => Ok(rt),
        failed @ (ProbeOutcome::NotResponding(_) | ProbeOutcome::Missing) => {
            Err(ForgeError::Runtime(failed.describe(program)))
        },
    }
}

/// Probe Docker by running `docker version`.
fn probe_docker(runner: &dyn CommandRunner) -> ProbeOutcome {
    probe_runtime(runner, "docker", RuntimeProvider::Docker)
}

/// Probe Podman by running `podman version`.
fn probe_podman(runner: &dyn CommandRunner) -> ProbeOutcome {
    probe_runtime(runner, "podman", RuntimeProvider::Podman)
}

/// Probe a runtime by running `<program> version`.
fn probe_runtime(runner: &dyn CommandRunner, program: &str, provider: RuntimeProvider) -> ProbeOutcome {
    let spec = version_spec(program);
    match runner.run(&spec) {
        Ok(out) if out.status == 0 => ProbeOutcome::Available(ResolvedRuntime {
            provider,
            binary: program.to_owned(),
        }),
        Ok(out) => ProbeOutcome::NotResponding(out.stderr.trim().to_owned()),
        Err(_err) => ProbeOutcome::Missing,
    }
}

/// Build a `<program> version` command spec.
fn version_spec(program: &str) -> CommandSpec {
    CommandSpec {
        program: program.into(),
        args: vec!["version".into()],
        env: BTreeMap::default(),
        stdin: None,
        redact: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::runner::{CommandOutput, MockRunner};

    /// Build a mock where the given program succeeds.
    fn mock_with_runtime(program: &str) -> MockRunner {
        let mut runner = MockRunner::new();
        runner.respond(
            &format!("{program} version"),
            CommandOutput {
                status: 0,
                stdout: format!("{program} version 24.0.0\n"),
                stderr: String::new(),
            },
        );
        runner
    }

    /// Build a mock where the given program exits non-zero (daemon down).
    fn mock_with_dead_daemon(program: &str) -> MockRunner {
        let mut runner = MockRunner::new();
        runner.respond(
            &format!("{program} version"),
            CommandOutput {
                status: 1,
                stdout: String::new(),
                stderr: "Cannot connect to the daemon".to_owned(),
            },
        );
        runner
    }

    #[test]
    fn auto_detects_docker_first() {
        let runner = mock_with_runtime("docker");
        let rt = resolve(&runner, &RuntimeProvider::Auto).unwrap_or_else(|_| {
            std::process::abort();
            #[expect(unreachable_code, reason = "abort prevents reaching this")]
            {
                unreachable!()
            }
        });
        assert_eq!(rt.provider, RuntimeProvider::Docker, "should detect docker");
    }

    #[test]
    fn auto_falls_back_to_podman() {
        let runner = mock_with_runtime("podman");
        let rt = resolve(&runner, &RuntimeProvider::Auto).unwrap_or_else(|_| {
            std::process::abort();
            #[expect(unreachable_code, reason = "abort prevents reaching this")]
            {
                unreachable!()
            }
        });
        assert_eq!(rt.provider, RuntimeProvider::Podman, "should fall back to podman");
    }

    #[test]
    fn auto_fails_when_neither_found() {
        let runner = MockRunner::new();
        let result = resolve(&runner, &RuntimeProvider::Auto);
        assert!(result.is_err(), "should fail when neither runtime found");
    }

    #[test]
    fn explicit_docker_succeeds() {
        let runner = mock_with_runtime("docker");
        let rt = resolve(&runner, &RuntimeProvider::Docker).unwrap_or_else(|_| {
            std::process::abort();
            #[expect(unreachable_code, reason = "abort prevents reaching this")]
            {
                unreachable!()
            }
        });
        assert_eq!(rt.binary, "docker", "binary should be docker");
    }

    #[test]
    fn explicit_docker_fails_when_missing() {
        let runner = MockRunner::new();
        let result = resolve(&runner, &RuntimeProvider::Docker);
        assert!(result.is_err(), "should fail when docker not found");
    }

    #[test]
    fn explicit_docker_daemon_down_reports_not_responding() {
        let runner = mock_with_dead_daemon("docker");
        let Err(err) = resolve(&runner, &RuntimeProvider::Docker) else {
            std::process::abort();
        };
        let msg = err.to_string();
        assert!(
            msg.contains("not responding") && msg.contains("Cannot connect"),
            "expected daemon-down error with stderr, got: {msg}"
        );
    }

    #[test]
    fn auto_falls_back_when_docker_daemon_down() {
        let mut runner = mock_with_dead_daemon("docker");
        runner.respond(
            "podman version",
            CommandOutput {
                status: 0,
                stdout: "podman version 4.0.0\n".to_owned(),
                stderr: String::new(),
            },
        );
        let rt = resolve(&runner, &RuntimeProvider::Auto).unwrap_or_else(|_| {
            std::process::abort();
            #[expect(unreachable_code, reason = "abort prevents reaching this")]
            {
                unreachable!()
            }
        });
        assert_eq!(rt.provider, RuntimeProvider::Podman, "should fall back to podman");
    }

    #[test]
    fn auto_failure_describes_both_probes() {
        let runner = mock_with_dead_daemon("docker");
        let Err(err) = resolve(&runner, &RuntimeProvider::Auto) else {
            std::process::abort();
        };
        let msg = err.to_string();
        assert!(
            msg.contains("docker found but not responding") && msg.contains("podman not found"),
            "expected per-probe detail, got: {msg}"
        );
    }

    #[test]
    fn explicit_podman_succeeds() {
        let runner = mock_with_runtime("podman");
        let rt = resolve(&runner, &RuntimeProvider::Podman).unwrap_or_else(|_| {
            std::process::abort();
            #[expect(unreachable_code, reason = "abort prevents reaching this")]
            {
                unreachable!()
            }
        });
        assert_eq!(rt.binary, "podman", "binary should be podman");
    }

    #[test]
    fn recorded_runtime_wins_and_a_conflicting_config_is_refused() {
        let runner = MockRunner::new();
        let auto = recorded_or_resolved(&runner, &RuntimeProvider::Auto, Some("podman"));
        assert_eq!(auto.ok().as_deref(), Some("podman"), "auto keeps the recorded runtime");
        let same = recorded_or_resolved(&runner, &RuntimeProvider::Podman, Some("podman"));
        assert_eq!(same.ok().as_deref(), Some("podman"), "a matching config keeps it");
        let conflict = recorded_or_resolved(&runner, &RuntimeProvider::Docker, Some("podman"));
        assert!(conflict.is_err(), "a conflicting config is refused");
        assert_eq!(runner.call_count(), 0, "a recorded runtime runs no probe");
    }
}
