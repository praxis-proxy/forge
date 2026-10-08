//! Container network lifecycle management.
//!
//! Creates, removes, and inspects Docker/Podman networks for Forge
//! environments.  All commands are structured [`CommandSpec`] values
//! executed through [`CommandRunner`].  No shell strings.

use std::collections::BTreeMap;

use crate::{
    command::runner::{CommandOutput, CommandRunner, CommandSpec},
    error::ForgeError,
};

// ---------------------------------------------------------------
// Naming
// ---------------------------------------------------------------

/// Verify the resolved runtime supports cross-cluster networking.
///
/// `KIND_EXPERIMENTAL_DOCKER_NETWORK` is Docker-only; Podman does not
/// support it.  Call after `runtime::resolve()` when cross-cluster
/// networking is configured.
///
/// # Errors
///
/// Returns [`ForgeError::Config`] if the resolved binary is not Docker.
pub fn require_docker_for_cross_cluster(binary: &str) -> Result<(), ForgeError> {
    if binary == "docker" {
        return Ok(());
    }
    Err(ForgeError::Config(format!(
        "cross-cluster networking requires Docker, but runtime resolved to {binary:?}"
    )))
}

/// Build the deterministic network name: `"{env_name}-net"`.
pub fn network_name(env_name: &str) -> String {
    format!("{env_name}-net")
}

// ---------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------

/// Create a container network with ownership labels.
///
/// Returns the runtime network ID only when this call creates the network.
/// An existing network must have matching ownership labels and returns `None`.
///
/// # Errors
///
/// Returns [`ForgeError`] if the network cannot be created or
/// an existing network has mismatched ownership labels.
pub fn create_network(
    runner: &dyn CommandRunner,
    binary: &str,
    net_name: &str,
    env_name: &str,
) -> Result<Option<String>, ForgeError> {
    if network_exists(runner, binary, net_name)? {
        verify_ownership(runner, binary, net_name, env_name)?;
        return Ok(None);
    }
    let spec = create_spec(binary, net_name, env_name);
    let output = runner.run(&spec)?;
    check_success(&output, "network create")?;
    if std::path::Path::new(binary)
        .file_name()
        .is_some_and(|name| name == "podman")
    {
        return inspect_network_id(runner, binary, net_name).map(Some);
    }
    validate_network_id(output.stdout.trim()).map(|id| Some(id.to_owned()))
}

/// Remove a container network after verifying ownership.
///
/// Idempotent: returns `Ok(())` if the network does not exist.
///
/// # Errors
///
/// Returns [`ForgeError`] if ownership verification fails or
/// the network cannot be removed.
pub fn remove_network(
    runner: &dyn CommandRunner,
    binary: &str,
    net_name: &str,
    env_name: &str,
) -> Result<(), ForgeError> {
    if !network_exists(runner, binary, net_name)? {
        return Ok(());
    }
    verify_ownership(runner, binary, net_name, env_name)?;
    let spec = remove_spec(binary, net_name);
    let output = runner.run(&spec)?;
    check_success(&output, "network rm")
}

/// Check whether a container network with the given name exists.
///
/// # Errors
///
/// Returns [`ForgeError`] if the runtime binary cannot execute, or if the
/// inspect fails for any reason other than the network being absent.
pub fn network_exists(runner: &dyn CommandRunner, binary: &str, net_name: &str) -> Result<bool, ForgeError> {
    let spec = inspect_spec(binary, net_name);
    let output = runner.run(&spec)?;
    if output.status == 0 {
        return Ok(true);
    }
    // A non-zero exit means "absent" only when the runtime says so. Reporting
    // absent for e.g. a stopped daemon makes `remove_network` a silent no-op,
    // and `down` then records the network as Gone while it is still there.
    if is_absent_error(&output.stderr, net_name) {
        return Ok(false);
    }
    // Reuses the shared error shape; the Ok arm is unreachable because a zero
    // status returned above.
    check_success(&output, "network inspect").map(|()| false)
}

/// Check whether inspect stderr reports a missing network rather than a fault.
///
/// Only the runtimes' actual absent-network phrasings are accepted, not the
/// words "network" and "no such"/"not found" merely appearing somewhere in
/// the message. With the daemon down, Docker reports "connect: no such file
/// or directory", and a corrupted networking store reports "open
/// /var/lib/docker/network/files/local-kv.db: no such file or directory":
/// both carry absence wording (the latter even the word "network") while
/// proving nothing about the network itself. Treating either as absence is
/// precisely the bug this function exists to prevent.
///
/// Recognised absent-network wording:
/// - Docker: `Error: No such network: x`
/// - Docker: `Error response from daemon: network x not found`
/// - Podman: `unable to find network with name or ID x: network not found`
fn is_absent_error(stderr: &str, net_name: &str) -> bool {
    let lower = stderr.to_lowercase();
    lower.contains("no such network")
        || lower.contains("network not found")
        || lower.contains(&format!("network {} not found", net_name.to_lowercase()))
}

/// Read the current IPv4 subnet from a container network.
///
/// # Errors
///
/// Returns [`ForgeError`] if the inspect command fails or the network does
/// not expose a valid IPv4 subnet.
pub fn inspect_network_cidr(runner: &dyn CommandRunner, binary: &str, net_name: &str) -> Result<String, ForgeError> {
    let spec = cidr_spec(binary, net_name);
    let output = runner.run(&spec)?;
    check_success(&output, "network inspect")?;
    parse_ipam_config(&output.stdout)
}

/// Inspect the immutable runtime identity of a named network.
///
/// # Errors
///
/// Returns [`ForgeError`] if inspection fails or contains no full network ID.
pub fn inspect_network_id(runner: &dyn CommandRunner, binary: &str, name: &str) -> Result<String, ForgeError> {
    let output = runner.run(&cidr_spec(binary, name))?;
    check_success(&output, "network inspect")?;
    let value: serde_json::Value = serde_json::from_str(&output.stdout)
        .map_err(|error| ForgeError::State(format!("cannot parse network identity: {error}")))?;
    let object = value.get(0).unwrap_or(&value);
    let id = object
        .get("Id")
        .or_else(|| object.get("ID"))
        .or_else(|| object.get("id"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ForgeError::State("network inspect omitted its runtime ID".to_owned()))?;
    validate_network_id(id).map(ToOwned::to_owned)
}

/// Accept only the full hexadecimal runtime ID, never a reusable network name.
fn validate_network_id(id: &str) -> Result<&str, ForgeError> {
    if id.len() == 64 && id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Ok(id);
    }
    Err(ForgeError::State(
        "network runtime ID must contain 64 hexadecimal characters".to_owned(),
    ))
}

// ---------------------------------------------------------------
// Ownership
// ---------------------------------------------------------------

/// Verify that an existing network is owned by this environment.
fn verify_ownership(
    runner: &dyn CommandRunner,
    binary: &str,
    net_name: &str,
    env_name: &str,
) -> Result<(), ForgeError> {
    let labels = inspect_labels(runner, binary, net_name)?;
    check_label(&labels, "forge.managed", "true", net_name)?;
    check_label(&labels, "forge.environment", env_name, net_name)
}

/// Fetch labels from an existing network.
fn inspect_labels(
    runner: &dyn CommandRunner,
    binary: &str,
    net_name: &str,
) -> Result<BTreeMap<String, String>, ForgeError> {
    let spec = labels_spec(binary, net_name);
    let output = runner.run(&spec)?;
    check_success(&output, "network inspect")?;
    parse_labels(&output.stdout)
}

/// Verify a single label value matches the expected value.
fn check_label(labels: &BTreeMap<String, String>, key: &str, expected: &str, net_name: &str) -> Result<(), ForgeError> {
    match labels.get(key) {
        Some(val) if val == expected => Ok(()),
        Some(val) => Err(ownership_mismatch(net_name, key, expected, val)),
        None => Err(missing_label(net_name, key)),
    }
}

/// Build an error for a mismatched ownership label.
fn ownership_mismatch(net_name: &str, key: &str, expected: &str, actual: &str) -> ForgeError {
    ForgeError::State(format!("network '{net_name}' has {key}={actual}, expected {expected}"))
}

/// Build an error for a missing ownership label.
fn missing_label(net_name: &str, key: &str) -> ForgeError {
    ForgeError::State(format!(
        "network '{net_name}' missing label {key} \u{2014} not managed by Forge"
    ))
}

// ---------------------------------------------------------------
// Command specs
// ---------------------------------------------------------------

/// Build a `<binary> network create` command spec with labels.
fn create_spec(binary: &str, net_name: &str, env_name: &str) -> CommandSpec {
    CommandSpec {
        program: binary.into(),
        args: vec![
            "network".into(),
            "create".into(),
            "--label".into(),
            "forge.managed=true".into(),
            "--label".into(),
            format!("forge.environment={env_name}").into(),
            net_name.into(),
        ],
        env: BTreeMap::default(),
        stdin: None,
        redact: Vec::new(),
    }
}

/// Build a `<binary> network rm` command spec.
fn remove_spec(binary: &str, net_name: &str) -> CommandSpec {
    CommandSpec {
        program: binary.into(),
        args: vec!["network".into(), "rm".into(), net_name.into()],
        env: BTreeMap::default(),
        stdin: None,
        redact: Vec::new(),
    }
}

/// Build a `<binary> network inspect` command spec.
fn inspect_spec(binary: &str, net_name: &str) -> CommandSpec {
    CommandSpec {
        program: binary.into(),
        args: vec!["network".into(), "inspect".into(), net_name.into()],
        env: BTreeMap::default(),
        stdin: None,
        redact: Vec::new(),
    }
}

/// Build a `<binary> network inspect --format` spec for labels.
fn labels_spec(binary: &str, net_name: &str) -> CommandSpec {
    CommandSpec {
        program: binary.into(),
        args: vec![
            "network".into(),
            "inspect".into(),
            net_name.into(),
            "--format".into(),
            "{{json .Labels}}".into(),
        ],
        env: BTreeMap::default(),
        stdin: None,
        redact: Vec::new(),
    }
}

/// Build a `<binary> network inspect --format` spec for the IPAM config.
fn cidr_spec(binary: &str, net_name: &str) -> CommandSpec {
    CommandSpec {
        program: binary.into(),
        args: vec![
            "network".into(),
            "inspect".into(),
            net_name.into(),
            "--format".into(),
            "{{json .}}".into(),
        ],
        env: BTreeMap::default(),
        stdin: None,
        redact: Vec::new(),
    }
}

// ---------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------

/// Parse JSON labels from `docker network inspect --format` output.
///
/// A network created outside Forge can have a nil label map, which
/// `{{json .Labels}}` prints as the literal `null`.  Both that and an
/// empty output mean "no labels", so ownership verification can report
/// the actionable "not managed by Forge" instead of a parse error.
fn parse_labels(stdout: &str) -> Result<BTreeMap<String, String>, ForgeError> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() || trimmed == "null" {
        return Ok(BTreeMap::new());
    }
    serde_json::from_str(trimmed).map_err(|err| ForgeError::State(format!("cannot parse network labels: {err}")))
}

/// Parse and validate the first IPv4 subnet in `network inspect` JSON.
fn parse_ipam_config(stdout: &str) -> Result<String, ForgeError> {
    let network: serde_json::Value = serde_json::from_str(stdout.trim())
        .map_err(|err| ForgeError::State(format!("cannot parse network IPAM config: {err}")))?;
    let subnet = first_ipv4_subnet(&network)
        .ok_or_else(|| ForgeError::State("network IPAM config has no IPv4 subnet".to_owned()))?;
    validate_ipv4_cidr(subnet)?;
    Ok(subnet.to_owned())
}

/// First IPv4 subnet of an inspected network, in Docker (`IPAM.Config[].Subnet`) or Podman (`subnets[].subnet`) shape.
pub(crate) fn first_ipv4_subnet(network: &serde_json::Value) -> Option<&str> {
    let network = network.as_array().and_then(|all| all.first()).unwrap_or(network);
    let docker = network.pointer("/IPAM/Config").and_then(serde_json::Value::as_array);
    let podman = network.get("subnets").and_then(serde_json::Value::as_array);
    docker
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.get("Subnet"))
        .chain(podman.into_iter().flatten().filter_map(|entry| entry.get("subnet")))
        .filter_map(serde_json::Value::as_str)
        .find(|subnet| !subnet.contains(':'))
}

/// Validate an IPv4 CIDR without accepting host-only or IPv6 forms.
fn validate_ipv4_cidr(cidr: &str) -> Result<(), ForgeError> {
    let (address, prefix) = cidr
        .split_once('/')
        .ok_or_else(|| ForgeError::State(format!("network subnet is not CIDR: {cidr:?}")))?;
    address
        .parse::<std::net::Ipv4Addr>()
        .map_err(|err| ForgeError::State(format!("network subnet has an invalid IPv4 address: {err}")))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|err| ForgeError::State(format!("network subnet has an invalid prefix: {err}")))?;
    if prefix > 32 {
        return Err(ForgeError::State(format!(
            "network subnet prefix /{prefix} exceeds /32"
        )));
    }
    Ok(())
}

/// Check command output for success (exit code 0).
fn check_success(output: &CommandOutput, context: &str) -> Result<(), ForgeError> {
    if output.status == 0 {
        return Ok(());
    }
    Err(ForgeError::Command {
        program: context.to_owned(),
        message: format!("exit code {}: {}", output.status, output.stderr.trim()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::runner::MockRunner;

    /// Successful empty command output.
    fn ok() -> CommandOutput {
        CommandOutput {
            status: 0,
            stdout: String::new(),
            stderr: String::new(),
        }
    }

    /// Failed command output (network not found).
    fn not_found() -> CommandOutput {
        CommandOutput {
            status: 1,
            stdout: String::new(),
            stderr: "network test-net not found\n".to_owned(),
        }
    }

    /// Labels JSON for a Forge-managed network.
    fn owned_labels(env: &str) -> CommandOutput {
        CommandOutput {
            status: 0,
            stdout: format!(r#"{{"forge.managed":"true","forge.environment":"{env}"}}"#),
            stderr: String::new(),
        }
    }

    /// Labels JSON for a network not managed by Forge.
    fn foreign_labels() -> CommandOutput {
        CommandOutput {
            status: 0,
            stdout: r#"{"some.other":"label"}"#.to_owned(),
            stderr: String::new(),
        }
    }

    /// Formatted Docker IPAM response for one IPv4 subnet.
    fn ipam_config(cidr: &str) -> CommandOutput {
        CommandOutput {
            status: 0,
            stdout: format!(r#"{{"IPAM":{{"Config":[{{"Subnet":"{cidr}","Gateway":"172.18.0.1"}}]}}}}"#),
            stderr: String::new(),
        }
    }

    #[test]
    fn network_name_format() {
        assert_eq!(network_name("test"), "test-net", "simple name");
        assert_eq!(network_name("prod-env"), "prod-env-net", "hyphenated name");
    }

    #[test]
    fn create_when_not_exists() {
        let mut runner = MockRunner::new();
        runner.respond("docker network inspect test-net", not_found());
        runner.respond("docker", ok());
        runner.respond(
            "docker network create",
            CommandOutput {
                status: 0,
                stdout: "a".repeat(64),
                stderr: String::new(),
            },
        );

        let _created = create_network(&runner, "docker", "test-net", "test").unwrap_or_else(|_| std::process::abort());
        assert!(runner.was_called("network create"), "should call network create");
        assert!(runner.was_called("forge.managed=true"), "should include managed label");
        assert!(runner.was_called("forge.environment=test"), "should include env label");
    }

    #[test]
    fn create_skips_when_exists_with_correct_owner() {
        let mut runner = MockRunner::new();
        runner.respond("docker network inspect test-net", ok());
        runner.respond(
            "docker network inspect test-net --format {{json .Labels}}",
            owned_labels("test"),
        );

        let _created = create_network(&runner, "docker", "test-net", "test").unwrap_or_else(|_| std::process::abort());
        assert!(
            !runner.was_called("network create"),
            "should not create existing network"
        );
    }

    #[test]
    fn create_rejects_wrong_owner() {
        let mut runner = MockRunner::new();
        runner.respond("docker network inspect test-net", ok());
        runner.respond(
            "docker network inspect test-net --format {{json .Labels}}",
            owned_labels("other-env"),
        );

        let result = create_network(&runner, "docker", "test-net", "test");
        let Err(err) = result else {
            std::process::abort();
        };
        let msg = err.to_string();
        assert!(
            msg.contains("expected test"),
            "error should mention expected env: {msg}"
        );
    }

    #[test]
    fn create_rejects_unmanaged_network() {
        let mut runner = MockRunner::new();
        runner.respond("docker network inspect test-net", ok());
        runner.respond(
            "docker network inspect test-net --format {{json .Labels}}",
            foreign_labels(),
        );

        let result = create_network(&runner, "docker", "test-net", "test");
        assert!(result.is_err(), "should reject unmanaged network");
    }

    #[test]
    fn remove_with_correct_owner() {
        let mut runner = MockRunner::new();
        runner.respond("docker network inspect test-net", ok());
        runner.respond(
            "docker network inspect test-net --format {{json .Labels}}",
            owned_labels("test"),
        );
        runner.respond("docker network rm test-net", ok());

        remove_network(&runner, "docker", "test-net", "test").unwrap_or_else(|_| std::process::abort());
        assert!(runner.was_called("network rm"), "should call network rm");
    }

    #[test]
    fn remove_skips_when_not_exists() {
        let mut runner = MockRunner::new();
        runner.respond("docker network inspect test-net", not_found());

        remove_network(&runner, "docker", "test-net", "test").unwrap_or_else(|_| std::process::abort());
        assert!(
            !runner.was_called("network rm"),
            "should not call rm on missing network"
        );
    }

    #[test]
    fn remove_rejects_wrong_owner() {
        let mut runner = MockRunner::new();
        runner.respond("docker network inspect test-net", ok());
        runner.respond(
            "docker network inspect test-net --format {{json .Labels}}",
            owned_labels("other-env"),
        );

        let result = remove_network(&runner, "docker", "test-net", "test");
        assert!(result.is_err(), "should reject mismatched owner on remove");
    }

    #[test]
    fn remove_refuses_unmanaged_network() {
        let mut runner = MockRunner::new();
        runner.respond("docker network inspect test-net", ok());
        runner.respond(
            "docker network inspect test-net --format {{json .Labels}}",
            foreign_labels(),
        );

        let result = remove_network(&runner, "docker", "test-net", "test");
        assert!(result.is_err(), "should reject unmanaged network on remove");
        assert!(!runner.was_called("network rm"), "must not remove unmanaged network");
    }

    #[test]
    fn exists_errors_when_runtime_fails() {
        let mut runner = MockRunner::new();
        runner.respond(
            "docker network inspect test-net",
            CommandOutput {
                status: 1,
                stdout: "[]\n".to_owned(),
                // Verbatim from Docker 29.3.1 with the daemon stopped. It says
                // "no such", which an absence-wording-only matcher accepts.
                stderr: "failed to connect to the docker API at \
                         unix:///var/run/docker.sock; check if the path is correct \
                         and if the daemon is running: dial unix \
                         /var/run/docker.sock: connect: no such file or directory"
                    .to_owned(),
            },
        );

        let result = network_exists(&runner, "docker", "test-net");
        assert!(
            result.is_err(),
            "a stopped daemon must not be reported as an absent network"
        );
    }

    #[test]
    fn absent_network_wording_is_recognised() {
        for stderr in [
            "Error: No such network: test-net",
            "Error response from daemon: network test-net not found",
            "unable to find network with name or ID test-net: network not found",
        ] {
            assert!(
                is_absent_error(stderr, "test-net"),
                "real absent-network wording should be recognised: {stderr}"
            );
        }
    }

    #[test]
    fn runtime_fault_wording_is_not_absence() {
        for stderr in [
            "failed to connect to the docker API at unix:///var/run/docker.sock: \
             dial unix /var/run/docker.sock: connect: no such file or directory",
            "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. \
             Is the docker daemon running?",
            "Error: context \"missing\" not found",
            "permission denied while trying to connect to the Docker daemon socket",
            // Networking-store corruption: contains both "network" and
            // "no such", yet says nothing about the network's existence.
            "Error response from daemon: open /var/lib/docker/network/files/local-kv.db: \
             no such file or directory",
        ] {
            assert!(
                !is_absent_error(stderr, "test-net"),
                "a runtime fault must not read as absence: {stderr}"
            );
        }
    }

    #[test]
    fn exists_true_when_present() {
        let mut runner = MockRunner::new();
        runner.respond("docker network inspect test-net", ok());

        let exists = network_exists(&runner, "docker", "test-net").unwrap_or_else(|_| {
            std::process::abort();
            #[expect(unreachable_code, reason = "abort prevents reaching this")]
            {
                unreachable!()
            }
        });
        assert!(exists, "should report network as existing");
    }

    #[test]
    fn exists_false_when_missing() {
        let mut runner = MockRunner::new();
        runner.respond("docker network inspect test-net", not_found());

        let exists = network_exists(&runner, "docker", "test-net").unwrap_or_else(|_| {
            std::process::abort();
            #[expect(unreachable_code, reason = "abort prevents reaching this")]
            {
                unreachable!()
            }
        });
        assert!(!exists, "should report network as not existing");
    }

    #[test]
    fn inspect_network_cidr_reads_formatted_ipam_config() {
        let mut runner = MockRunner::new();
        runner.respond(
            "docker network inspect test-net --format {{json .}}",
            ipam_config("172.18.0.0/16"),
        );

        let cidr = inspect_network_cidr(&runner, "docker", "test-net").unwrap_or_else(|_| std::process::abort());
        assert_eq!(cidr, "172.18.0.0/16");
    }

    #[test]
    fn inspect_network_cidr_rejects_invalid_subnet() {
        let mut runner = MockRunner::new();
        runner.respond(
            "docker network inspect test-net --format {{json .}}",
            ipam_config("fd00::/64"),
        );

        assert!(
            inspect_network_cidr(&runner, "docker", "test-net").is_err(),
            "IPv6 must not be accepted by the IPv4 MetalLB allocator"
        );
    }

    #[test]
    fn parse_labels_valid_json() {
        let input = r#"{"forge.managed":"true","forge.environment":"test"}"#;
        let labels = parse_labels(input).unwrap_or_else(|_| {
            std::process::abort();
            #[expect(unreachable_code, reason = "abort prevents reaching this")]
            {
                unreachable!()
            }
        });
        assert_eq!(
            labels.get("forge.managed").map(String::as_str),
            Some("true"),
            "managed label"
        );
        assert_eq!(
            labels.get("forge.environment").map(String::as_str),
            Some("test"),
            "env label"
        );
    }

    #[test]
    fn parse_labels_empty_string() {
        let labels = parse_labels("").unwrap_or_else(|_| {
            std::process::abort();
            #[expect(unreachable_code, reason = "abort prevents reaching this")]
            {
                unreachable!()
            }
        });
        assert!(labels.is_empty(), "empty input should yield empty map");
    }

    #[test]
    fn parse_labels_null_literal() {
        // A nil label map is printed by `{{json .Labels}}` as the literal
        // `null` for networks created outside Forge.
        let labels = parse_labels("null\n").unwrap_or_else(|_| {
            std::process::abort();
            #[expect(unreachable_code, reason = "abort prevents reaching this")]
            {
                unreachable!()
            }
        });
        assert!(labels.is_empty(), "null input should yield empty map");
    }

    #[test]
    fn remove_reports_null_labels_as_unmanaged() {
        let mut runner = MockRunner::new();
        runner.respond("docker network inspect test-net", ok());
        runner.respond(
            "docker network inspect test-net --format {{json .Labels}}",
            CommandOutput {
                status: 0,
                stdout: "null\n".to_owned(),
                stderr: String::new(),
            },
        );

        let Err(err) = remove_network(&runner, "docker", "test-net", "test") else {
            std::process::abort();
        };
        let msg = err.to_string();
        assert!(
            msg.contains("not managed by Forge"),
            "a nil label map should read as unmanaged, not a parse error: {msg}"
        );
    }

    #[test]
    fn podman_uses_correct_binary() {
        let mut runner = MockRunner::new();
        runner.respond("podman network inspect test-net", not_found());
        runner.respond("podman", ok());

        runner.respond(
            "podman network inspect test-net --format {{json .}}",
            CommandOutput {
                status: 0,
                stdout: format!(r#"{{"id":"{}"}}"#, "a".repeat(64)),
                stderr: String::new(),
            },
        );
        let _created = create_network(&runner, "podman", "test-net", "test").unwrap_or_else(|_| std::process::abort());
        assert!(runner.was_called("podman"), "should use podman binary");
    }

    #[test]
    fn network_cidr_accepts_docker_and_podman_ipv6_first_results() -> Result<(), ForgeError> {
        for json in [
            r#"{"IPAM":{"Config":[{"Subnet":"fd00::/64"},{"Subnet":"172.18.0.0/16"}]}}"#,
            r#"{"subnets":[{"subnet":"fd00::/64"},{"subnet":"172.18.0.0/16"}]}"#,
            r#"[{"subnets":[{"subnet":"fd00::/64"},{"subnet":"172.18.0.0/16"}]}]"#,
        ] {
            assert_eq!(
                parse_ipam_config(json)?,
                "172.18.0.0/16",
                "IPv4 allocator must skip preceding IPv6 for both runtimes"
            );
        }
        Ok(())
    }

    #[test]
    fn network_identity_accepts_runtime_inspect_shapes() -> Result<(), ForgeError> {
        let id = "a".repeat(64);
        for json in [
            format!(r#"{{"Id":"{id}"}}"#),
            format!(r#"{{"id":"{id}"}}"#),
            format!(r#"[{{"ID":"{id}"}}]"#),
        ] {
            let mut runner = MockRunner::new();
            runner.respond(
                "docker",
                CommandOutput {
                    status: 0,
                    stdout: json,
                    stderr: String::new(),
                },
            );
            assert_eq!(inspect_network_id(&runner, "docker", "test-net")?, id);
        }
        assert!(
            validate_network_id("test-net").is_err(),
            "a reusable name is not an identity"
        );
        Ok(())
    }
}
