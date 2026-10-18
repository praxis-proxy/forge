//! The `status` command: show environment status.
//!
//! Cross-references the persisted state, the live KIND cluster list,
//! and the configuration to produce a unified view.

use std::io::Write;

use crate::{
    cluster::kind as kind_ops,
    command::runner::CommandRunner,
    context::ForgeContext,
    error::ForgeError,
    output::{self, OutputFormat},
    service::{self, ServiceIdentity},
    state,
};

/// Run the `status` command (read-only, no lock).
///
/// # Errors
///
/// Returns [`ForgeError`] if state loading fails. A failed KIND probe
/// does not abort the report; affected entries render with an unknown
/// live status instead.
pub fn run(ctx: &ForgeContext<'_>, writer: &mut dyn Write) -> Result<(), ForgeError> {
    let st = state::load(&ctx.state_dir)?;
    let live = probe_live(ctx, &st);
    let entries = build_entries(ctx, &st, live.as_deref());
    let net_info = network_info(&st);
    let svc_entries = service_entries(ctx.runner, st.runtime.as_deref(), &st);
    render_all(writer, &entries, net_info.as_ref(), &svc_entries, &ctx.format)
}

/// Probe the live KIND cluster list, degrading gracefully.
///
/// The probe is skipped when neither config nor state tracks a
/// cluster: a services-only environment must not require `kind` to be
/// installed just to report status. A failed probe returns `None` so
/// state phases, network info, and service entries stay visible with
/// per-cluster live status marked unknown, rather than one failed
/// probe suppressing the entire report.
fn probe_live(ctx: &ForgeContext<'_>, st: &state::ForgeState) -> Option<Vec<String>> {
    if ctx.config.spec.clusters.is_empty() && st.clusters.is_empty() {
        return Some(Vec::new());
    }
    let provider = ctx.kind_provider(st).ok()?;
    kind_ops::list_clusters(ctx.runner, provider).ok()
}

// ---------------------------------------------------------------
// Status entries
// ---------------------------------------------------------------

/// Status information for one cluster.
struct StatusEntry {
    /// Cluster name from config or state.
    name: String,
    /// KIND cluster name.
    kind_name: String,
    /// State phase, if tracked.
    state_phase: String,
    /// Whether a live KIND cluster was found; `None` if the probe failed.
    live: Option<bool>,
    /// Whether the current config still lists this cluster.
    in_config: bool,
}

/// Build status entries from config, state, and live clusters.
fn build_entries(ctx: &ForgeContext<'_>, st: &state::ForgeState, live: Option<&[String]>) -> Vec<StatusEntry> {
    let mut entries: Vec<StatusEntry> = ctx
        .config
        .spec
        .clusters
        .iter()
        .map(|cluster| entry_for_cluster(ctx, st, live, &cluster.name))
        .collect();
    entries.extend(state_only_entries(ctx, st, live));
    entries
}

/// Build a status entry for one configured cluster.
fn entry_for_cluster(
    ctx: &ForgeContext<'_>,
    st: &state::ForgeState,
    live: Option<&[String]>,
    name: &str,
) -> StatusEntry {
    let kind_name = kind_ops::kind_cluster_name(&ctx.config.spec.runtime.cluster_prefix, name);
    let state_phase = state_phase_label(st, name);
    let is_live = live.map(|list| list.contains(&kind_name));
    StatusEntry {
        name: name.to_owned(),
        kind_name,
        state_phase,
        live: is_live,
        in_config: true,
    }
}

/// Build entries for state-tracked clusters absent from the config.
///
/// `forge down` deletes every non-Gone cluster recorded in state, so a
/// cluster removed from the config after it was created must still be
/// visible here; hiding it would make status omit exactly the
/// resources the user is most likely to have forgotten about.
fn state_only_entries(ctx: &ForgeContext<'_>, st: &state::ForgeState, live: Option<&[String]>) -> Vec<StatusEntry> {
    st.clusters
        .iter()
        .filter(|cluster| cluster.phase != state::ClusterPhase::Gone)
        .filter(|cluster| !ctx.config.spec.clusters.iter().any(|spec| spec.name == cluster.name))
        .map(|cluster| StatusEntry {
            name: cluster.name.clone(),
            kind_name: cluster.kind_name.clone(),
            state_phase: format!("{:?}", cluster.phase).to_lowercase(),
            live: live.map(|list| list.contains(&cluster.kind_name)),
            in_config: false,
        })
        .collect()
}

/// Get the state phase label for a cluster, or "unknown".
fn state_phase_label(st: &state::ForgeState, name: &str) -> String {
    state::find_cluster(st, name).map_or_else(|| "unknown".to_owned(), |cl| format!("{:?}", cl.phase).to_lowercase())
}

// ---------------------------------------------------------------
// Network status
// ---------------------------------------------------------------

/// Network status information.
struct NetInfo {
    /// Network name.
    name: String,
    /// Phase label (e.g. "active", "gone").
    phase: String,
}

/// Extract network status from state.
fn network_info(st: &state::ForgeState) -> Option<NetInfo> {
    st.network.as_ref().map(|ns| NetInfo {
        name: ns.name.clone(),
        phase: format!("{:?}", ns.phase).to_lowercase(),
    })
}

// ---------------------------------------------------------------
// Service status
// ---------------------------------------------------------------

/// Status information for one service.
struct SvcEntry {
    /// Service name.
    name: String,
    /// Container name.
    container_name: String,
    /// Phase label (e.g. "running", "stopped").
    phase: String,
    /// Health label (e.g. "healthy", "unknown").
    health: String,
    /// Live container identity from runtime inspect.
    identity: ServiceIdentity,
}

/// Build service status entries from state with live identity.
fn service_entries(runner: &dyn CommandRunner, binary: Option<&str>, st: &state::ForgeState) -> Vec<SvcEntry> {
    st.services
        .iter()
        .map(|svc| SvcEntry {
            name: svc.name.clone(),
            container_name: svc.container_name.clone(),
            phase: format!("{:?}", svc.phase).to_lowercase(),
            health: format!("{:?}", svc.health).to_lowercase(),
            identity: inspect_live(runner, binary, &svc.container_name),
        })
        .collect()
}

/// Inspect a container for identity, falling back to empty on error.
fn inspect_live(runner: &dyn CommandRunner, binary: Option<&str>, container_name: &str) -> ServiceIdentity {
    let Some(bin) = binary else {
        return ServiceIdentity::empty();
    };
    match service::inspect_identity(runner, bin, container_name) {
        Ok(id) => id,
        Err(_) => ServiceIdentity::empty(),
    }
}

// ---------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------

/// Render all status entries.
fn render_all(
    writer: &mut dyn Write,
    entries: &[StatusEntry],
    net: Option<&NetInfo>,
    services: &[SvcEntry],
    format: &OutputFormat,
) -> Result<(), ForgeError> {
    match format {
        OutputFormat::Json => render_json(writer, entries, net, services),
        OutputFormat::Text => render_text(writer, entries, net, services),
    }
}

/// Render entries as JSON.
fn render_json(
    writer: &mut dyn Write,
    entries: &[StatusEntry],
    net: Option<&NetInfo>,
    services: &[SvcEntry],
) -> Result<(), ForgeError> {
    let items: Vec<_> = entries.iter().map(entry_to_json).collect();
    let mut data = serde_json::json!({ "clusters": items });
    if let (Some(network), Some(obj)) = (net, data.as_object_mut()) {
        obj.insert(
            "network".to_owned(),
            serde_json::json!({ "name": network.name, "phase": network.phase }),
        );
    }
    if let (false, Some(obj)) = (services.is_empty(), data.as_object_mut()) {
        let svc_items: Vec<_> = services.iter().map(svc_to_json).collect();
        obj.insert("services".to_owned(), serde_json::json!(svc_items));
    }
    let envelope = output::success(data);
    output::write_json(writer, &envelope)?;
    Ok(())
}

/// Convert one service entry to JSON.
fn svc_to_json(svc: &SvcEntry) -> serde_json::Value {
    serde_json::json!({
        "name": svc.name,
        "containerName": svc.container_name,
        "phase": svc.phase,
        "health": svc.health,
        "containerId": svc.identity.container_id,
        "startedAt": svc.identity.started_at,
        "restartCount": svc.identity.restart_count,
    })
}

/// Convert one entry to JSON.
fn entry_to_json(entry: &StatusEntry) -> serde_json::Value {
    serde_json::json!({
        "name": entry.name,
        "kindName": entry.kind_name,
        "statePhase": entry.state_phase,
        "live": entry.live,
        "inConfig": entry.in_config,
    })
}

/// Render entries as text.
fn render_text(
    writer: &mut dyn Write,
    entries: &[StatusEntry],
    net: Option<&NetInfo>,
    services: &[SvcEntry],
) -> Result<(), ForgeError> {
    if let Some(network) = net {
        output::write_text(writer, &format!("  network: {} ({})", network.name, network.phase))?;
    }
    for entry in entries {
        output::write_text(writer, &format_entry_text(entry))?;
    }
    for svc in services {
        output::write_text(writer, &format_svc_text(svc))?;
    }
    Ok(())
}

/// Format a service entry as a text line.
fn format_svc_text(svc: &SvcEntry) -> String {
    let id_label = svc
        .identity
        .container_id
        .as_deref()
        .map_or("none", |id| id.get(..12).unwrap_or(id));
    format!(
        "  {}: phase={}, health={}, container={}, id={}",
        svc.name, svc.phase, svc.health, svc.container_name, id_label
    )
}

/// Format one entry as a text line.
fn format_entry_text(entry: &StatusEntry) -> String {
    let live_label = match entry.live {
        Some(true) => "live",
        Some(false) => "not found",
        None => "live unknown",
    };
    let config_label = if entry.in_config { "" } else { ", not in config" };
    format!(
        "  {}: state={}, kind={} ({}{})",
        entry.name, entry.state_phase, entry.kind_name, live_label, config_label
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        command::runner::{CommandOutput, MockRunner},
        state::{ClusterPhase, ClusterState},
    };

    /// Build a minimal config.
    fn test_config() -> crate::config::ForgeConfig {
        let yaml = "\
apiVersion: forge.praxis.dev/v1alpha1
kind: Environment
metadata:
  name: test
spec:
  runtime:
    provider: docker
    clusterPrefix: forge
  clusters:
    - name: hub
  services: []
  stacks: {}
";
        serde_yaml::from_str(yaml).unwrap_or_else(|_| {
            std::process::abort();
            #[expect(unreachable_code, reason = "abort prevents reaching this")]
            {
                unreachable!()
            }
        })
    }

    /// Create a temp dir for test state.
    fn test_dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap_or_else(|_| {
            std::process::abort();
            #[expect(unreachable_code, reason = "abort prevents reaching this")]
            {
                unreachable!()
            }
        })
    }

    /// Seed state with a running hub cluster.
    fn seed_running_hub(state_dir: &std::path::Path) {
        let mut st = state::empty();
        st.clusters.push(ClusterState {
            name: "hub".to_owned(),
            kind_name: "forge-hub".to_owned(),
            context: "kind-forge-hub".to_owned(),
            phase: ClusterPhase::Running,
        });
        state::save(state_dir, &st).unwrap_or_else(|_| std::process::abort());
    }

    /// Run status and return output text.
    fn run_status(ctx: &ForgeContext<'_>) -> String {
        let mut buf = Vec::new();
        run(ctx, &mut buf).unwrap_or_else(|_| std::process::abort());
        String::from_utf8_lossy(&buf).into_owned()
    }

    #[test]
    fn status_reports_running_cluster() {
        let dir = test_dir();
        seed_running_hub(dir.path());
        let config = test_config();
        let mut runner = MockRunner::with_runtime("docker");
        runner.respond(
            "kind get clusters",
            CommandOutput {
                status: 0,
                stdout: "forge-hub\n".to_owned(),
                stderr: String::new(),
            },
        );
        let ctx = ForgeContext {
            runner: &runner,
            config: &config,
            state_dir: dir.path().to_path_buf(),
            config_dir: dir.path().to_path_buf(),
            format: OutputFormat::Text,
            dry_run: false,
        };
        let text = run_status(&ctx);
        assert!(text.contains("running"), "should show running: {text}");
        assert!(text.contains("live"), "should show live: {text}");
    }

    #[test]
    fn status_reports_missing_cluster() {
        let dir = test_dir();
        let config = test_config();
        let mut runner = MockRunner::with_runtime("docker");
        runner.respond(
            "kind get clusters",
            CommandOutput {
                status: 0,
                stdout: String::new(),
                stderr: String::new(),
            },
        );
        let ctx = ForgeContext {
            runner: &runner,
            config: &config,
            state_dir: dir.path().to_path_buf(),
            config_dir: dir.path().to_path_buf(),
            format: OutputFormat::Text,
            dry_run: false,
        };
        let text = run_status(&ctx);
        assert!(text.contains("unknown"), "should show unknown state: {text}");
        assert!(text.contains("not found"), "should show not found: {text}");
    }

    /// Build a config with no clusters and no services.
    fn test_config_clusterless() -> crate::config::ForgeConfig {
        let yaml = "\
apiVersion: forge.praxis.dev/v1alpha1
kind: Environment
metadata:
  name: test
spec:
  runtime:
    provider: docker
    clusterPrefix: forge
  clusters: []
  services: []
  stacks: {}
";
        serde_yaml::from_str(yaml).unwrap_or_else(|_| {
            std::process::abort();
            #[expect(unreachable_code, reason = "abort prevents reaching this")]
            {
                unreachable!()
            }
        })
    }

    #[test]
    fn status_skips_kind_probe_without_clusters() {
        let dir = test_dir();
        let config = test_config_clusterless();
        // No responses registered: any kind invocation would error.
        let runner = MockRunner::new();
        let ctx = ForgeContext {
            runner: &runner,
            config: &config,
            state_dir: dir.path().to_path_buf(),
            config_dir: dir.path().to_path_buf(),
            format: OutputFormat::Text,
            dry_run: false,
        };

        let mut buf = Vec::new();
        run(&ctx, &mut buf).unwrap_or_else(|_| std::process::abort());

        assert!(
            !runner.was_called("kind get clusters"),
            "a cluster-free environment must not require kind for status"
        );
    }

    #[test]
    fn status_degrades_to_unknown_when_kind_probe_fails() {
        let dir = test_dir();
        seed_running_hub(dir.path());
        let config = test_config();
        let mut runner = MockRunner::with_runtime("docker");
        runner.respond(
            "kind get clusters",
            CommandOutput {
                status: 1,
                stdout: String::new(),
                stderr: "kind: connection refused\n".to_owned(),
            },
        );
        let ctx = ForgeContext {
            runner: &runner,
            config: &config,
            state_dir: dir.path().to_path_buf(),
            config_dir: dir.path().to_path_buf(),
            format: OutputFormat::Text,
            dry_run: false,
        };

        let text = run_status(&ctx);

        assert!(text.contains("state=running"), "state phases must survive: {text}");
        assert!(
            text.contains("live unknown"),
            "a failed probe must degrade to unknown, not abort: {text}"
        );
    }

    /// Seed state with a running cluster the config does not list.
    fn seed_state_only_spoke(state_dir: &std::path::Path) {
        let mut st = state::empty();
        st.clusters.push(ClusterState {
            name: "spoke".to_owned(),
            kind_name: "forge-spoke".to_owned(),
            context: "kind-forge-spoke".to_owned(),
            phase: ClusterPhase::Running,
        });
        state::save(state_dir, &st).unwrap_or_else(|_| std::process::abort());
    }

    #[test]
    fn status_lists_state_tracked_cluster_missing_from_config() {
        let dir = test_dir();
        // State tracks a cluster the config no longer lists; down would
        // still delete it, so status must show it.
        seed_state_only_spoke(dir.path());
        let config = test_config();
        let mut runner = MockRunner::with_runtime("docker");
        runner.respond(
            "kind get clusters",
            CommandOutput {
                status: 0,
                stdout: "forge-spoke\n".to_owned(),
                stderr: String::new(),
            },
        );
        let ctx = ForgeContext {
            runner: &runner,
            config: &config,
            state_dir: dir.path().to_path_buf(),
            config_dir: dir.path().to_path_buf(),
            format: OutputFormat::Text,
            dry_run: false,
        };

        let text = run_status(&ctx);

        assert!(
            text.contains("spoke: state=running, kind=forge-spoke (live, not in config)"),
            "the state-only cluster must be listed and flagged: {text}"
        );
    }

    /// Seed state with a running hub cluster and active network.
    fn seed_with_network(state_dir: &std::path::Path) {
        let mut st = state::empty();
        st.clusters.push(ClusterState {
            name: "hub".to_owned(),
            kind_name: "forge-hub".to_owned(),
            context: "kind-forge-hub".to_owned(),
            phase: ClusterPhase::Running,
        });
        st.network = Some(state::NetworkState {
            name: "test-net".to_owned(),
            phase: state::NetworkPhase::Active,
            cidr: None,
            cluster_pools: Vec::new(),
        });
        state::save(state_dir, &st).unwrap_or_else(|_| std::process::abort());
    }

    /// Valid identity JSON matching the `--format` template output.
    fn identity_json() -> String {
        r#"{"containerId":"abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890","startedAt":"2026-07-22T14:30:00Z","restartCount":0}"#.to_owned()
    }

    /// Docker inspect output with valid identity.
    fn docker_identity() -> CommandOutput {
        CommandOutput {
            status: 0,
            stdout: identity_json(),
            stderr: String::new(),
        }
    }

    /// Docker inspect output for a missing container.
    fn docker_gone() -> CommandOutput {
        CommandOutput {
            status: 1,
            stdout: String::new(),
            stderr: "no such container\n".to_owned(),
        }
    }

    /// Seed state with a running hub cluster and a running service.
    fn seed_with_service(state_dir: &std::path::Path) {
        let mut st = state::empty();
        st.runtime = Some("docker".to_owned());
        st.clusters.push(ClusterState {
            name: "hub".to_owned(),
            kind_name: "forge-hub".to_owned(),
            context: "kind-forge-hub".to_owned(),
            phase: ClusterPhase::Running,
        });
        st.services.push(state::ServiceState {
            name: "edge".to_owned(),
            container_name: "test-edge".to_owned(),
            image: "praxis:latest".to_owned(),
            phase: state::ServicePhase::Running,
            health: state::ServiceHealth::Healthy,
            last_observed: 0,
        });
        state::save(state_dir, &st).unwrap_or_else(|_| std::process::abort());
    }

    /// KIND cluster list showing forge-hub as live.
    fn kind_hub_live() -> CommandOutput {
        CommandOutput {
            status: 0,
            stdout: "forge-hub\n".to_owned(),
            stderr: String::new(),
        }
    }

    /// Parse JSON envelope from output buffer.
    fn parse_envelope(buf: &[u8]) -> serde_json::Value {
        let text = String::from_utf8_lossy(buf);
        serde_json::from_str(&text).unwrap_or_else(|_| {
            std::process::abort();
            #[expect(unreachable_code, reason = "abort prevents reaching this")]
            {
                unreachable!()
            }
        })
    }

    /// Extract the first service entry from a parsed JSON envelope.
    fn first_service(envelope: &serde_json::Value) -> &serde_json::Value {
        let Some(svc) = envelope
            .get("data")
            .and_then(|data| data.get("services"))
            .and_then(|svcs| svcs.get(0))
        else {
            std::process::abort();
        };
        svc
    }

    #[test]
    fn status_json_includes_service_identity() {
        let dir = test_dir();
        seed_with_service(dir.path());
        let config = test_config();
        let mut runner = MockRunner::with_runtime("docker");
        runner.respond("kind get clusters", kind_hub_live());
        runner.respond("docker", docker_identity());
        let ctx = ForgeContext {
            runner: &runner,
            config: &config,
            state_dir: dir.path().to_path_buf(),
            config_dir: dir.path().to_path_buf(),
            format: OutputFormat::Json,
            dry_run: false,
        };
        let mut buf = Vec::new();
        run(&ctx, &mut buf).unwrap_or_else(|_| std::process::abort());
        let envelope = parse_envelope(&buf);
        let svc = first_service(&envelope);
        assert!(
            svc.get("containerId").is_some_and(serde_json::Value::is_string),
            "containerId"
        );
        assert!(
            svc.get("startedAt").is_some_and(serde_json::Value::is_string),
            "startedAt"
        );
        assert_eq!(svc.get("restartCount"), Some(&serde_json::json!(0)), "restartCount");
    }

    #[test]
    fn status_json_missing_container_has_null_identity() {
        let dir = test_dir();
        seed_with_service(dir.path());
        let config = test_config();
        let mut runner = MockRunner::with_runtime("docker");
        runner.respond("kind get clusters", kind_hub_live());
        runner.respond("docker", docker_gone());
        let ctx = ForgeContext {
            runner: &runner,
            config: &config,
            state_dir: dir.path().to_path_buf(),
            config_dir: dir.path().to_path_buf(),
            format: OutputFormat::Json,
            dry_run: false,
        };
        let mut buf = Vec::new();
        run(&ctx, &mut buf).unwrap_or_else(|_| std::process::abort());
        let envelope = parse_envelope(&buf);
        let svc = first_service(&envelope);
        assert!(
            svc.get("containerId").is_some_and(serde_json::Value::is_null),
            "containerId null"
        );
        assert!(
            svc.get("startedAt").is_some_and(serde_json::Value::is_null),
            "startedAt null"
        );
        assert!(
            svc.get("restartCount").is_some_and(serde_json::Value::is_null),
            "restartCount null"
        );
    }

    #[test]
    fn status_reports_network() {
        let dir = test_dir();
        seed_with_network(dir.path());
        let config = test_config();
        let mut runner = MockRunner::with_runtime("docker");
        runner.respond(
            "kind get clusters",
            CommandOutput {
                status: 0,
                stdout: "forge-hub\n".to_owned(),
                stderr: String::new(),
            },
        );
        let ctx = ForgeContext {
            runner: &runner,
            config: &config,
            state_dir: dir.path().to_path_buf(),
            config_dir: dir.path().to_path_buf(),
            format: OutputFormat::Text,
            dry_run: false,
        };
        let text = run_status(&ctx);
        assert!(text.contains("test-net"), "should show network name: {text}");
        assert!(text.contains("active"), "should show network phase: {text}");
    }
}
