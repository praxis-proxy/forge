//! The `down` command: tear down all managed clusters.
//!
//! Deletes clusters tracked in state, updates state to `Gone`,
//! and reports the result.

use std::io::Write;

use crate::{
    cluster::kind as kind_ops,
    command::{
        checkpoint::{checkpoint, checkpointed, record_operation},
        confirm,
    },
    context::ForgeContext,
    error::ForgeError,
    networking,
    output::{self, OutputFormat},
    runtime, service,
    state::{self, ClusterPhase, NetworkPhase, ServicePhase, lock},
};

/// Run the `down` command.
///
/// On an interactive terminal the teardown asks for confirmation
/// first unless `skip_confirm` (`--force` or `--non-interactive`) is
/// set; non-TTY invocations never prompt.  Each teardown phase is
/// checkpointed so that resources already removed stay recorded as
/// gone even when a later phase fails; re-running `down` then
/// converges instead of reporting stale state.
///
/// # Errors
///
/// Returns [`ForgeError`] if cluster deletion or state
/// persistence fails.
pub fn run(ctx: &ForgeContext<'_>, skip_confirm: bool, writer: &mut dyn Write) -> Result<(), ForgeError> {
    if !ctx.dry_run
        && !confirm::confirm_destructive("delete all managed services, clusters, and networks", skip_confirm)?
    {
        return confirm::report_declined(writer, &ctx.format);
    }
    let _lock = lock::acquire(&ctx.state_dir)?;
    let mut st = state::load(&ctx.state_dir)?;
    let svc_results = checkpointed(ctx, &mut st, "down", |state| stop_services(ctx, state))?;
    let results = checkpointed(ctx, &mut st, "down", |state| delete_clusters(ctx, state))?;
    let net_result = checkpointed(ctx, &mut st, "down", |state| remove_env_network(ctx, state))?;
    record_operation(&mut st, "down", true);
    checkpoint(ctx, &st)?;
    render_all(writer, &svc_results, &results, net_result.as_ref(), &ctx.format)
}

// ---------------------------------------------------------------
// Cluster deletion
// ---------------------------------------------------------------

/// Result of processing one cluster for deletion.
struct DeleteResult {
    /// Cluster config name.
    name: String,
    /// KIND cluster name.
    kind_name: String,
    /// Whether this was a dry-run skip.
    dry_run: bool,
}

/// Delete clusters in reverse order from state.
fn delete_clusters(ctx: &ForgeContext<'_>, state: &mut state::ForgeState) -> Result<Vec<DeleteResult>, ForgeError> {
    let targets = collect_targets(state);
    let mut results = Vec::new();
    for (name, kind_name) in targets.into_iter().rev() {
        let result = delete_one(ctx, state, &name, &kind_name)?;
        results.push(result);
    }
    Ok(results)
}

/// Collect (name, `kind_name`) pairs from state for deletion.
fn collect_targets(state: &state::ForgeState) -> Vec<(String, String)> {
    state
        .clusters
        .iter()
        .filter(|cluster| cluster.phase != ClusterPhase::Gone)
        .map(|cluster| (cluster.name.clone(), cluster.kind_name.clone()))
        .collect()
}

/// Delete a single cluster or report dry-run.
///
/// The `Deleting` phase is persisted before `kind delete` runs so a
/// crash mid-delete leaves a diagnosable record instead of a cluster
/// still marked `Running`.
fn delete_one(
    ctx: &ForgeContext<'_>,
    state: &mut state::ForgeState,
    name: &str,
    kind_name: &str,
) -> Result<DeleteResult, ForgeError> {
    if ctx.dry_run {
        return Ok(DeleteResult {
            name: name.to_owned(),
            kind_name: kind_name.to_owned(),
            dry_run: true,
        });
    }
    set_cluster_phase(state, name, ClusterPhase::Deleting);
    checkpoint(ctx, state)?;
    kind_ops::delete_cluster(ctx.runner, kind_name)?;
    set_cluster_phase(state, name, ClusterPhase::Gone);
    Ok(DeleteResult {
        name: name.to_owned(),
        kind_name: kind_name.to_owned(),
        dry_run: false,
    })
}

/// Set a tracked cluster's lifecycle phase in state.
fn set_cluster_phase(state: &mut state::ForgeState, name: &str, phase: ClusterPhase) {
    if let Some(cs) = state::find_cluster_mut(state, name) {
        cs.phase = phase;
    }
}

// ---------------------------------------------------------------
// Service teardown
// ---------------------------------------------------------------

/// Result of processing one service for teardown.
struct SvcDeleteResult {
    /// Service config name.
    name: String,
    /// Deterministic container name.
    container_name: String,
    /// Whether this was a dry-run skip.
    dry_run: bool,
}

/// A service teardown target: service name and container name.
type SvcTarget = (String, String);

/// Stop services in reverse dependency order.
fn stop_services(ctx: &ForgeContext<'_>, state: &mut state::ForgeState) -> Result<Vec<SvcDeleteResult>, ForgeError> {
    let targets = collect_svc_targets(ctx, state)?;
    if targets.is_empty() {
        return Ok(Vec::new());
    }
    let binary = resolve_binary(ctx, state)?;
    let mut results = Vec::new();
    for (name, cname) in targets {
        let result = stop_one_svc(ctx, state, &binary, &name, &cname)?;
        results.push(result);
    }
    Ok(results)
}

/// Collect service teardown targets from config and state.
///
/// Configured services come first, in reverse dependency order, then
/// state-tracked services no longer present in the config, a service
/// removed from the config after it was started must still be stopped,
/// or its container would be orphaned with no supported way to remove
/// it (`forge service stop` also refuses services outside the config).
fn collect_svc_targets(ctx: &ForgeContext<'_>, state: &state::ForgeState) -> Result<Vec<SvcTarget>, ForgeError> {
    let mut order = service::dependency_order(&ctx.config.spec.services)?;
    order.reverse();
    let mut targets = Vec::new();
    for idx in order {
        let svc = ctx
            .config
            .spec
            .services
            .get(idx)
            .ok_or_else(|| ForgeError::State("service index out of range".to_owned()))?;
        let cname = service::container_name(&ctx.config.metadata.name, &svc.name);
        targets.push((svc.name.clone(), cname));
    }
    append_state_only_targets(&mut targets, state);
    Ok(targets)
}

/// Append non-Gone state services that are absent from the config.
///
/// Entries already marked `Gone` have nothing left to stop; configured
/// services are stopped regardless since stopping is idempotent.
fn append_state_only_targets(targets: &mut Vec<SvcTarget>, state: &state::ForgeState) {
    for svc in &state.services {
        if svc.phase == ServicePhase::Gone {
            continue;
        }
        if targets.iter().any(|(name, _)| name == &svc.name) {
            continue;
        }
        targets.push((svc.name.clone(), svc.container_name.clone()));
    }
}

/// Stop a single service container.
fn stop_one_svc(
    ctx: &ForgeContext<'_>,
    state: &mut state::ForgeState,
    binary: &str,
    name: &str,
    cname: &str,
) -> Result<SvcDeleteResult, ForgeError> {
    if ctx.dry_run {
        return Ok(SvcDeleteResult {
            name: name.to_owned(),
            container_name: cname.to_owned(),
            dry_run: true,
        });
    }
    let params = service::ServiceParams {
        binary,
        container_name: cname,
        env_name: &ctx.config.metadata.name,
        config_dir: &ctx.config_dir,
        state_dir: &ctx.state_dir,
    };
    service::stop_service(ctx.runner, &params)?;
    mark_svc_gone(state, name);
    Ok(SvcDeleteResult {
        name: name.to_owned(),
        container_name: cname.to_owned(),
        dry_run: false,
    })
}

/// Mark a service as `Gone` in state.
fn mark_svc_gone(state: &mut state::ForgeState, name: &str) {
    if let Some(ss) = state::find_service_mut(state, name) {
        ss.phase = ServicePhase::Gone;
    }
}

// ---------------------------------------------------------------
// Network teardown
// ---------------------------------------------------------------

/// Result of network teardown.
struct NetworkTeardown {
    /// Network name.
    name: String,
    /// Whether this was a dry-run skip.
    dry_run: bool,
    /// Intended network disposition.
    action: NetworkAction,
}

/// Network disposition after teardown.
enum NetworkAction {
    /// Delete a network owned by the active lifecycle.
    Remove,
    /// Retain a network whose creation is not owned.
    Preserve,
    /// The tracked network is already absent.
    Absent,
    /// A dry run must inspect a pending attempt before deciding deletion.
    Recover,
}

/// Remove the environment network if one is tracked in state.
fn remove_env_network(
    ctx: &ForgeContext<'_>,
    state: &mut state::ForgeState,
) -> Result<Option<NetworkTeardown>, ForgeError> {
    let net = match &state.network {
        Some(ns) if ns.phase != NetworkPhase::Gone => ns.clone(),
        _ => return Ok(None),
    };
    if ctx.dry_run {
        let action = planned_network_action(state);
        return Ok(Some(NetworkTeardown {
            name: net.name,
            dry_run: true,
            action,
        }));
    }
    let action = remove_owned_network(ctx, state, &net.name)?;
    if matches!(action, NetworkAction::Preserve) {
        state.network_created_by_forge = false;
        state.network_id = None;
        state.network_creation_token = None;
    } else {
        mark_network_gone(state);
    }
    Ok(Some(NetworkTeardown {
        name: net.name,
        dry_run: false,
        action,
    }))
}

/// Describe the required identity check without contacting the runtime.
fn planned_network_action(state: &state::ForgeState) -> NetworkAction {
    if state.network_created_by_forge && state.network_id.is_some() {
        NetworkAction::Remove
    } else if state.network_creation_token.is_some() {
        NetworkAction::Recover
    } else {
        NetworkAction::Preserve
    }
}

/// Compare the live instance with persisted creation authority before deletion.
fn remove_owned_network(
    ctx: &ForgeContext<'_>,
    state: &state::ForgeState,
    name: &str,
) -> Result<NetworkAction, ForgeError> {
    let binary = resolve_binary(ctx, state)?;
    if !networking::network_exists(ctx.runner, &binary, name)? {
        return Ok(NetworkAction::Absent);
    }
    let Some(current) = owned_network_id(ctx, state, &binary, name)? else {
        return Ok(NetworkAction::Preserve);
    };
    networking::remove_network(ctx.runner, &binary, &current, &ctx.config.metadata.name)?;
    Ok(NetworkAction::Remove)
}

/// Recover only an exact saved instance or a matching pending creation attempt.
fn owned_network_id(
    ctx: &ForgeContext<'_>,
    state: &state::ForgeState,
    binary: &str,
    name: &str,
) -> Result<Option<String>, ForgeError> {
    if let Some(recorded) = state.network_id.as_ref().filter(|_| state.network_created_by_forge) {
        let current = networking::inspect_network_id(ctx.runner, binary, name)?;
        return Ok((*recorded == current).then_some(current));
    }
    if let Some(token) = state.network_creation_token.as_deref() {
        return networking::recover_network_id(ctx.runner, binary, name, &ctx.config.metadata.name, token);
    }
    Ok(None)
}

/// Get the runtime binary from state or by re-detecting.
fn resolve_binary(ctx: &ForgeContext<'_>, state: &state::ForgeState) -> Result<String, ForgeError> {
    if let Some(binary) = &state.runtime {
        return Ok(binary.clone());
    }
    let resolved = runtime::resolve(ctx.runner, &ctx.config.spec.runtime.provider)?;
    Ok(resolved.binary)
}

/// Mark the network as gone in state.
fn mark_network_gone(state: &mut state::ForgeState) {
    state.network_created_by_forge = false;
    state.network_id = None;
    state.network_creation_token = None;
    if let Some(ref mut ns) = state.network {
        ns.phase = NetworkPhase::Gone;
        ns.cidr = None;
        ns.cluster_pools.clear();
    }
}

// ---------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------

/// Render all deletion results.
fn render_all(
    writer: &mut dyn Write,
    services: &[SvcDeleteResult],
    clusters: &[DeleteResult],
    net: Option<&NetworkTeardown>,
    format: &OutputFormat,
) -> Result<(), ForgeError> {
    match format {
        OutputFormat::Json => render_json(writer, services, clusters, net),
        OutputFormat::Text => render_text(writer, services, clusters, net),
    }
}

/// Render results as JSON.
fn render_json(
    writer: &mut dyn Write,
    services: &[SvcDeleteResult],
    clusters: &[DeleteResult],
    net: Option<&NetworkTeardown>,
) -> Result<(), ForgeError> {
    let items: Vec<_> = clusters.iter().map(result_to_json).collect();
    let mut data = serde_json::json!({ "clusters": items });
    if let (false, Some(obj)) = (services.is_empty(), data.as_object_mut()) {
        let svc_items: Vec<_> = services.iter().map(svc_result_to_json).collect();
        obj.insert("services".to_owned(), serde_json::json!(svc_items));
    }
    if let (Some(nd), Some(obj)) = (net, data.as_object_mut()) {
        obj.insert(
            "network".to_owned(),
            serde_json::json!({ "name": nd.name, "dryRun": nd.dry_run, "removed": !nd.dry_run && matches!(nd.action, NetworkAction::Remove) }),
        );
    }
    let envelope = output::success(data);
    output::write_json(writer, &envelope)?;
    Ok(())
}

/// Convert one service teardown result to JSON.
fn svc_result_to_json(result: &SvcDeleteResult) -> serde_json::Value {
    serde_json::json!({
        "name": result.name,
        "containerName": result.container_name,
        "dryRun": result.dry_run,
    })
}

/// Convert one result to JSON.
fn result_to_json(result: &DeleteResult) -> serde_json::Value {
    serde_json::json!({
        "name": result.name,
        "kindName": result.kind_name,
        "dryRun": result.dry_run,
    })
}

/// Render results as text.
fn render_text(
    writer: &mut dyn Write,
    services: &[SvcDeleteResult],
    clusters: &[DeleteResult],
    net: Option<&NetworkTeardown>,
) -> Result<(), ForgeError> {
    for svc in services {
        output::write_text(writer, &format_svc_text(svc))?;
    }
    for result in clusters {
        output::write_text(writer, &format_result_text(result))?;
    }
    if let Some(net) = net {
        output::write_text(writer, &format_net_text(net))?;
    }
    Ok(())
}

/// Format a service teardown result as a text line.
fn format_svc_text(svc: &SvcDeleteResult) -> String {
    if svc.dry_run {
        return format!("would stop service '{}' (container: {})", svc.name, svc.container_name);
    }
    format!("stopped service '{}' (container: {})", svc.name, svc.container_name)
}

/// Format a network teardown result as a text line.
fn format_net_text(n: &NetworkTeardown) -> String {
    if n.dry_run {
        let action = match n.action {
            NetworkAction::Preserve => "preserve pre-existing",
            NetworkAction::Remove => "remove",
            NetworkAction::Absent => "observe absence of",
            NetworkAction::Recover => "verify pending creation before removing",
        };
        return format!("would {action} network '{}'", n.name);
    }
    if matches!(n.action, NetworkAction::Remove) {
        return format!("removed network '{}'", n.name);
    }
    if matches!(n.action, NetworkAction::Absent) {
        return format!("network '{}' is already absent", n.name);
    }
    format!("preserved pre-existing network '{}'", n.name)
}

/// Format a single result as text.
fn format_result_text(result: &DeleteResult) -> String {
    if result.dry_run {
        return format!(
            "would delete cluster '{}' (kind name: {})",
            result.name, result.kind_name
        );
    }
    format!("deleted cluster '{}' (kind name: {})", result.name, result.kind_name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        command::runner::{CommandOutput, MockRunner},
        state::ClusterState,
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

    /// Pre-populate state with a running cluster.
    fn seed_state(state_dir: &std::path::Path) {
        let mut st = state::empty();
        st.clusters.push(ClusterState {
            name: "hub".to_owned(),
            kind_name: "forge-hub".to_owned(),
            context: "kind-forge-hub".to_owned(),
            phase: ClusterPhase::Running,
        });
        state::save(state_dir, &st).unwrap_or_else(|_| std::process::abort());
    }

    #[test]
    fn down_deletes_cluster() {
        let dir = test_dir();
        seed_state(dir.path());
        let config = test_config();
        let mut runner = MockRunner::new();
        runner.respond(
            "kind",
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
        let mut buf = Vec::new();
        run(&ctx, false, &mut buf).unwrap_or_else(|_| std::process::abort());
        assert!(runner.was_called("kind delete cluster"), "should call kind delete");
        let text = String::from_utf8_lossy(&buf);
        assert!(text.contains("deleted"), "should say deleted: {text}");
    }

    #[test]
    fn down_persists_deleting_phase_when_delete_fails() {
        let dir = test_dir();
        seed_state(dir.path());
        let config = test_config();
        let mut runner = MockRunner::new();
        runner.respond(
            "kind",
            CommandOutput {
                status: 1,
                stdout: String::new(),
                stderr: "delete blew up\n".to_owned(),
            },
        );
        let ctx = test_ctx(&runner, &config, &dir);

        let mut buf = Vec::new();
        let result = run(&ctx, false, &mut buf);

        assert!(result.is_err(), "a failing delete should fail the run");
        let st = state::load(dir.path()).unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            state::find_cluster(&st, "hub").map(|cs| cs.phase.clone()),
            Some(ClusterPhase::Deleting),
            "an interrupted delete must leave a Deleting record"
        );
    }

    #[test]
    fn down_dry_run_does_not_delete() {
        let dir = test_dir();
        seed_state(dir.path());
        let config = test_config();
        let runner = MockRunner::new();
        let ctx = ForgeContext {
            runner: &runner,
            config: &config,
            state_dir: dir.path().to_path_buf(),
            config_dir: dir.path().to_path_buf(),
            format: OutputFormat::Text,
            dry_run: true,
        };
        let mut buf = Vec::new();
        run(&ctx, false, &mut buf).unwrap_or_else(|_| std::process::abort());
        assert!(!runner.was_called("kind delete"), "dry-run should not call kind delete");
        let text = String::from_utf8_lossy(&buf);
        assert!(text.contains("would delete"), "should say would delete: {text}");
    }

    /// Pre-populate state with a running cluster and active network.
    fn seed_state_with_network(state_dir: &std::path::Path) {
        let mut st = state::empty();
        st.runtime = Some("docker".to_owned());
        st.clusters.push(ClusterState {
            name: "hub".to_owned(),
            kind_name: "forge-hub".to_owned(),
            context: "kind-forge-hub".to_owned(),
            phase: ClusterPhase::Running,
        });
        st.network_created_by_forge = true;
        st.network_id = Some("a".repeat(64));
        st.network = Some(state::NetworkState {
            name: "test-net".to_owned(),
            phase: NetworkPhase::Active,
            cidr: None,
            cluster_pools: Vec::new(),
        });
        state::save(state_dir, &st).unwrap_or_else(|_| std::process::abort());
    }

    /// Labels JSON for ownership verification.
    fn owned_labels() -> CommandOutput {
        CommandOutput {
            status: 0,
            stdout: r#"{"forge.managed":"true","forge.environment":"test"}"#.to_owned(),
            stderr: String::new(),
        }
    }

    /// Respond with a particular runtime network identity.
    fn respond_network_instance(runner: &mut MockRunner, digit: char) {
        let id = digit.to_string().repeat(64);
        runner.respond(
            "docker network inspect test-net --format {{json .}}",
            CommandOutput {
                status: 0,
                stdout: format!(r#"{{"Id":"{id}"}}"#),
                stderr: String::new(),
            },
        );
        runner.respond(&format!("docker network inspect {id}"), ok());
    }

    /// Successful empty output.
    fn ok() -> CommandOutput {
        CommandOutput {
            status: 0,
            stdout: String::new(),
            stderr: String::new(),
        }
    }

    /// Assert that removing a network invalidates its address allocations.
    fn assert_network_allocation_cleared(state_dir: &std::path::Path) {
        let state = state::load(state_dir).unwrap_or_else(|_| std::process::abort());
        let network = state.network.as_ref().unwrap_or_else(|| std::process::abort());
        assert_eq!(network.phase, NetworkPhase::Gone);
        assert!(network.cidr.is_none(), "removed network must not retain its CIDR");
        assert!(
            network.cluster_pools.is_empty(),
            "removed network must not retain MetalLB pools"
        );
    }

    #[test]
    fn down_removes_network() {
        let dir = test_dir();
        seed_state_with_network(dir.path());
        let config = test_config();
        let mut runner = MockRunner::new();
        runner.respond("kind", ok());
        runner.respond("docker network inspect test-net", ok());
        respond_network_instance(&mut runner, 'a');
        runner.respond(
            &format!(
                "docker network inspect {} --format {{{{json .Labels}}}}",
                "a".repeat(64)
            ),
            owned_labels(),
        );
        runner.respond(&format!("docker network rm {}", "a".repeat(64)), ok());
        let ctx = ForgeContext {
            runner: &runner,
            config: &config,
            state_dir: dir.path().to_path_buf(),
            config_dir: dir.path().to_path_buf(),
            format: OutputFormat::Text,
            dry_run: false,
        };
        let mut buf = Vec::new();
        run(&ctx, false, &mut buf).unwrap_or_else(|_| std::process::abort());
        assert!(runner.was_called("network rm"), "should remove network");
        assert_network_allocation_cleared(dir.path());
        let text = String::from_utf8_lossy(&buf);
        assert!(text.contains("removed network"), "should report removal: {text}");
    }

    /// Build a config with two dependent services and no clusters.
    fn test_config_with_services() -> crate::config::ForgeConfig {
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
  services:
    - name: db
      image: example/db:v1
    - name: web
      image: example/web:v1
      dependsOn:
        - db
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

    /// Seed state with running services and a resolved runtime.
    fn seed_state_with_services(state_dir: &std::path::Path, names: &[&str]) {
        let mut st = state::empty();
        st.runtime = Some("docker".to_owned());
        for name in names {
            st.services.push(state::ServiceState {
                name: (*name).to_owned(),
                container_name: format!("test-{name}"),
                image: format!("example/{name}:v1"),
                phase: ServicePhase::Running,
                health: state::ServiceHealth::Unknown,
                last_observed: 0,
            });
        }
        state::save(state_dir, &st).unwrap_or_else(|_| std::process::abort());
    }

    /// Register mock responses for one owned, existing container.
    fn respond_owned_container(runner: &mut MockRunner, cname: &str) {
        runner.respond(&format!("docker container inspect {cname}"), ok());
        runner.respond(
            &format!("docker container inspect --format {{{{json .Config.Labels}}}} {cname}"),
            owned_labels(),
        );
    }

    /// Build a non-dry-run context over the given runner, config, and dir.
    fn test_ctx<'env>(
        runner: &'env MockRunner,
        config: &'env crate::config::ForgeConfig,
        dir: &tempfile::TempDir,
    ) -> ForgeContext<'env> {
        ForgeContext {
            runner,
            config,
            state_dir: dir.path().to_path_buf(),
            config_dir: dir.path().to_path_buf(),
            format: OutputFormat::Text,
            dry_run: false,
        }
    }

    #[test]
    fn down_stops_services_in_reverse_dependency_order() {
        let dir = test_dir();
        seed_state_with_services(dir.path(), &["db", "web"]);
        let config = test_config_with_services();
        let mut runner = MockRunner::new();
        runner.respond("docker", ok());
        respond_owned_container(&mut runner, "test-db");
        respond_owned_container(&mut runner, "test-web");
        let ctx = test_ctx(&runner, &config, &dir);

        let mut buf = Vec::new();
        run(&ctx, false, &mut buf).unwrap_or_else(|_| std::process::abort());

        let stops: Vec<String> = runner.calls_matching("stop").iter().map(ToString::to_string).collect();
        assert_eq!(
            stops,
            vec!["docker stop test-web", "docker stop test-db"],
            "dependents must stop before their dependencies"
        );
        let st = state::load(dir.path()).unwrap_or_else(|_| std::process::abort());
        assert!(
            st.services.iter().all(|svc| svc.phase == ServicePhase::Gone),
            "stopped services must be recorded Gone"
        );
    }

    #[test]
    fn down_stops_service_removed_from_config() {
        let dir = test_dir();
        // State tracks a service the config no longer lists.
        seed_state_with_services(dir.path(), &["edge"]);
        let config = test_config();
        let mut runner = MockRunner::new();
        runner.respond("docker", ok());
        respond_owned_container(&mut runner, "test-edge");
        let ctx = test_ctx(&runner, &config, &dir);

        let mut buf = Vec::new();
        run(&ctx, false, &mut buf).unwrap_or_else(|_| std::process::abort());

        assert!(
            runner.was_called("docker stop test-edge"),
            "a state-tracked service must be stopped even when absent from config"
        );
        let text = String::from_utf8_lossy(&buf);
        assert!(
            text.contains("stopped service 'edge'"),
            "should report the stop: {text}"
        );
        let st = state::load(dir.path()).unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            state::find_service(&st, "edge").map(|svc| svc.phase.clone()),
            Some(ServicePhase::Gone),
            "the orphaned service must be recorded Gone"
        );
    }

    #[test]
    fn down_aborts_on_foreign_service_container() {
        let dir = test_dir();
        seed_state_with_services(dir.path(), &["edge"]);
        let config = test_config();
        let mut runner = MockRunner::new();
        runner.respond("docker", ok());
        runner.respond("docker container inspect test-edge", ok());
        runner.respond(
            "docker container inspect --format {{json .Config.Labels}} test-edge",
            foreign_labels(),
        );
        let ctx = test_ctx(&runner, &config, &dir);

        let mut buf = Vec::new();
        let result = run(&ctx, false, &mut buf);

        assert!(result.is_err(), "an ownership mismatch must abort teardown");
        assert!(
            !runner.was_called("docker stop"),
            "a foreign container must not be stopped"
        );
    }

    /// Labels JSON owned by a different environment.
    fn foreign_labels() -> CommandOutput {
        CommandOutput {
            status: 0,
            stdout: r#"{"forge.managed":"true","forge.environment":"other"}"#.to_owned(),
            stderr: String::new(),
        }
    }

    #[test]
    fn down_persists_earlier_phases_when_later_phase_fails() {
        let dir = test_dir();
        seed_state_with_network(dir.path());
        let config = test_config();
        let mut runner = MockRunner::new();
        runner.respond("kind", ok());
        runner.respond("docker network inspect test-net", ok());
        respond_network_instance(&mut runner, 'a');
        // The network belongs to another environment, so removal fails
        // after the clusters were already deleted.
        runner.respond(
            &format!(
                "docker network inspect {} --format {{{{json .Labels}}}}",
                "a".repeat(64)
            ),
            foreign_labels(),
        );
        let ctx = test_ctx(&runner, &config, &dir);

        let mut buf = Vec::new();
        let result = run(&ctx, false, &mut buf);

        assert!(result.is_err(), "an ownership mismatch should fail the run");
        assert!(runner.was_called("kind delete cluster"), "cluster phase should run");
        let st = state::load(dir.path()).unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            state::find_cluster(&st, "hub").map(|cs| cs.phase.clone()),
            Some(ClusterPhase::Gone),
            "a deleted cluster must be recorded Gone even when a later phase fails"
        );
        assert_eq!(
            st.last_operation.map(|op| (op.operation, op.success)),
            Some(("down".to_owned(), false)),
            "the failed run must be recorded as an unsuccessful down"
        );
    }

    #[test]
    fn down_dry_run_reports_network() {
        let dir = test_dir();
        seed_state_with_network(dir.path());
        let config = test_config();
        let runner = MockRunner::new();
        let ctx = ForgeContext {
            runner: &runner,
            config: &config,
            state_dir: dir.path().to_path_buf(),
            config_dir: dir.path().to_path_buf(),
            format: OutputFormat::Text,
            dry_run: true,
        };
        let mut buf = Vec::new();
        run(&ctx, false, &mut buf).unwrap_or_else(|_| std::process::abort());
        assert!(!runner.was_called("network rm"), "dry-run should not remove network");
        let text = String::from_utf8_lossy(&buf);
        assert!(
            text.contains("would remove network"),
            "should report would remove network: {text}"
        );
    }

    #[test]
    fn forced_down_preserves_reused_network() -> Result<(), ForgeError> {
        let directory = test_dir();
        seed_state_with_network(directory.path());
        let mut state = state::load(directory.path())?;
        state.network_created_by_forge = false;
        state::save(directory.path(), &state)?;
        let mut runner = MockRunner::new();
        runner.respond("kind", ok());
        runner.respond("docker network inspect test-net", ok());
        respond_network_instance(&mut runner, 'a');
        let output = run_forced_network_teardown(&runner, directory.path())?;
        assert!(
            !runner.was_called("network rm"),
            "force suppresses confirmation without granting ownership"
        );
        assert!(
            String::from_utf8_lossy(&output).contains("preserved pre-existing network"),
            "preservation must be explicit"
        );
        let retained = state::load(directory.path())?;
        assert_eq!(
            retained.network.as_ref().map(|net| &net.phase),
            Some(&NetworkPhase::Active),
            "retained network stays active"
        );
        Ok(())
    }
    /// Run forced teardown with explicit runtime responses and persisted state.
    fn run_forced_network_teardown(runner: &MockRunner, directory: &std::path::Path) -> Result<Vec<u8>, ForgeError> {
        let config = test_config();
        let context = ForgeContext {
            runner,
            config: &config,
            state_dir: directory.to_path_buf(),
            config_dir: directory.to_path_buf(),
            format: OutputFormat::Text,
            dry_run: false,
        };
        let mut output = Vec::new();
        run(&context, true, &mut output)?;
        Ok(output)
    }

    #[test]
    fn dry_run_reports_prospective_network_preservation() {
        let teardown = NetworkTeardown {
            name: "reused-net".to_owned(),
            dry_run: true,
            action: NetworkAction::Preserve,
        };
        assert_eq!(
            format_net_text(&teardown),
            "would preserve pre-existing network 'reused-net'",
            "dry-run output must not imply observed preservation"
        );
    }

    #[test]
    fn down_preserves_replaced_network_instance() -> Result<(), ForgeError> {
        let directory = test_dir();
        seed_state_with_network(directory.path());
        let mut runner = MockRunner::new();
        runner.respond("kind", ok());
        runner.respond("docker network inspect test-net", ok());
        respond_network_instance(&mut runner, 'b');
        let _output = run_forced_network_teardown(&runner, directory.path())?;
        assert!(
            !runner.was_called("network rm"),
            "matching names cannot authorize deleting replacement networks"
        );
        let state = state::load(directory.path())?;
        assert!(!state.network_created_by_forge, "replacement revokes stale ownership");
        assert!(state.network_id.is_none(), "replacement must not transfer its identity");
        assert!(
            state.clusters.iter().all(|cluster| cluster.phase == ClusterPhase::Gone),
            "cluster cleanup still completes"
        );
        Ok(())
    }

    #[test]
    fn down_preserves_legacy_network_without_instance_id() -> Result<(), ForgeError> {
        let directory = test_dir();
        seed_state_with_network(directory.path());
        let mut state = state::load(directory.path())?;
        state.network_id = None;
        state::save(directory.path(), &state)?;
        let mut runner = MockRunner::new();
        runner.respond("kind", ok());
        runner.respond("docker network inspect test-net", ok());
        let _output = run_forced_network_teardown(&runner, directory.path())?;
        assert!(
            !runner.was_called("network rm"),
            "legacy true flag cannot distinguish runtime instances"
        );
        Ok(())
    }

    #[test]
    fn down_accepts_an_already_absent_owned_network() -> Result<(), ForgeError> {
        let directory = test_dir();
        seed_state_with_network(directory.path());
        let mut runner = MockRunner::new();
        runner.respond("kind", ok());
        runner.respond(
            "docker network inspect test-net",
            CommandOutput {
                status: 1,
                stdout: String::new(),
                stderr: "Error: No such network: test-net".to_owned(),
            },
        );
        let _output = run_forced_network_teardown(&runner, directory.path())?;
        assert!(!runner.was_called("network rm"), "absent networks require no deletion");
        assert_network_allocation_cleared(directory.path());
        Ok(())
    }

    #[test]
    fn down_recovers_an_interrupted_creation_by_its_label() -> Result<(), ForgeError> {
        let directory = test_dir();
        seed_pending_creation(directory.path())?;
        let runner = pending_creation_runner("original-attempt");
        let _output = run_forced_network_teardown(&runner, directory.path())?;
        assert!(
            runner.was_called(&format!("network rm {}", "a".repeat(64))),
            "cleanup must target the recovered immutable ID"
        );
        let state = state::load(directory.path())?;
        assert!(state.network_creation_token.is_none(), "cleanup clears pending attempt");
        assert_network_allocation_cleared(directory.path());
        Ok(())
    }

    #[test]
    fn down_preserves_a_replacement_of_an_interrupted_creation() -> Result<(), ForgeError> {
        let directory = test_dir();
        seed_pending_creation(directory.path())?;
        let runner = pending_creation_runner("another-attempt");
        let _output = run_forced_network_teardown(&runner, directory.path())?;
        assert!(
            !runner.was_called("network rm"),
            "same environment and name cannot transfer pending ownership"
        );
        Ok(())
    }

    /// Persist a failed identity lookup after successful external creation.
    fn seed_pending_creation(directory: &std::path::Path) -> Result<(), ForgeError> {
        seed_state_with_network(directory);
        let mut state = state::load(directory)?;
        state.network_created_by_forge = false;
        state.network_id = None;
        state.network_creation_token = Some("original-attempt".to_owned());
        state::save(directory, &state)
    }

    /// Supply successful immutable-ID cleanup and a selectable creation label.
    fn pending_creation_runner(token: &str) -> MockRunner {
        let mut runner = MockRunner::new();
        runner.respond("kind", ok());
        runner.respond("docker network inspect test-net", ok());
        respond_network_instance(&mut runner, 'a');
        runner.respond(
            "docker network inspect test-net --format {{json .}}",
            CommandOutput {
                status: 0,
                stdout: serde_json::json!({
                    "Id": "a".repeat(64),
                    "Labels": {"forge.managed": "true", "forge.environment": "test", "forge.creation": token}
                })
                .to_string(),
                stderr: String::new(),
            },
        );
        runner.respond(
            &format!(
                "docker network inspect {} --format {{{{json .Labels}}}}",
                "a".repeat(64)
            ),
            owned_labels(),
        );
        runner.respond(&format!("docker network rm {}", "a".repeat(64)), ok());
        runner
    }
}
