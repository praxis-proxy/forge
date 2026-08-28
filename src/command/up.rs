//! The `up` command: bring up the configured environment.
//!
//! Ensures the cross-cluster network, creates any clusters that do
//! not already exist, starts auto-start services, updates state, and
//! reports the result. Stacks are not applied here; they are managed
//! by the `stack` subcommands.

use std::io::Write;

use crate::{
    cluster::{kind as kind_ops, kubeconfig},
    command::checkpoint::{checkpoint, checkpointed, record_operation},
    config::ClusterSpec,
    context::ForgeContext,
    error::ForgeError,
    networking,
    output::{self, OutputFormat},
    runtime, service,
    state::{self, ClusterPhase, ClusterState, NetworkPhase, ServiceHealth, ServicePhase, ServiceState, lock},
};

/// Run the `up` command.
///
/// # Errors
///
/// Returns [`ForgeError`] if runtime detection, cluster creation,
/// or state persistence fails.
pub fn run(ctx: &ForgeContext<'_>, writer: &mut dyn Write) -> Result<(), ForgeError> {
    let resolved = runtime::resolve(ctx.runner, &ctx.config.spec.runtime.provider)?;
    if wants_network(ctx) {
        networking::require_docker_for_cross_cluster(&resolved.binary)?;
    }
    let _lock = lock::acquire(&ctx.state_dir)?;
    let mut state = state::load(&ctx.state_dir)?;
    state.runtime = Some(resolved.binary.clone());
    let binary = resolved.binary.as_str();
    let net_result = checkpointed(ctx, &mut state, "up", |st| ensure_network(ctx, binary, st))?;
    let results = checkpointed(ctx, &mut state, "up", |st| create_clusters(ctx, st))?;
    export_kubeconfigs(ctx, &state)?;
    let svc_results = checkpointed(ctx, &mut state, "up", |st| start_services(ctx, binary, st))?;
    update_digest(ctx, &mut state)?;
    record_operation(&mut state, "up", true);
    checkpoint(ctx, &state)?;
    render_all(writer, net_result.as_ref(), &results, &svc_results, &ctx.format)
}

// ---------------------------------------------------------------
// Network setup
// ---------------------------------------------------------------

/// Result of network setup.
struct NetworkSetup {
    /// Network name.
    name: String,
    /// Whether this was a dry-run skip.
    dry_run: bool,
}

/// Ensure the environment network exists if configured.
fn ensure_network(
    ctx: &ForgeContext<'_>,
    binary: &str,
    state: &mut state::ForgeState,
) -> Result<Option<NetworkSetup>, ForgeError> {
    if !wants_network(ctx) {
        return Ok(None);
    }
    let env_name = &ctx.config.metadata.name;
    let net_name = networking::network_name(env_name);
    if ctx.dry_run {
        return Ok(Some(NetworkSetup {
            name: net_name,
            dry_run: true,
        }));
    }
    networking::create_network(ctx.runner, binary, &net_name, env_name)?;
    // The network exists from here on. inspect_network_cidr can still fail, and
    // until the network is in state `down` has no way to remove it.
    set_network_created(state, &net_name);
    let cidr = networking::inspect_network_cidr(ctx.runner, binary, &net_name)?;
    set_network_active(state, &net_name, &cidr);
    Ok(Some(NetworkSetup {
        name: net_name,
        dry_run: false,
    }))
}

/// Check if the config requests cross-cluster networking.
fn wants_network(ctx: &ForgeContext<'_>) -> bool {
    ctx.config.spec.network.as_ref().is_some_and(|net| net.cross_cluster)
}

/// Record a network that exists but whose CIDR is not known yet.
///
/// Renaming the network invalidates any pool allocation derived from the old
/// one, so those are dropped alongside the stale CIDR.
fn set_network_created(state: &mut state::ForgeState, name: &str) {
    if let Some(ref mut net) = state.network {
        if net.name != name {
            net.cluster_pools.clear();
            name.clone_into(&mut net.name);
            net.cidr = None;
        }
        net.phase = NetworkPhase::Active;
        return;
    }
    state.network = Some(state::NetworkState {
        name: name.to_owned(),
        phase: NetworkPhase::Active,
        cidr: None,
        cluster_pools: Vec::new(),
    });
}

/// Record the live network identity, preserving only compatible pools.
fn set_network_active(state: &mut state::ForgeState, name: &str, cidr: &str) {
    if let Some(ref mut net) = state.network {
        let network_changed = net.name != name || net.cidr.as_deref() != Some(cidr);
        if network_changed {
            net.cluster_pools.clear();
        }
        name.clone_into(&mut net.name);
        net.phase = NetworkPhase::Active;
        net.cidr = Some(cidr.to_owned());
        return;
    }
    state.network = Some(state::NetworkState {
        name: name.to_owned(),
        phase: NetworkPhase::Active,
        cidr: Some(cidr.to_owned()),
        cluster_pools: Vec::new(),
    });
}

// ---------------------------------------------------------------
// Cluster creation
// ---------------------------------------------------------------

/// Result of processing one cluster.
struct ClusterResult {
    /// Cluster config name.
    name: String,
    /// KIND cluster name.
    kind_name: String,
    /// Whether the cluster was created (vs. already existed).
    created: bool,
    /// Whether this was a dry-run skip.
    dry_run: bool,
}

/// Iterate configured clusters, creating any that are missing.
fn create_clusters(ctx: &ForgeContext<'_>, state: &mut state::ForgeState) -> Result<Vec<ClusterResult>, ForgeError> {
    let docker_network = docker_network_for_kind(ctx);
    let mut results = Vec::new();
    for cluster in &ctx.config.spec.clusters {
        let result = process_cluster(ctx, state, cluster, docker_network.as_deref())?;
        results.push(result);
    }
    Ok(results)
}

/// Determine the Docker network name for KIND clusters, if any.
fn docker_network_for_kind(ctx: &ForgeContext<'_>) -> Option<String> {
    ctx.config
        .spec
        .network
        .as_ref()
        .filter(|net| net.cross_cluster)
        .map(|_| networking::network_name(&ctx.config.metadata.name))
}

/// Process a single cluster: create if missing, skip if exists.
fn process_cluster(
    ctx: &ForgeContext<'_>,
    state: &mut state::ForgeState,
    cluster: &ClusterSpec,
    docker_network: Option<&str>,
) -> Result<ClusterResult, ForgeError> {
    let kind_name = kind_ops::kind_cluster_name(&ctx.config.spec.runtime.cluster_prefix, &cluster.name);
    if ctx.dry_run {
        return Ok(dry_run_result(&cluster.name, &kind_name));
    }
    let created = create_if_missing(ctx, &kind_name, cluster, state, docker_network)?;
    Ok(ClusterResult {
        name: cluster.name.clone(),
        kind_name,
        created,
        dry_run: false,
    })
}

/// Build a dry-run result without executing anything.
fn dry_run_result(name: &str, kind_name: &str) -> ClusterResult {
    ClusterResult {
        name: name.to_owned(),
        kind_name: kind_name.to_owned(),
        created: false,
        dry_run: true,
    }
}

/// Create a cluster if it doesn't already exist. Returns true if created.
///
/// A `Creating` entry is persisted before `kind create` runs: creation
/// takes minutes, and a crash mid-create would otherwise leave real
/// KIND containers with no state record for `forge down` to act on.
fn create_if_missing(
    ctx: &ForgeContext<'_>,
    kind_name: &str,
    cluster: &ClusterSpec,
    state: &mut state::ForgeState,
    docker_network: Option<&str>,
) -> Result<bool, ForgeError> {
    if kind_ops::cluster_exists(ctx.runner, kind_name)? {
        ensure_state_entry(state, &cluster.name, kind_name, ClusterPhase::Running);
        return Ok(false);
    }
    ensure_state_entry(state, &cluster.name, kind_name, ClusterPhase::Creating);
    checkpoint(ctx, state)?;
    let cluster_config = kind_ops::CreateClusterConfig {
        nodes: &cluster.nodes,
        ports: &cluster.ports,
        config_dir: &ctx.state_dir,
        docker_network,
    };
    kind_ops::create_cluster(ctx.runner, kind_name, &cluster_config)?;
    ensure_state_entry(state, &cluster.name, kind_name, ClusterPhase::Running);
    Ok(true)
}

/// Ensure a cluster has an entry in state with the given phase.
///
/// An existing entry also has its `kind_name` and `context` refreshed:
/// after a `clusterPrefix` change the freshly created KIND cluster has
/// a new name, and keeping the stale one would make `forge down`
/// delete the wrong cluster and orphan the live one.
fn ensure_state_entry(state: &mut state::ForgeState, name: &str, kind_name: &str, phase: ClusterPhase) {
    if let Some(cs) = state::find_cluster_mut(state, name) {
        cs.phase = phase;
        if cs.kind_name != kind_name {
            kind_name.clone_into(&mut cs.kind_name);
            cs.context = kind_ops::kubectl_context(kind_name);
        }
        return;
    }
    state.clusters.push(ClusterState {
        name: name.to_owned(),
        kind_name: kind_name.to_owned(),
        context: kind_ops::kubectl_context(kind_name),
        phase,
    });
}

// ---------------------------------------------------------------
// Kubeconfig export
// ---------------------------------------------------------------

/// Export container-reachable kubeconfigs for all running clusters.
///
/// Skipped during dry-run. On a real run, exports a kubeconfig for
/// each cluster in state so services on the Docker network can
/// reach cluster API servers by DNS name.
fn export_kubeconfigs(ctx: &ForgeContext<'_>, state: &state::ForgeState) -> Result<(), ForgeError> {
    if ctx.dry_run || ctx.config.spec.services.is_empty() {
        return Ok(());
    }
    for cluster in &state.clusters {
        if cluster.phase != ClusterPhase::Running {
            continue;
        }
        kubeconfig::export_kubeconfig(ctx.runner, &cluster.kind_name, &cluster.name, &ctx.state_dir)?;
    }
    Ok(())
}

// ---------------------------------------------------------------
// Service startup
// ---------------------------------------------------------------

/// Result of processing one service.
struct ServiceResult {
    /// Service config name.
    name: String,
    /// Deterministic container name.
    container_name: String,
    /// Whether this was a dry-run skip.
    dry_run: bool,
}

/// Start configured services in dependency order.
fn start_services(
    ctx: &ForgeContext<'_>,
    binary: &str,
    state: &mut state::ForgeState,
) -> Result<Vec<ServiceResult>, ForgeError> {
    if ctx.config.spec.services.is_empty() {
        return Ok(Vec::new());
    }
    let order = service::dependency_order(&ctx.config.spec.services)?;
    let mut results = Vec::new();
    for idx in order {
        let Some(svc) = ctx.config.spec.services.get(idx) else {
            return Err(ForgeError::State("service index out of range".to_owned()));
        };
        if !svc.auto_start {
            continue;
        }
        let result = start_one_svc(ctx, binary, state, idx)?;
        results.push(result);
    }
    Ok(results)
}

/// Start a single service by index.
fn start_one_svc(
    ctx: &ForgeContext<'_>,
    binary: &str,
    state: &mut state::ForgeState,
    idx: usize,
) -> Result<ServiceResult, ForgeError> {
    let svc = ctx
        .config
        .spec
        .services
        .get(idx)
        .ok_or_else(|| ForgeError::State("service index out of range".to_owned()))?;
    let cname = service::container_name(&ctx.config.metadata.name, &svc.name);
    if ctx.dry_run {
        return Ok(ServiceResult {
            name: svc.name.clone(),
            container_name: cname,
            dry_run: true,
        });
    }
    let params = build_svc_params(binary, &cname, ctx);
    service::start_service(ctx.runner, &params, svc)?;
    let health = run_health_check(svc);
    upsert_svc_state(state, svc, &cname, &health);
    ensure_healthy(svc, &cname, &health)?;
    Ok(ServiceResult {
        name: svc.name.clone(),
        container_name: cname,
        dry_run: false,
    })
}

/// Fail the run when a configured health check never passed.
///
/// The unhealthy phase is recorded in state before this runs, and the
/// checkpointed service phase persists it. Failing loudly keeps
/// `forge up` honest for scripts: without it a dead service printed a
/// plain "started" line and the run exited 0, with `forge status` as
/// the only signal.
fn ensure_healthy(svc: &crate::config::ServiceSpec, cname: &str, health: &ServiceHealth) -> Result<(), ForgeError> {
    if *health != ServiceHealth::Unhealthy {
        return Ok(());
    }
    let retries = svc.health_check.as_ref().map_or(0, |check| check.retries);
    Err(ForgeError::Runtime(format!(
        "service '{}' (container: {cname}) failed its health check after {retries} retries",
        svc.name
    )))
}

/// Build service parameters from context.
fn build_svc_params<'ctx>(
    binary: &'ctx str,
    cname: &'ctx str,
    ctx: &'ctx ForgeContext<'_>,
) -> service::ServiceParams<'ctx> {
    service::ServiceParams {
        binary,
        container_name: cname,
        env_name: &ctx.config.metadata.name,
        config_dir: &ctx.config_dir,
        state_dir: &ctx.state_dir,
    }
}

/// Run a health check if configured, return health status.
fn run_health_check(svc: &crate::config::ServiceSpec) -> ServiceHealth {
    let Some(check) = &svc.health_check else {
        return ServiceHealth::Unknown;
    };
    let Some((addr, host_port)) = health_probe_target(svc, check.port) else {
        return ServiceHealth::Unhealthy;
    };
    match service::health::wait_for_healthy(&addr, host_port, check) {
        Ok(true) => ServiceHealth::Healthy,
        _ => ServiceHealth::Unhealthy,
    }
}

/// Resolve a container-side health-check port to a probe target.
///
/// Host-network services expose the container port directly on
/// loopback. Published ports are probed at the mapping's bind address:
/// a mapping bound to a specific interface (e.g. a LAN IP) does not
/// listen on 127.0.0.1, so probing loopback would mark a healthy
/// service unhealthy.
fn health_probe_target(svc: &crate::config::ServiceSpec, container_port: u16) -> Option<(String, u16)> {
    if matches!(svc.network, crate::config::NetworkMode::Host) {
        return Some(("127.0.0.1".to_owned(), container_port));
    }
    svc.ports
        .iter()
        .find(|port| port.container == container_port && port.protocol == "tcp")
        .map(|port| (probe_addr(port.bind_address.as_deref()), port.host))
}

/// Choose the probe address for a port mapping's bind address.
///
/// An unset or unspecified (`0.0.0.0`/`::`) address publishes on all
/// interfaces, which loopback reaches; any other address is bound to
/// that interface only and must be probed there.
fn probe_addr(bind_address: Option<&str>) -> String {
    match bind_address {
        None | Some("0.0.0.0") => "127.0.0.1".to_owned(),
        Some("::") => "::1".to_owned(),
        Some(addr) => addr.to_owned(),
    }
}

/// Insert or update a service state entry.
fn upsert_svc_state(
    state: &mut state::ForgeState,
    svc: &crate::config::ServiceSpec,
    cname: &str,
    health: &ServiceHealth,
) {
    let phase = match health {
        ServiceHealth::Unhealthy => ServicePhase::Unhealthy,
        ServiceHealth::Unknown | ServiceHealth::Healthy => ServicePhase::Running,
    };
    if let Some(ss) = state::find_service_mut(state, &svc.name) {
        ss.phase = phase;
        ss.health = health.clone();
        ss.last_observed = state::now_epoch_secs();
        return;
    }
    state.services.push(ServiceState {
        name: svc.name.clone(),
        container_name: cname.to_owned(),
        image: svc.image.clone(),
        phase,
        health: health.clone(),
        last_observed: state::now_epoch_secs(),
    });
}

// ---------------------------------------------------------------
// State helpers
// ---------------------------------------------------------------

/// Update the config digest in state.
fn update_digest(ctx: &ForgeContext<'_>, state: &mut state::ForgeState) -> Result<(), ForgeError> {
    state.config_digest = Some(state::config_digest(ctx.config)?);
    Ok(())
}

// ---------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------

/// Render all results (network, clusters, services).
fn render_all(
    writer: &mut dyn Write,
    net: Option<&NetworkSetup>,
    clusters: &[ClusterResult],
    services: &[ServiceResult],
    format: &OutputFormat,
) -> Result<(), ForgeError> {
    match format {
        OutputFormat::Json => render_json(writer, net, clusters, services),
        OutputFormat::Text => render_text(writer, net, clusters, services),
    }
}

/// Render results as JSON.
fn render_json(
    writer: &mut dyn Write,
    net: Option<&NetworkSetup>,
    clusters: &[ClusterResult],
    services: &[ServiceResult],
) -> Result<(), ForgeError> {
    let items: Vec<_> = clusters.iter().map(result_to_json).collect();
    let mut data = serde_json::json!({ "clusters": items });
    if let (Some(nd), Some(obj)) = (net, data.as_object_mut()) {
        obj.insert(
            "network".to_owned(),
            serde_json::json!({ "name": nd.name, "dryRun": nd.dry_run }),
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

/// Convert one result to a JSON value.
fn result_to_json(result: &ClusterResult) -> serde_json::Value {
    serde_json::json!({
        "name": result.name,
        "kindName": result.kind_name,
        "created": result.created,
        "dryRun": result.dry_run,
    })
}

/// Convert one service result to JSON.
fn svc_to_json(svc: &ServiceResult) -> serde_json::Value {
    serde_json::json!({
        "name": svc.name,
        "containerName": svc.container_name,
        "dryRun": svc.dry_run,
    })
}

/// Render results as text.
fn render_text(
    writer: &mut dyn Write,
    net: Option<&NetworkSetup>,
    clusters: &[ClusterResult],
    services: &[ServiceResult],
) -> Result<(), ForgeError> {
    if let Some(nd) = net {
        output::write_text(writer, &format_net_text(nd))?;
    }
    for result in clusters {
        output::write_text(writer, &format_result_text(result))?;
    }
    for svc in services {
        output::write_text(writer, &format_svc_text(svc))?;
    }
    Ok(())
}

/// Format a service result as a text line.
fn format_svc_text(svc: &ServiceResult) -> String {
    if svc.dry_run {
        return format!("would start service '{}' (container: {})", svc.name, svc.container_name);
    }
    format!("started service '{}' (container: {})", svc.name, svc.container_name)
}

/// Format a network setup result as a text line.
fn format_net_text(net: &NetworkSetup) -> String {
    if net.dry_run {
        return format!("would create network '{}'", net.name);
    }
    format!("network '{}' ready", net.name)
}

/// Format a single result as a text line.
fn format_result_text(result: &ClusterResult) -> String {
    if result.dry_run {
        return format!(
            "would create cluster '{}' (kind name: {})",
            result.name, result.kind_name
        );
    }
    if result.created {
        return format!("created cluster '{}' (kind name: {})", result.name, result.kind_name);
    }
    format!(
        "cluster '{}' already exists (kind name: {})",
        result.name, result.kind_name
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::runner::{CommandOutput, MockRunner};

    /// Build a minimal `ForgeConfig` with one cluster.
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

    /// Build a successful docker-version mock response.
    fn docker_ok() -> CommandOutput {
        CommandOutput {
            status: 0,
            stdout: "Docker 24.0\n".to_owned(),
            stderr: String::new(),
        }
    }

    /// Build a successful empty command output.
    fn empty_ok() -> CommandOutput {
        CommandOutput {
            status: 0,
            stdout: String::new(),
            stderr: String::new(),
        }
    }

    /// Docker version check failure (binary not found).
    fn docker_not_found() -> CommandOutput {
        CommandOutput {
            status: 1,
            stdout: String::new(),
            stderr: "docker: command not found\n".to_owned(),
        }
    }

    /// Successful Podman version output.
    fn podman_ok() -> CommandOutput {
        CommandOutput {
            status: 0,
            stdout: "Podman 4.0\n".to_owned(),
            stderr: String::new(),
        }
    }

    /// Build a minimal kubeconfig YAML with the given server URL.
    fn sample_kubeconfig(server_url: &str) -> String {
        format!(
            "\
apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority-data: dGVzdC1jYQ==
    server: {server_url}
  name: kind-test
contexts:
- context:
    cluster: kind-test
    user: kind-test
  name: kind-test
current-context: kind-test
users:
- name: kind-test
  user:
    client-certificate-data: dGVzdC1jZXJ0
    client-key-data: dGVzdC1rZXk=
"
        )
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

    /// Build a mock that responds to docker, kind list, kind create.
    fn mock_for_create() -> MockRunner {
        let mut runner = MockRunner::new();
        runner.respond("docker version", docker_ok());
        runner.respond("kind get clusters", empty_ok());
        runner.respond("kind", empty_ok());
        runner
    }

    /// Run `up` with the given context and return output text.
    fn run_up(ctx: &ForgeContext<'_>) -> String {
        let mut buf = Vec::new();
        run(ctx, &mut buf).unwrap_or_else(|_| std::process::abort());
        String::from_utf8_lossy(&buf).into_owned()
    }

    #[test]
    fn up_creates_missing_cluster() {
        let dir = test_dir();
        let config = test_config();
        let runner = mock_for_create();
        let ctx = ForgeContext {
            runner: &runner,
            config: &config,
            state_dir: dir.path().to_path_buf(),
            config_dir: dir.path().to_path_buf(),
            format: OutputFormat::Text,
            dry_run: false,
        };
        let text = run_up(&ctx);
        assert!(runner.was_called("kind create cluster"), "should call kind create");
        assert!(text.contains("created"), "output should mention created: {text}");
    }

    #[test]
    fn up_skips_existing_cluster() {
        let dir = test_dir();
        let config = test_config();
        let mut runner = MockRunner::new();
        runner.respond("docker version", docker_ok());
        runner.respond(
            "kind get clusters",
            CommandOutput {
                status: 0,
                stdout: "forge-hub\n".to_owned(),
                stderr: String::new(),
            },
        );
        runner.respond("kind", empty_ok());
        let ctx = ForgeContext {
            runner: &runner,
            config: &config,
            state_dir: dir.path().to_path_buf(),
            config_dir: dir.path().to_path_buf(),
            format: OutputFormat::Text,
            dry_run: false,
        };
        let text = run_up(&ctx);
        assert!(!runner.was_called("kind create"), "should not call kind create");
        assert!(text.contains("already exists"), "output should note existing: {text}");
    }

    #[test]
    fn up_persists_creating_phase_when_create_fails() {
        let dir = test_dir();
        let config = test_config();
        let mut runner = MockRunner::new();
        runner.respond("docker version", docker_ok());
        runner.respond("kind get clusters", empty_ok());
        // The generic kind responder covers `kind create cluster`.
        runner.respond(
            "kind",
            CommandOutput {
                status: 1,
                stdout: String::new(),
                stderr: "create blew up\n".to_owned(),
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
        let result = run(&ctx, &mut buf);

        assert!(result.is_err(), "a failing create should fail the run");
        let st = state::load(dir.path()).unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            state::find_cluster(&st, "hub").map(|cs| cs.phase.clone()),
            Some(ClusterPhase::Creating),
            "an interrupted create must leave a Creating record for down"
        );
    }

    #[test]
    fn up_dry_run_does_not_create() {
        let dir = test_dir();
        let config = test_config();
        let mut runner = MockRunner::new();
        runner.respond("docker version", docker_ok());
        let ctx = ForgeContext {
            runner: &runner,
            config: &config,
            state_dir: dir.path().to_path_buf(),
            config_dir: dir.path().to_path_buf(),
            format: OutputFormat::Text,
            dry_run: true,
        };
        let text = run_up(&ctx);
        assert!(!runner.was_called("kind create"), "dry-run should not call kind create");
        assert!(text.contains("would create"), "should say would create: {text}");
    }

    /// Build a config with one service disabled for `forge up`.
    fn test_config_with_disabled_service() -> crate::config::ForgeConfig {
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
    - name: placeholder
      image: example/placeholder:v1
      autoStart: false
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

    /// Build a config with one cluster and one non-auto-start service.
    fn test_config_with_cluster_and_service() -> crate::config::ForgeConfig {
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
  services:
    - name: placeholder
      image: example/placeholder:v1
      autoStart: false
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
    fn up_skips_services_with_auto_start_false() {
        let config = test_config_with_disabled_service();
        let dir = test_dir();
        let mut runner = MockRunner::new();
        runner.respond("docker version", docker_ok());
        let ctx = ForgeContext {
            runner: &runner,
            config: &config,
            state_dir: dir.path().to_path_buf(),
            config_dir: dir.path().to_path_buf(),
            format: OutputFormat::Text,
            dry_run: false,
        };

        let text = run_up(&ctx);

        assert!(!runner.was_called("docker run"), "autoStart false should not start");
        assert!(
            !text.contains("placeholder"),
            "skipped service should not appear as started: {text}"
        );
    }

    #[test]
    fn up_exports_kubeconfig_when_services_are_configured() {
        let config = test_config_with_cluster_and_service();
        let dir = test_dir();
        let runner = mock_for_service_kubeconfig_export();
        let ctx = ForgeContext {
            runner: &runner,
            config: &config,
            state_dir: dir.path().to_path_buf(),
            config_dir: dir.path().to_path_buf(),
            format: OutputFormat::Text,
            dry_run: false,
        };

        let _text = run_up(&ctx);

        assert!(
            runner.was_called("kind get kubeconfig --name forge-hub"),
            "service-bearing environments should export a container-reachable kubeconfig"
        );
        assert!(
            dir.path().join("runtime/kubeconfig/hub/config").exists(),
            "rewritten kubeconfig should be written under runtime"
        );
    }

    /// Find a TCP port with no listener on loopback.
    fn closed_port() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap_or_else(|_| std::process::abort());
        let Ok(addr) = listener.local_addr() else {
            std::process::abort();
        };
        drop(listener);
        addr.port()
    }

    /// YAML for one auto-start service probing the given host port.
    fn health_check_yaml(port: u16) -> String {
        format!(
            "\
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
    - name: web
      image: example/web:v1
      ports:
        - host: {port}
          container: 80
          protocol: tcp
      healthCheck:
        type: tcp
        port: 80
        interval: 1ms
        timeout: 50ms
        retries: 1
  stacks: {{}}
"
        )
    }

    /// Config with one auto-start service probing the given host port.
    fn test_config_with_health_check(port: u16) -> crate::config::ForgeConfig {
        serde_yaml::from_str(&health_check_yaml(port)).unwrap_or_else(|_| {
            std::process::abort();
            #[expect(unreachable_code, reason = "abort prevents reaching this")]
            {
                unreachable!()
            }
        })
    }

    #[test]
    fn up_fails_when_service_health_check_never_passes() {
        let dir = test_dir();
        // Nothing listens on the probed port, so every retry fails.
        let config = test_config_with_health_check(closed_port());
        let mut runner = MockRunner::new();
        runner.respond("docker version", docker_ok());
        runner.respond("docker container inspect test-web", docker_not_found());
        runner.respond("docker", empty_ok());
        let ctx = ForgeContext {
            runner: &runner,
            config: &config,
            state_dir: dir.path().to_path_buf(),
            config_dir: dir.path().to_path_buf(),
            format: OutputFormat::Text,
            dry_run: false,
        };

        let mut buf = Vec::new();
        let result = run(&ctx, &mut buf);

        let Err(err) = result else {
            std::process::abort();
        };
        let msg = err.to_string();
        assert!(
            msg.contains("service 'web'") && msg.contains("failed its health check"),
            "the error must name the unhealthy service: {msg}"
        );
        let st = state::load(dir.path()).unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            state::find_service(&st, "web").map(|svc| svc.phase.clone()),
            Some(ServicePhase::Unhealthy),
            "the failed probe must still be recorded in state"
        );
    }

    /// Mock a successful `forge up` for an environment with services.
    fn mock_for_service_kubeconfig_export() -> MockRunner {
        let mut runner = MockRunner::new();
        runner.respond("docker version", docker_ok());
        runner.respond("kind get clusters", empty_ok());
        runner.respond("kind", empty_ok());
        runner.respond(
            "kind get kubeconfig --name forge-hub",
            CommandOutput {
                status: 0,
                stdout: sample_kubeconfig("https://127.0.0.1:42789"),
                stderr: String::new(),
            },
        );
        runner
    }

    #[test]
    fn up_does_not_export_kubeconfig_without_services() {
        let dir = test_dir();
        let config = test_config();
        let runner = mock_for_create();
        let ctx = ForgeContext {
            runner: &runner,
            config: &config,
            state_dir: dir.path().to_path_buf(),
            config_dir: dir.path().to_path_buf(),
            format: OutputFormat::Text,
            dry_run: false,
        };

        let _text = run_up(&ctx);

        assert!(
            !runner.was_called("kind get kubeconfig"),
            "service-free environments should not write kubeconfigs containing client key material"
        );
    }

    #[test]
    fn ensure_state_entry_refreshes_stale_kind_name() {
        let mut st = state::empty();
        st.clusters.push(ClusterState {
            name: "hub".to_owned(),
            kind_name: "forge-hub".to_owned(),
            context: "kind-forge-hub".to_owned(),
            phase: ClusterPhase::Gone,
        });

        // A clusterPrefix change derives a new KIND name for the same
        // config cluster; the state entry must follow it.
        ensure_state_entry(&mut st, "hub", "dev-hub", ClusterPhase::Running);

        let cluster = state::find_cluster(&st, "hub").unwrap_or_else(|| std::process::abort());
        assert_eq!(cluster.kind_name, "dev-hub", "kind name must track the current prefix");
        assert_eq!(cluster.context, "kind-dev-hub", "context must follow the new kind name");
        assert_eq!(cluster.phase, ClusterPhase::Running, "phase must be updated");
    }

    /// Parse a config with one service using the given port mapping.
    fn config_with_port_mapping(mapping: &str) -> crate::config::ForgeConfig {
        let yaml = format!(
            "
apiVersion: forge.praxis.dev/v1alpha1
kind: Environment
metadata: {{ name: test }}
spec:
  runtime: {{ provider: docker, clusterPrefix: forge }}
  services:
    - name: web
      image: example/web:v1
      ports:
        - {mapping}
  stacks: {{}}
"
        );
        serde_yaml::from_str(&yaml).unwrap_or_else(|_| {
            std::process::abort();
            #[expect(unreachable_code, reason = "abort prevents reaching this")]
            {
                unreachable!()
            }
        })
    }

    /// Resolve the probe target for the config's single service.
    fn probe_target_for(mapping: &str, container_port: u16) -> Option<(String, u16)> {
        let config = config_with_port_mapping(mapping);
        let svc = config.spec.services.first().unwrap_or_else(|| {
            std::process::abort();
            #[expect(unreachable_code, reason = "abort prevents reaching this")]
            {
                unreachable!()
            }
        });
        health_probe_target(svc, container_port)
    }

    #[test]
    fn health_probe_maps_container_port_to_host_port() {
        let target = probe_target_for(
            "{ bindAddress: 127.0.0.1, host: 8080, container: 80, protocol: tcp }",
            80,
        );
        assert_eq!(target, Some(("127.0.0.1".to_owned(), 8080)));
    }

    #[test]
    fn health_probe_uses_the_mapping_bind_address() {
        // A port published on a specific interface is not reachable on
        // loopback, so the probe must target that interface.
        let target = probe_target_for(
            "{ bindAddress: 192.168.1.50, host: 8080, container: 80, protocol: tcp }",
            80,
        );
        assert_eq!(target, Some(("192.168.1.50".to_owned(), 8080)));
    }

    #[test]
    fn health_probe_treats_unspecified_bind_addresses_as_loopback() {
        let all_v4 = probe_target_for("{ bindAddress: 0.0.0.0, host: 8080, container: 80, protocol: tcp }", 80);
        assert_eq!(all_v4, Some(("127.0.0.1".to_owned(), 8080)));
        let all_v6 = probe_target_for("{ bindAddress: '::', host: 8080, container: 80, protocol: tcp }", 80);
        assert_eq!(all_v6, Some(("::1".to_owned(), 8080)));
        let unset = probe_target_for("{ host: 8080, container: 80, protocol: tcp }", 80);
        assert_eq!(unset, Some(("127.0.0.1".to_owned(), 8080)));
    }

    /// Build a config with `network.crossCluster: true`.
    fn test_config_with_network() -> crate::config::ForgeConfig {
        let yaml = "\
apiVersion: forge.praxis.dev/v1alpha1
kind: Environment
metadata:
  name: test
spec:
  runtime:
    provider: docker
    clusterPrefix: forge
  network:
    crossCluster: true
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

    /// Network not-found response for inspect, worded as Docker words it.
    fn net_not_found() -> CommandOutput {
        CommandOutput {
            status: 1,
            stdout: String::new(),
            stderr: "Error: No such network: test-net\n".to_owned(),
        }
    }

    /// Formatted Docker IPAM response for the test network.
    fn network_cidr(cidr: &str) -> CommandOutput {
        CommandOutput {
            status: 0,
            stdout: format!(r#"[{{"Subnet":"{cidr}","Gateway":"172.18.0.1"}}]"#),
            stderr: String::new(),
        }
    }

    #[test]
    fn up_creates_network_when_configured() {
        let dir = test_dir();
        let config = test_config_with_network();
        let mut runner = MockRunner::new();
        runner.respond("docker version", docker_ok());
        runner.respond("docker network inspect test-net", net_not_found());
        runner.respond(
            "docker network inspect test-net --format {{json .IPAM.Config}}",
            network_cidr("172.18.0.0/16"),
        );
        runner.respond("docker", empty_ok());
        runner.respond("kind get clusters", empty_ok());
        runner.respond("kind", empty_ok());
        let ctx = ForgeContext {
            runner: &runner,
            config: &config,
            state_dir: dir.path().to_path_buf(),
            config_dir: dir.path().to_path_buf(),
            format: OutputFormat::Text,
            dry_run: false,
        };
        let text = run_up(&ctx);
        assert!(runner.was_called("network create"), "should call network create");
        assert!(
            text.contains("network 'test-net' ready"),
            "should report network: {text}"
        );
        assert_kind_create_has_network_env(&runner, "test-net");
    }

    /// A failing `kind get clusters` probe.
    fn kind_list_failed() -> CommandOutput {
        CommandOutput {
            status: 1,
            stdout: String::new(),
            stderr: "kind: connection refused\n".to_owned(),
        }
    }

    #[test]
    #[expect(clippy::too_many_lines, reason = "test setup")]
    fn up_records_earlier_phase_when_later_phase_fails() {
        let dir = test_dir();
        let config = test_config_with_network();
        let mut runner = MockRunner::new();
        runner.respond("docker version", docker_ok());
        runner.respond("docker network inspect test-net", net_not_found());
        runner.respond(
            "docker network inspect test-net --format {{json .IPAM.Config}}",
            network_cidr("172.18.0.0/16"),
        );
        runner.respond("docker", empty_ok());
        runner.respond("kind get clusters", kind_list_failed());
        let ctx = ForgeContext {
            runner: &runner,
            config: &config,
            state_dir: dir.path().to_path_buf(),
            config_dir: dir.path().to_path_buf(),
            format: OutputFormat::Text,
            dry_run: false,
        };

        let mut buf = Vec::new();
        let result = run(&ctx, &mut buf);

        assert!(result.is_err(), "a failing cluster phase should fail the run");
        assert!(
            runner.was_called("network create"),
            "the network phase should have created a real network"
        );
        assert!(
            dir.path().join("state.json").exists(),
            "a failed run must still persist what earlier phases created"
        );
        let persisted = state::load(dir.path()).unwrap_or_else(|_| std::process::abort());
        let net = persisted.network;
        assert_eq!(
            net.as_ref().map(|ns| ns.name.as_str()),
            Some("test-net"),
            "the created network must be recorded so down can remove it"
        );
        assert_eq!(
            net.map(|ns| ns.phase),
            Some(NetworkPhase::Active),
            "the recorded network should be marked active"
        );
        let Some(op) = persisted.last_operation else {
            std::process::abort();
        };
        assert_eq!(op.operation, "up", "the failed run must be the last operation");
        assert!(!op.success, "a failed phase must not be recorded as a success");
    }

    #[test]
    #[expect(clippy::too_many_lines, reason = "test setup")]
    fn up_records_network_when_cidr_inspect_fails() {
        let dir = test_dir();
        let config = test_config_with_network();
        let mut runner = MockRunner::new();
        runner.respond("docker version", docker_ok());
        runner.respond("docker network inspect test-net", net_not_found());
        // The network is created, then the CIDR inspect fails. The network is
        // live either way, so it has to be recorded for `down` to remove it.
        runner.respond(
            "docker network inspect test-net --format {{json .IPAM.Config}}",
            CommandOutput {
                status: 1,
                stdout: String::new(),
                stderr: "inspect blew up\n".to_owned(),
            },
        );
        runner.respond("docker", empty_ok());
        let ctx = ForgeContext {
            runner: &runner,
            config: &config,
            state_dir: dir.path().to_path_buf(),
            config_dir: dir.path().to_path_buf(),
            format: OutputFormat::Text,
            dry_run: false,
        };

        let mut buf = Vec::new();
        let result = run(&ctx, &mut buf);

        assert!(result.is_err(), "a failing CIDR inspect should fail the run");
        assert!(
            runner.was_called("network create"),
            "the network should really have been created"
        );
        let persisted = state::load(dir.path()).unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            persisted.network.map(|ns| ns.name),
            Some("test-net".to_owned()),
            "a created network must be recorded even when the CIDR lookup fails"
        );
    }

    #[test]
    fn checkpoint_failure_is_reported_alongside_the_phase_failure() {
        let dir = test_dir();
        let config = test_config_with_network();
        let runner = MockRunner::new();
        // A regular file where the state directory should be, so `save` fails.
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, b"x").unwrap_or_else(|_| std::process::abort());
        let ctx = ForgeContext {
            runner: &runner,
            config: &config,
            state_dir: blocker.join("state"),
            config_dir: dir.path().to_path_buf(),
            format: OutputFormat::Text,
            dry_run: false,
        };

        let mut state = state::empty();
        let outcome: Result<(), ForgeError> = checkpointed(&ctx, &mut state, "up", |_st| {
            Err(ForgeError::State("phase blew up".to_owned()))
        });

        let Err(err) = outcome else {
            std::process::abort();
        };
        let msg = err.to_string();
        assert!(
            msg.contains("phase blew up"),
            "the phase failure must stay visible: {msg}"
        );
        assert!(
            msg.contains("not recorded"),
            "a lost checkpoint must be reported too: {msg}"
        );
    }

    #[test]
    fn up_dry_run_writes_no_state_file() {
        let dir = test_dir();
        let config = test_config_with_network();
        let mut runner = MockRunner::new();
        runner.respond("docker version", docker_ok());
        let ctx = ForgeContext {
            runner: &runner,
            config: &config,
            state_dir: dir.path().to_path_buf(),
            config_dir: dir.path().to_path_buf(),
            format: OutputFormat::Text,
            dry_run: true,
        };

        let _text = run_up(&ctx);

        assert!(
            !dir.path().join("state.json").exists(),
            "dry-run must not persist state"
        );
    }

    #[test]
    fn up_skips_network_without_config() {
        let dir = test_dir();
        let config = test_config();
        let runner = mock_for_create();
        let ctx = ForgeContext {
            runner: &runner,
            config: &config,
            state_dir: dir.path().to_path_buf(),
            config_dir: dir.path().to_path_buf(),
            format: OutputFormat::Text,
            dry_run: false,
        };
        let text = run_up(&ctx);
        assert!(!runner.was_called("network"), "should not call any network commands");
        assert!(!text.contains("network"), "should not mention network: {text}");
    }

    #[test]
    fn up_dry_run_reports_network() {
        let dir = test_dir();
        let config = test_config_with_network();
        let mut runner = MockRunner::new();
        runner.respond("docker version", docker_ok());
        let ctx = ForgeContext {
            runner: &runner,
            config: &config,
            state_dir: dir.path().to_path_buf(),
            config_dir: dir.path().to_path_buf(),
            format: OutputFormat::Text,
            dry_run: true,
        };
        let text = run_up(&ctx);
        assert!(
            !runner.was_called("network create"),
            "dry-run should not create network"
        );
        assert!(
            text.contains("would create network"),
            "should report would create network: {text}"
        );
    }

    #[test]
    fn set_network_active_preserves_compatible_pools() {
        let mut st = state::empty();
        st.network = Some(state::NetworkState {
            name: "old-net".to_owned(),
            phase: NetworkPhase::Active,
            cidr: Some("172.18.0.0/16".to_owned()),
            cluster_pools: vec![state::ClusterPool {
                cluster: "hub".to_owned(),
                range: "172.18.255.231-172.18.255.250".to_owned(),
            }],
        });
        set_network_active(&mut st, "old-net", "172.18.0.0/16");
        let net = st.network.as_ref().unwrap_or_else(|| std::process::abort());
        assert_eq!(net.name, "old-net", "name should be preserved");
        assert_eq!(net.cidr.as_deref(), Some("172.18.0.0/16"), "cidr should be preserved");
        assert_eq!(net.cluster_pools.len(), 1, "pools should be preserved");
    }

    #[test]
    fn set_network_active_clears_pools_when_cidr_changes() {
        let mut st = state::empty();
        st.network = Some(state::NetworkState {
            name: "test-net".to_owned(),
            phase: NetworkPhase::Gone,
            cidr: Some("172.19.0.0/16".to_owned()),
            cluster_pools: vec![state::ClusterPool {
                cluster: "hub".to_owned(),
                range: "172.19.255.231-172.19.255.250".to_owned(),
            }],
        });

        set_network_active(&mut st, "test-net", "172.18.0.0/16");

        let net = st.network.as_ref().unwrap_or_else(|| std::process::abort());
        assert_eq!(net.phase, NetworkPhase::Active);
        assert_eq!(net.cidr.as_deref(), Some("172.18.0.0/16"));
        assert!(net.cluster_pools.is_empty(), "stale pools must be discarded");
    }

    #[test]
    fn cross_cluster_auto_resolved_docker_passes() {
        let config = test_config_cross_auto();
        let dir = test_dir();
        let mut runner = MockRunner::new();
        runner.respond("docker version", docker_ok());
        runner.respond("docker network inspect test-net", net_not_found());
        runner.respond(
            "docker network inspect test-net --format {{json .IPAM.Config}}",
            network_cidr("172.18.0.0/16"),
        );
        runner.respond("docker", empty_ok());
        runner.respond("kind get clusters", empty_ok());
        runner.respond("kind", empty_ok());
        let ctx = ForgeContext {
            runner: &runner,
            config: &config,
            state_dir: dir.path().to_path_buf(),
            config_dir: dir.path().to_path_buf(),
            format: OutputFormat::Text,
            dry_run: false,
        };
        let text = run_up(&ctx);
        assert!(
            text.contains("network 'test-net' ready"),
            "auto+docker should succeed: {text}"
        );
    }

    #[test]
    fn cross_cluster_auto_resolved_podman_fails() {
        let config = test_config_cross_auto();
        let dir = test_dir();
        let mut runner = MockRunner::new();
        runner.respond("docker version", docker_not_found());
        runner.respond("podman version", podman_ok());
        let ctx = ForgeContext {
            runner: &runner,
            config: &config,
            state_dir: dir.path().to_path_buf(),
            config_dir: dir.path().to_path_buf(),
            format: OutputFormat::Text,
            dry_run: false,
        };
        let mut buf = Vec::new();
        let result = run(&ctx, &mut buf);
        assert!(result.is_err(), "auto+podman+crossCluster should fail");
        let Err(err) = result else {
            std::process::abort();
        };
        let msg = err.to_string();
        assert!(msg.contains("Docker"), "error should mention Docker: {msg}");
    }

    #[test]
    fn cross_cluster_explicit_docker_passes() {
        let dir = test_dir();
        let config = test_config_with_network();
        let mut runner = MockRunner::new();
        runner.respond("docker version", docker_ok());
        runner.respond("docker network inspect test-net", net_not_found());
        runner.respond(
            "docker network inspect test-net --format {{json .IPAM.Config}}",
            network_cidr("172.18.0.0/16"),
        );
        runner.respond("docker", empty_ok());
        runner.respond("kind get clusters", empty_ok());
        runner.respond("kind", empty_ok());
        let ctx = ForgeContext {
            runner: &runner,
            config: &config,
            state_dir: dir.path().to_path_buf(),
            config_dir: dir.path().to_path_buf(),
            format: OutputFormat::Text,
            dry_run: false,
        };
        let text = run_up(&ctx);
        assert!(
            text.contains("network 'test-net' ready"),
            "explicit docker should succeed: {text}"
        );
    }

    #[test]
    fn no_cross_cluster_podman_allowed() {
        let config = test_config_podman();
        let dir = test_dir();
        let mut runner = MockRunner::new();
        runner.respond("podman version", podman_ok());
        runner.respond("kind get clusters", empty_ok());
        runner.respond("kind", empty_ok());
        let ctx = ForgeContext {
            runner: &runner,
            config: &config,
            state_dir: dir.path().to_path_buf(),
            config_dir: dir.path().to_path_buf(),
            format: OutputFormat::Text,
            dry_run: false,
        };
        let text = run_up(&ctx);
        assert!(
            text.contains("created"),
            "podman without crossCluster should succeed: {text}"
        );
    }

    // Test Utilities

    /// Verify `kind create` was called with the expected Docker network env.
    fn assert_kind_create_has_network_env(runner: &MockRunner, expected: &str) {
        let calls = runner.calls();
        let Some(call) = calls.iter().find(|cl| cl.to_string().contains("kind create")) else {
            std::process::abort();
        };
        let key = std::ffi::OsString::from("KIND_EXPERIMENTAL_DOCKER_NETWORK");
        let val = call.env.get(&key).map(|os| os.to_string_lossy().into_owned());
        assert_eq!(val.as_deref(), Some(expected), "kind create should set network env");
    }

    /// Config with `crossCluster: true` and `provider: auto`.
    fn test_config_cross_auto() -> crate::config::ForgeConfig {
        let yaml = "\
apiVersion: forge.praxis.dev/v1alpha1
kind: Environment
metadata:
  name: test
spec:
  runtime:
    provider: auto
    clusterPrefix: forge
  network:
    crossCluster: true
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

    /// Config with `provider: podman` and no cross-cluster networking.
    fn test_config_podman() -> crate::config::ForgeConfig {
        let yaml = "\
apiVersion: forge.praxis.dev/v1alpha1
kind: Environment
metadata:
  name: test
spec:
  runtime:
    provider: podman
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
}
