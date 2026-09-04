//! Deployment stack lifecycle management.
//!
//! Applies composable deployment stacks to KIND clusters.  Each
//! stack is a sequence of steps (kubectl apply, helm install, etc.)
//! executed through [`CommandRunner`](crate::command::runner::CommandRunner).
//! Templates allow cluster-specific customisation without
//! duplicating stack definitions.

pub mod engine;
pub mod steps;
pub mod template;

use std::io::Write;

use sha2::Digest as _;

use crate::{
    cli::StackCommand,
    config::{ClusterSpec, StackSpec},
    context::ForgeContext,
    error::ForgeError,
    output::{self, OutputFormat},
    state::{self, ClusterPool, StackPhase, StackState},
};

// -------------------------------------------------------------
// Public dispatch
// -------------------------------------------------------------

/// Dispatch a stack subcommand.
///
/// # Errors
///
/// Returns [`ForgeError`] if the operation fails.
pub fn dispatch(ctx: &ForgeContext<'_>, cmd: &StackCommand, writer: &mut dyn Write) -> Result<(), ForgeError> {
    match cmd {
        StackCommand::List => handle_list(ctx, writer),
        StackCommand::Plan { cluster, stack } => handle_plan(ctx, cluster, stack.as_deref(), writer),
        StackCommand::Apply { cluster, stack } => handle_apply(ctx, cluster, stack.as_deref(), writer),
        StackCommand::Status { cluster } => handle_status(ctx, cluster.as_deref(), writer),
    }
}

// -------------------------------------------------------------
// Handlers
// -------------------------------------------------------------

/// List configured stacks.
fn handle_list(ctx: &ForgeContext<'_>, writer: &mut dyn Write) -> Result<(), ForgeError> {
    match &ctx.format {
        OutputFormat::Json => render_list_json(ctx, writer),
        OutputFormat::Text => render_list_text(ctx, writer),
    }
}

/// Show what a stack apply would do.
///
/// Plan expands for-each steps and renders templates with the same context
/// `apply` builds, so it surfaces resolved URLs and values and catches
/// variable, property, and path errors up front. Values produced during a
/// run (this run's captures, an unallocated `MetalLB` pool) do not exist yet,
/// so references to them render as `<pending-...>` placeholders (see
/// `engine::plan_stack`).
fn handle_plan(
    ctx: &ForgeContext<'_>,
    cluster_name: &str,
    stack_filter: Option<&str>,
    writer: &mut dyn Write,
) -> Result<(), ForgeError> {
    let cluster = lookup_cluster(ctx, cluster_name)?;
    let stacks = resolve_stacks(ctx, cluster, stack_filter)?;
    let st = state::load(&ctx.state_dir)?;
    let planned = plan_stacks(ctx, cluster, &stacks, &st)?;
    match &ctx.format {
        OutputFormat::Json => render_plan_json(cluster, &planned, writer),
        OutputFormat::Text => render_plan_text(cluster, &planned, writer),
    }
}

/// Apply stacks to a cluster.
fn handle_apply(
    ctx: &ForgeContext<'_>,
    cluster_name: &str,
    stack_filter: Option<&str>,
    writer: &mut dyn Write,
) -> Result<(), ForgeError> {
    let cluster = lookup_cluster(ctx, cluster_name)?;
    let stacks = resolve_stacks(ctx, cluster, stack_filter)?;
    if ctx.dry_run {
        return handle_plan(ctx, cluster_name, stack_filter, writer);
    }
    let results = apply_stacks(ctx, cluster, &stacks)?;
    ensure_apply_success(cluster_name, &results)?;
    render_apply(cluster_name, &results, &ctx.format, writer)
}

/// Show applied stack status.
fn handle_status(
    ctx: &ForgeContext<'_>,
    cluster_filter: Option<&str>,
    writer: &mut dyn Write,
) -> Result<(), ForgeError> {
    let st = state::load(&ctx.state_dir)?;
    let rows: Vec<StatusRow<'_>> = filter_stack_states(&st, cluster_filter)
        .into_iter()
        .map(|entry| StatusRow {
            entry,
            drifted: stack_drifted(ctx, entry),
        })
        .collect();
    match &ctx.format {
        OutputFormat::Json => render_status_json(&rows, writer),
        OutputFormat::Text => render_status_text(&rows, writer),
    }
}

// -------------------------------------------------------------
// Apply logic
// -------------------------------------------------------------

/// Result of one stack apply attempt.
struct ApplyResult {
    /// Stack name.
    name: String,
    /// Number of steps executed.
    steps_executed: usize,
    /// Whether the apply succeeded.
    success: bool,
    /// Underlying step failure, when the apply did not succeed.
    error: Option<String>,
}

/// Apply resolved stacks and persist state.
///
/// Stops after the first failed stack: later stacks can consume
/// captures recorded by earlier ones, so they are not applied on top
/// of an incomplete prerequisite.  State for the stacks already
/// attempted is still persisted.
fn apply_stacks(
    ctx: &ForgeContext<'_>,
    cluster: &ClusterSpec,
    stacks: &[(&str, &StackSpec)],
) -> Result<Vec<ApplyResult>, ForgeError> {
    let _lock = state::lock::acquire(&ctx.state_dir)?;
    let mut st = state::load(&ctx.state_dir)?;
    let mut results = Vec::new();
    for (name, spec) in stacks {
        let result = apply_one(ctx, cluster, name, spec, &mut st);
        let failed = !result.success;
        results.push(result);
        if failed {
            break;
        }
    }
    state::save(&ctx.state_dir, &st)?;
    Ok(results)
}

/// Apply a single stack and update state.
fn apply_one(
    ctx: &ForgeContext<'_>,
    cluster: &ClusterSpec,
    name: &str,
    spec: &StackSpec,
    st: &mut state::ForgeState,
) -> ApplyResult {
    let digest = stack_digest(spec).ok();
    upsert_stack_state(st, name, &cluster.name, StackPhase::Applying, digest.as_deref());
    let network = build_network_params(ctx, cluster, st);
    match engine::apply_stack(ctx, cluster, name, spec, network.as_ref(), &st.captures) {
        Ok(outcome) => {
            if let Some(alloc) = &outcome.pool_allocation {
                let network_name = crate::networking::network_name(&ctx.config.metadata.name);
                record_pool_allocation(st, &network_name, &cluster.name, alloc);
            }
            record_captures(st, &cluster.name, &outcome.captures);
            upsert_stack_state(st, name, &cluster.name, StackPhase::Applied, digest.as_deref());
            ApplyResult {
                name: name.to_owned(),
                steps_executed: outcome.steps_executed,
                success: true,
                error: None,
            }
        },
        Err(err) => {
            let message = err.to_string();
            set_stack_failed(st, name, &cluster.name, digest.as_deref(), &message);
            ApplyResult {
                name: name.to_owned(),
                steps_executed: 0,
                success: false,
                error: Some(message),
            }
        },
    }
}

/// Convert a failed stack result into a command error after state is saved.
fn ensure_apply_success(cluster: &str, results: &[ApplyResult]) -> Result<(), ForgeError> {
    let Some(failed) = results.iter().find(|result| !result.success) else {
        return Ok(());
    };
    let message = failed.error.as_deref().unwrap_or("stack step failed");
    Err(ForgeError::Command {
        program: format!("stack apply {} -> {cluster}", failed.name),
        message: message.to_owned(),
    })
}

// -------------------------------------------------------------
// Lookups
// -------------------------------------------------------------

/// Find a cluster in the config by name.
fn lookup_cluster<'ctx>(ctx: &'ctx ForgeContext<'_>, name: &str) -> Result<&'ctx ClusterSpec, ForgeError> {
    ctx.config
        .spec
        .clusters
        .iter()
        .find(|cluster| cluster.name == name)
        .ok_or_else(|| ForgeError::Config(format!("cluster '{name}' not found")))
}

/// Resolve which stacks to apply for a cluster.
fn resolve_stacks<'ctx>(
    ctx: &'ctx ForgeContext<'_>,
    cluster: &ClusterSpec,
    stack_filter: Option<&str>,
) -> Result<Vec<(&'ctx str, &'ctx StackSpec)>, ForgeError> {
    if let Some(name) = stack_filter {
        let entry = lookup_stack_entry(ctx, name)?;
        return Ok(vec![entry]);
    }
    resolve_cluster_stacks(ctx, cluster)
}

/// Resolve all stacks assigned to a cluster.
fn resolve_cluster_stacks<'ctx>(
    ctx: &'ctx ForgeContext<'_>,
    cluster: &ClusterSpec,
) -> Result<Vec<(&'ctx str, &'ctx StackSpec)>, ForgeError> {
    let mut result = Vec::new();
    for name in &cluster.stacks {
        result.push(lookup_stack_entry(ctx, name)?);
    }
    Ok(result)
}

/// Find a stack entry (key+value) in the config.
fn lookup_stack_entry<'ctx>(
    ctx: &'ctx ForgeContext<'_>,
    name: &str,
) -> Result<(&'ctx str, &'ctx StackSpec), ForgeError> {
    ctx.config
        .spec
        .stacks
        .get_key_value(name)
        .map(|(key, val)| (key.as_str(), val))
        .ok_or_else(|| ForgeError::Config(format!("stack '{name}' not found")))
}

// -------------------------------------------------------------
// State management
// -------------------------------------------------------------

/// Insert or update a stack state entry.
fn upsert_stack_state(st: &mut state::ForgeState, name: &str, cluster: &str, phase: StackPhase, digest: Option<&str>) {
    if let Some(existing) = state::find_stack_mut(st, name, cluster) {
        existing.phase = phase;
        existing.digest = digest.map(str::to_owned);
        existing.timestamp = state::now_epoch_secs();
        existing.error = None;
        return;
    }
    st.stacks.push(StackState {
        name: name.to_owned(),
        cluster: cluster.to_owned(),
        phase,
        digest: digest.map(str::to_owned),
        timestamp: state::now_epoch_secs(),
        error: None,
    });
}

/// Mark a stack as failed with an error message.
fn set_stack_failed(st: &mut state::ForgeState, name: &str, cluster: &str, digest: Option<&str>, message: &str) {
    if let Some(existing) = state::find_stack_mut(st, name, cluster) {
        existing.phase = StackPhase::Failed;
        existing.digest = digest.map(str::to_owned);
        existing.timestamp = state::now_epoch_secs();
        existing.error = Some(message.to_owned());
        return;
    }
    st.stacks.push(StackState {
        name: name.to_owned(),
        cluster: cluster.to_owned(),
        phase: StackPhase::Failed,
        digest: digest.map(str::to_owned),
        timestamp: state::now_epoch_secs(),
        error: Some(message.to_owned()),
    });
}

/// Compute a stable digest for the stack spec being applied.
fn stack_digest(spec: &StackSpec) -> Result<String, ForgeError> {
    let json = serde_json::to_string(spec)
        .map_err(|err| ForgeError::State(format!("cannot serialize stack spec for digest: {err}")))?;
    let hash = sha2::Sha256::digest(json.as_bytes());
    Ok(format!("{hash:x}"))
}

/// One stack status row with computed drift.
struct StatusRow<'st> {
    /// Persisted stack state entry.
    entry: &'st StackState,
    /// Whether the configured spec has drifted from the applied
    /// digest (`None` when drift cannot be determined).
    drifted: Option<bool>,
}

/// Compare a stored stack digest against the currently configured spec.
///
/// Returns `Some(true)` when the spec has changed since the recorded
/// apply, `Some(false)` when it still matches, and `None` when drift
/// cannot be determined (no digest was recorded, or the stack is no
/// longer present in the config).
fn stack_drifted(ctx: &ForgeContext<'_>, entry: &StackState) -> Option<bool> {
    let stored = entry.digest.as_deref()?;
    let spec = ctx.config.spec.stacks.get(&entry.name)?;
    let fresh = stack_digest(spec).ok()?;
    Some(stored != fresh)
}

/// Filter stack states by optional cluster name.
fn filter_stack_states<'st>(st: &'st state::ForgeState, cluster: Option<&str>) -> Vec<&'st StackState> {
    st.stacks
        .iter()
        .filter(|stack| cluster.is_none_or(|name| stack.cluster == name))
        .collect()
}

// -------------------------------------------------------------
// Network integration
// -------------------------------------------------------------

/// Build [`engine::NetworkParams`] when cross-cluster networking is enabled.
fn build_network_params<'env>(
    ctx: &'env ForgeContext<'_>,
    cluster: &ClusterSpec,
    st: &'env state::ForgeState,
) -> Option<engine::NetworkParams<'env>> {
    let net_cfg = ctx.config.spec.network.as_ref().filter(|net| net.cross_cluster)?;
    let idx = cluster_index(ctx, &cluster.name);
    Some(engine::NetworkParams {
        cluster_pool: state::find_cluster_pool(st, &cluster.name),
        cluster_index: idx,
        cluster_count: ctx.config.spec.clusters.len(),
        dns_zone: net_cfg.dns_zone(),
    })
}

/// Find a cluster's position in the config cluster list.
fn cluster_index(ctx: &ForgeContext<'_>, name: &str) -> usize {
    ctx.config
        .spec
        .clusters
        .iter()
        .position(|cluster| cluster.name == name)
        .unwrap_or(0)
}

/// Record a newly computed pool allocation in state.
///
/// When no network state exists yet (a cross-cluster stack applied
/// before `up` recorded the network), an active entry is initialised
/// so the computed allocation is not silently dropped: the pool was
/// derived by inspecting the live container network, which therefore
/// exists.
fn record_pool_allocation(
    st: &mut state::ForgeState,
    network_name: &str,
    cluster: &str,
    alloc: &engine::PoolAllocation,
) {
    let net = st.network.get_or_insert_with(|| state::NetworkState {
        name: network_name.to_owned(),
        phase: state::NetworkPhase::Active,
        cidr: None,
        cluster_pools: Vec::new(),
    });
    if net.cidr.as_deref() != Some(&alloc.cidr) {
        net.cidr = Some(alloc.cidr.clone());
        net.cluster_pools.clear();
    }
    if let Some(existing) = net.cluster_pools.iter_mut().find(|pool| pool.cluster == cluster) {
        alloc.range.clone_into(&mut existing.range);
    } else {
        net.cluster_pools.push(ClusterPool {
            cluster: cluster.to_owned(),
            range: alloc.range.clone(),
        });
    }
}

/// Merge captured values from a stack apply into persisted state.
fn record_captures(st: &mut state::ForgeState, cluster: &str, captures: &std::collections::BTreeMap<String, String>) {
    if captures.is_empty() {
        return;
    }
    let entry = st.captures.entry(cluster.to_owned()).or_default();
    for (key, value) in captures {
        entry.insert(key.clone(), value.clone());
    }
}

// -------------------------------------------------------------
// List rendering
// -------------------------------------------------------------

/// Render stack list as JSON.
fn render_list_json(ctx: &ForgeContext<'_>, writer: &mut dyn Write) -> Result<(), ForgeError> {
    let stacks: Vec<serde_json::Value> = ctx
        .config
        .spec
        .stacks
        .iter()
        .map(|(name, spec)| stack_list_entry(name, spec))
        .collect();
    let data = serde_json::json!({ "stacks": stacks });
    let result = output::success(data);
    output::write_json(writer, &result)?;
    Ok(())
}

/// Build a JSON entry for one stack in the list.
fn stack_list_entry(name: &str, spec: &StackSpec) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "steps": spec.steps.len(),
        "description": spec.description,
    })
}

/// Render stack list as text.
fn render_list_text(ctx: &ForgeContext<'_>, writer: &mut dyn Write) -> Result<(), ForgeError> {
    output::write_text(writer, &format!("Stacks: {}", ctx.config.spec.stacks.len()))?;
    for (name, spec) in &ctx.config.spec.stacks {
        output::write_text(writer, &format!("  - {name} ({} steps)", spec.steps.len()))?;
    }
    Ok(())
}

// -------------------------------------------------------------
// Plan rendering
// -------------------------------------------------------------

/// A stack expanded and rendered for planning.
struct PlannedStack<'plan> {
    /// Stack name.
    name: &'plan str,
    /// Rendered, for-each-expanded steps in execution order.
    steps: Vec<engine::PlannedStep>,
}

/// Expand and render each resolved stack against the same context apply uses.
///
/// State is read so cross-cluster captures and any recorded `MetalLB` pool
/// resolve; values apply computes live during this run render as placeholders.
fn plan_stacks<'plan>(
    ctx: &ForgeContext<'_>,
    cluster: &ClusterSpec,
    stacks: &[(&'plan str, &StackSpec)],
    st: &state::ForgeState,
) -> Result<Vec<PlannedStack<'plan>>, ForgeError> {
    let network = build_network_params(ctx, cluster, st);
    stacks
        .iter()
        .map(|&(name, spec)| {
            let steps = engine::plan_stack(cluster, name, spec, network.as_ref(), &st.captures)?;
            Ok(PlannedStack { name, steps })
        })
        .collect()
}

/// Render plan as JSON.
fn render_plan_json(
    cluster: &ClusterSpec,
    planned: &[PlannedStack<'_>],
    writer: &mut dyn Write,
) -> Result<(), ForgeError> {
    let entries: Vec<serde_json::Value> = planned.iter().map(|stack| plan_entry(&cluster.name, stack)).collect();
    let data = serde_json::json!({ "cluster": cluster.name, "stacks": entries });
    let result = output::success(data);
    output::write_json(writer, &result)?;
    Ok(())
}

/// Build a JSON entry for one planned stack.
fn plan_entry(cluster: &str, stack: &PlannedStack<'_>) -> serde_json::Value {
    let steps: Vec<serde_json::Value> = stack.steps.iter().map(planned_step_entry).collect();
    serde_json::json!({
        "cluster": cluster,
        "stack": stack.name,
        "steps": steps,
    })
}

/// Build a JSON entry for one planned step.
fn planned_step_entry(planned: &engine::PlannedStep) -> serde_json::Value {
    serde_json::json!({
        "type": step_type_label(&planned.step),
        "description": step_description(&planned.step),
        "warning": step_warning(&planned.step),
        "item": planned.item,
    })
}

/// Render plan as text.
fn render_plan_text(
    cluster: &ClusterSpec,
    planned: &[PlannedStack<'_>],
    writer: &mut dyn Write,
) -> Result<(), ForgeError> {
    for stack in planned {
        output::write_text(writer, &format!("Stack: {} -> {}", stack.name, cluster.name))?;
        render_planned_steps(&stack.steps, writer)?;
    }
    Ok(())
}

/// Render the expanded step list for plan text output.
fn render_planned_steps(steps_list: &[engine::PlannedStep], writer: &mut dyn Write) -> Result<(), ForgeError> {
    for (idx, planned) in steps_list.iter().enumerate() {
        let idx = idx.saturating_add(1);
        let label = step_type_label(&planned.step);
        let desc = step_description(&planned.step);
        let item = plan_item_suffix(planned.item.as_ref());
        output::write_text(writer, &format!("  {idx}. [{label}] {desc}{item}"))?;
        if let Some(warning) = step_warning(&planned.step) {
            output::write_text(writer, &format!("     WARNING: {warning}"))?;
        }
    }
    Ok(())
}

/// Format the for-each item annotation for a planned step, if any.
fn plan_item_suffix(item: Option<&serde_json::Value>) -> String {
    item.map_or_else(String::new, |val| format!(" (item {val})"))
}

// -------------------------------------------------------------
// Apply rendering
// -------------------------------------------------------------

/// Render apply results.
fn render_apply(
    cluster: &str,
    results: &[ApplyResult],
    format: &OutputFormat,
    writer: &mut dyn Write,
) -> Result<(), ForgeError> {
    match format {
        OutputFormat::Json => render_apply_json(cluster, results, writer),
        OutputFormat::Text => render_apply_text(cluster, results, writer),
    }
}

/// Render apply results as JSON.
fn render_apply_json(cluster: &str, results: &[ApplyResult], writer: &mut dyn Write) -> Result<(), ForgeError> {
    let entries: Vec<serde_json::Value> = results.iter().map(apply_entry).collect();
    let data = serde_json::json!({ "cluster": cluster, "stacks": entries });
    let result = output::success(data);
    output::write_json(writer, &result)?;
    Ok(())
}

/// Build a JSON entry for one apply result.
fn apply_entry(result: &ApplyResult) -> serde_json::Value {
    serde_json::json!({
        "name": result.name,
        "stepsExecuted": result.steps_executed,
        "success": result.success,
        "error": result.error,
    })
}

/// Render apply results as text.
fn render_apply_text(cluster: &str, results: &[ApplyResult], writer: &mut dyn Write) -> Result<(), ForgeError> {
    for result in results {
        let status = if result.success { "applied" } else { "FAILED" };
        output::write_text(
            writer,
            &format!(
                "{status} stack {} -> {cluster} ({} steps)",
                result.name, result.steps_executed
            ),
        )?;
    }
    Ok(())
}

// -------------------------------------------------------------
// Status rendering
// -------------------------------------------------------------

/// Render status as JSON.
fn render_status_json(rows: &[StatusRow<'_>], writer: &mut dyn Write) -> Result<(), ForgeError> {
    let stacks: Vec<serde_json::Value> = rows.iter().map(status_entry).collect();
    let data = serde_json::json!({ "stacks": stacks });
    let result = output::success(data);
    output::write_json(writer, &result)?;
    Ok(())
}

/// Build a JSON entry for one stack status row.
fn status_entry(row: &StatusRow<'_>) -> serde_json::Value {
    serde_json::json!({
        "name": row.entry.name,
        "cluster": row.entry.cluster,
        "phase": format!("{:?}", row.entry.phase).to_lowercase(),
        "digest": row.entry.digest,
        "timestamp": row.entry.timestamp,
        "drifted": row.drifted,
    })
}

/// Render status as text.
fn render_status_text(rows: &[StatusRow<'_>], writer: &mut dyn Write) -> Result<(), ForgeError> {
    output::write_text(writer, &format!("Stacks: {}", rows.len()))?;
    for row in rows {
        let phase = format!("{:?}", row.entry.phase).to_lowercase();
        let drift_note = if row.drifted == Some(true) { " (drifted)" } else { "" };
        output::write_text(
            writer,
            &format!("  {}/{}: {phase}{drift_note}", row.entry.cluster, row.entry.name),
        )?;
    }
    Ok(())
}

// -------------------------------------------------------------
// Step description helpers
// -------------------------------------------------------------

/// Return a short type label for a step.
fn step_type_label(step: &crate::config::StepSpec) -> &'static str {
    match step {
        crate::config::StepSpec::Url { .. } => "url",
        crate::config::StepSpec::Manifest { .. } => "manifest",
        crate::config::StepSpec::Kustomize { .. } => "kustomize",
        crate::config::StepSpec::Helm { .. } => "helm",
        crate::config::StepSpec::Deployment { .. } => "deployment",
        crate::config::StepSpec::Service { .. } => "service",
        crate::config::StepSpec::Wait { .. } => "wait",
        crate::config::StepSpec::Exec { .. } => "exec",
        crate::config::StepSpec::ForEach { .. } => "for-each",
        crate::config::StepSpec::MetallbAutoPool { .. } => "metallb-auto-pool",
        crate::config::StepSpec::CoreDnsForward { .. } => "core-dns-forward",
        crate::config::StepSpec::Capture { .. } => "capture",
        crate::config::StepSpec::TemplateManifest { .. } => "template-manifest",
        crate::config::StepSpec::TemplateFile { .. } => "template-file",
    }
}

/// Return a human-readable description for a step.
fn step_description(step: &crate::config::StepSpec) -> String {
    match step {
        crate::config::StepSpec::Url { url, .. } => format!("download {url}"),
        crate::config::StepSpec::Manifest { path } => format!("apply {path}"),
        crate::config::StepSpec::Kustomize { path } => format!("kustomize {path}"),
        crate::config::StepSpec::Helm { release, chart, .. } => format!("helm {release} ({chart})"),
        crate::config::StepSpec::Deployment { name, image, .. } => {
            format!("deploy {name} ({image})")
        },
        crate::config::StepSpec::Service { name, port, .. } => format!("service {name}:{port}"),
        crate::config::StepSpec::Wait { resource, .. } => format!("wait {resource}"),
        crate::config::StepSpec::Exec { command, .. } => command
            .first()
            .map_or_else(|| "exec <empty>".to_owned(), |prog| format!("exec {prog}")),
        crate::config::StepSpec::ForEach { property, steps } => {
            format!("for-each {property} ({} steps)", steps.len())
        },
        crate::config::StepSpec::MetallbAutoPool { name } => format!("metallb pool {name}"),
        crate::config::StepSpec::CoreDnsForward { zone, .. } => format!("coredns forward {zone}"),
        crate::config::StepSpec::Capture { key, resource, .. } => {
            format!("capture {key} from {resource}")
        },
        crate::config::StepSpec::TemplateManifest { path } => format!("template-apply {path}"),
        crate::config::StepSpec::TemplateFile { source, target } => {
            format!("template-file {source} -> {target}")
        },
    }
}

/// Return a warning for steps that deserve explicit operator attention.
fn step_warning(step: &crate::config::StepSpec) -> Option<&'static str> {
    match step {
        crate::config::StepSpec::Exec { .. } => Some("exec is an explicit command escape hatch"),
        crate::config::StepSpec::Url { .. }
        | crate::config::StepSpec::Manifest { .. }
        | crate::config::StepSpec::Kustomize { .. }
        | crate::config::StepSpec::Helm { .. }
        | crate::config::StepSpec::Deployment { .. }
        | crate::config::StepSpec::Service { .. }
        | crate::config::StepSpec::Wait { .. }
        | crate::config::StepSpec::ForEach { .. }
        | crate::config::StepSpec::MetallbAutoPool { .. }
        | crate::config::StepSpec::CoreDnsForward { .. }
        | crate::config::StepSpec::Capture { .. }
        | crate::config::StepSpec::TemplateManifest { .. }
        | crate::config::StepSpec::TemplateFile { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::config::{
        API_VERSION, EnvironmentSpec, ForgeConfig, KIND, Metadata, NetworkConfig, NodeConfig, RuntimeConfig, StepSpec,
    };

    fn test_stack() -> StackSpec {
        StackSpec {
            description: Some("Base stack".to_owned()),
            steps: vec![
                StepSpec::Manifest {
                    path: "crds.yaml".to_owned(),
                },
                StepSpec::Wait {
                    resource: "deployment/controller".to_owned(),
                    condition: "available".to_owned(),
                    timeout: "60s".to_owned(),
                    namespace: None,
                },
            ],
        }
    }

    fn test_config() -> ForgeConfig {
        ForgeConfig {
            api_version: API_VERSION.to_owned(),
            kind: KIND.to_owned(),
            metadata: Metadata {
                name: "test".to_owned(),
            },
            spec: EnvironmentSpec {
                runtime: RuntimeConfig::default(),
                network: None,
                clusters: vec![ClusterSpec {
                    name: "hub".to_owned(),
                    nodes: NodeConfig::default(),
                    ports: Vec::new(),
                    stacks: vec!["base".to_owned()],
                    properties: BTreeMap::new(),
                }],
                services: Vec::new(),
                certificates: None,
                stacks: BTreeMap::from([("base".to_owned(), test_stack())]),
            },
        }
    }

    #[test]
    fn handle_list_renders_configured_stacks() {
        let config = test_config();
        let runner = crate::command::runner::MockRunner::new();
        let ctx = ForgeContext {
            runner: &runner,
            config: &config,
            state_dir: std::path::PathBuf::from("/tmp/state"),
            config_dir: std::path::PathBuf::from("/tmp"),
            format: OutputFormat::Text,
            dry_run: false,
        };
        let mut buf = Vec::new();
        handle_list(&ctx, &mut buf).unwrap_or_else(|_| std::process::abort());
        let text = String::from_utf8_lossy(&buf);
        assert!(text.contains("Stacks: 1"), "should show stack count: {text}");
        assert!(text.contains("base (2 steps)"), "should list base stack: {text}");
    }

    #[test]
    fn handle_plan_renders_step_descriptions() {
        let config = test_config();
        let runner = crate::command::runner::MockRunner::new();
        let ctx = ForgeContext {
            runner: &runner,
            config: &config,
            state_dir: std::path::PathBuf::from("/tmp/state"),
            config_dir: std::path::PathBuf::from("/tmp"),
            format: OutputFormat::Text,
            dry_run: false,
        };
        let mut buf = Vec::new();
        handle_plan(&ctx, "hub", None, &mut buf).unwrap_or_else(|_| std::process::abort());
        let text = String::from_utf8_lossy(&buf);
        assert!(text.contains("Stack: base -> hub"), "should show stack target: {text}");
        assert!(text.contains("[manifest]"), "should describe manifest step: {text}");
        assert!(text.contains("[wait]"), "should describe wait step: {text}");
    }

    /// Build a one-step manifest stack for apply-order tests.
    fn manifest_stack(path: &str) -> StackSpec {
        StackSpec {
            description: None,
            steps: vec![StepSpec::Manifest { path: path.to_owned() }],
        }
    }

    /// Build a config whose cluster references two stacks in order.
    fn two_stack_config() -> ForgeConfig {
        let mut config = test_config();
        config.spec.stacks = BTreeMap::from([
            ("a-first".to_owned(), manifest_stack("a.yaml")),
            ("b-second".to_owned(), manifest_stack("b.yaml")),
        ]);
        if let Some(cluster) = config.spec.clusters.first_mut() {
            cluster.stacks = vec!["a-first".to_owned(), "b-second".to_owned()];
        }
        config
    }

    /// Build a runner whose docker probe succeeds and kubectl fails.
    fn failing_kubectl_runner() -> crate::command::runner::MockRunner {
        let mut runner = crate::command::runner::MockRunner::new();
        runner.respond(
            "docker",
            crate::command::runner::CommandOutput {
                status: 0,
                stdout: String::new(),
                stderr: String::new(),
            },
        );
        runner.respond(
            "kubectl",
            crate::command::runner::CommandOutput {
                status: 1,
                stdout: String::new(),
                stderr: "apply failed".to_owned(),
            },
        );
        runner
    }

    #[test]
    fn apply_stacks_stops_after_first_failed_stack() {
        let config = two_stack_config();
        let state_dir = tempfile::tempdir().unwrap_or_else(|_| std::process::abort());
        let runner = failing_kubectl_runner();
        let ctx = ForgeContext {
            runner: &runner,
            config: &config,
            state_dir: state_dir.path().to_path_buf(),
            config_dir: std::path::PathBuf::from("/tmp"),
            format: OutputFormat::Text,
            dry_run: false,
        };
        let cluster = config.spec.clusters.first().unwrap_or_else(|| std::process::abort());
        let stacks = resolve_stacks(&ctx, cluster, None).unwrap_or_else(|_| std::process::abort());
        let results = apply_stacks(&ctx, cluster, &stacks).unwrap_or_else(|_| std::process::abort());
        assert_eq!(results.len(), 1, "must stop after the failed stack");
        assert!(!runner.was_called("b.yaml"), "later stack must not be applied");
        let st = state::load(&ctx.state_dir).unwrap_or_else(|_| std::process::abort());
        assert!(
            state::find_stack(&st, "b-second", "hub").is_none(),
            "unattempted stack must not gain state"
        );
    }

    #[test]
    fn failed_apply_surfaces_the_underlying_error() {
        let results = [ApplyResult {
            name: "edge-gateway".to_owned(),
            steps_executed: 0,
            success: false,
            error: Some("deployment did not become available".to_owned()),
        }];
        let Err(error) = ensure_apply_success("east-edge", &results) else {
            std::process::abort()
        };
        let message = error.to_string();
        assert!(
            message.contains("edge-gateway"),
            "error must identify the stack: {message}"
        );
        assert!(
            message.contains("east-edge"),
            "error must identify the cluster: {message}"
        );
        assert!(
            message.contains("deployment did not become available"),
            "error must retain the step failure: {message}"
        );
    }

    #[test]
    fn failed_stack_state_is_retryable_without_manual_deletion() {
        let mut state = state::empty();
        set_stack_failed(&mut state, "edge-gateway", "east-edge", Some("old"), "first failure");
        upsert_stack_state(
            &mut state,
            "edge-gateway",
            "east-edge",
            StackPhase::Applying,
            Some("new"),
        );
        let entry = state::find_stack(&state, "edge-gateway", "east-edge").unwrap_or_else(|| std::process::abort());
        assert_eq!(entry.phase, StackPhase::Applying);
        assert_eq!(entry.digest.as_deref(), Some("new"));
        assert!(entry.error.is_none(), "retry must clear the previous failure");
    }

    /// Build an applied stack state entry for drift tests.
    fn applied_state_entry(name: &str, digest: Option<String>) -> StackState {
        StackState {
            name: name.to_owned(),
            cluster: "hub".to_owned(),
            phase: StackPhase::Applied,
            digest,
            timestamp: 0,
            error: None,
        }
    }

    #[test]
    fn stack_drifted_detects_spec_change() {
        let config = test_config();
        let runner = crate::command::runner::MockRunner::new();
        let ctx = ForgeContext {
            runner: &runner,
            config: &config,
            state_dir: std::path::PathBuf::from("/tmp/state"),
            config_dir: std::path::PathBuf::from("/tmp"),
            format: OutputFormat::Text,
            dry_run: false,
        };
        let stale = applied_state_entry("base", Some("0".repeat(64)));
        assert_eq!(stack_drifted(&ctx, &stale), Some(true), "changed spec must drift");
        let spec = config.spec.stacks.get("base").unwrap_or_else(|| std::process::abort());
        let fresh = applied_state_entry("base", stack_digest(spec).ok());
        assert_eq!(stack_drifted(&ctx, &fresh), Some(false), "matching spec must not drift");
        let unknown = applied_state_entry("base", None);
        assert_eq!(stack_drifted(&ctx, &unknown), None, "missing digest is indeterminate");
        let removed = applied_state_entry("gone", Some("0".repeat(64)));
        assert_eq!(
            stack_drifted(&ctx, &removed),
            None,
            "unconfigured stack is indeterminate"
        );
    }

    #[test]
    fn status_text_marks_drifted_stack() {
        let entry = applied_state_entry("base", Some("0".repeat(64)));
        let rows = vec![StatusRow {
            entry: &entry,
            drifted: Some(true),
        }];
        let mut buf = Vec::new();
        render_status_text(&rows, &mut buf).unwrap_or_else(|_| std::process::abort());
        let text = String::from_utf8_lossy(&buf);
        assert!(text.contains("hub/base"), "should list the stack: {text}");
        assert!(text.contains("(drifted)"), "should flag drift: {text}");
    }

    #[test]
    fn status_json_reports_drift_field() {
        let entry = applied_state_entry("base", Some("0".repeat(64)));
        let rows = vec![StatusRow {
            entry: &entry,
            drifted: Some(true),
        }];
        let mut buf = Vec::new();
        render_status_json(&rows, &mut buf).unwrap_or_else(|_| std::process::abort());
        let parsed: serde_json::Value = serde_json::from_slice(&buf).unwrap_or_else(|_| std::process::abort());
        let drifted = parsed
            .pointer("/data/stacks/0/drifted")
            .unwrap_or_else(|| std::process::abort());
        assert_eq!(drifted, &serde_json::Value::Bool(true), "JSON must expose drift");
    }

    #[test]
    fn build_network_params_returns_none_without_cross_cluster() {
        let config = test_config();
        let runner = crate::command::runner::MockRunner::new();
        let ctx = ForgeContext {
            runner: &runner,
            config: &config,
            state_dir: std::path::PathBuf::from("/tmp/state"),
            config_dir: std::path::PathBuf::from("/tmp"),
            format: OutputFormat::Text,
            dry_run: false,
        };
        let cluster = &config.spec.clusters.first().unwrap_or_else(|| std::process::abort());
        let st = state::empty();
        let result = build_network_params(&ctx, cluster, &st);
        assert!(result.is_none(), "should return None without crossCluster");
    }

    #[test]
    fn build_network_params_returns_some_with_cross_cluster() {
        let mut config = test_config();
        config.spec.network = Some(NetworkConfig {
            cross_cluster: true,
            dns_zone: None,
        });
        let runner = crate::command::runner::MockRunner::new();
        let ctx = ForgeContext {
            runner: &runner,
            config: &config,
            state_dir: std::path::PathBuf::from("/tmp/state"),
            config_dir: std::path::PathBuf::from("/tmp"),
            format: OutputFormat::Text,
            dry_run: false,
        };
        let cluster = &config.spec.clusters.first().unwrap_or_else(|| std::process::abort());
        let st = state::empty();
        let result = build_network_params(&ctx, cluster, &st);
        assert!(result.is_some(), "should return Some with crossCluster");
        let params = result.unwrap_or_else(|| std::process::abort());
        assert_eq!(params.dns_zone, "forge.test", "should default to forge.test");
        assert_eq!(params.cluster_index, 0, "hub should be index 0");
    }

    #[test]
    fn record_pool_allocation_initialises_missing_network_state() {
        let mut st = state::empty();
        let allocation = engine::PoolAllocation {
            cidr: "172.18.0.0/16".to_owned(),
            range: "172.18.255.231-172.18.255.250".to_owned(),
        };

        record_pool_allocation(&mut st, "test-net", "hub", &allocation);

        let network = st.network.as_ref().unwrap_or_else(|| std::process::abort());
        assert_eq!(network.name, "test-net", "network state must carry the network name");
        assert_eq!(network.phase, state::NetworkPhase::Active);
        assert_eq!(network.cidr.as_deref(), Some("172.18.0.0/16"));
        let pool = network.cluster_pools.first().unwrap_or_else(|| std::process::abort());
        assert_eq!(pool.cluster, "hub");
        assert_eq!(
            pool.range, allocation.range,
            "allocation must be persisted, not dropped"
        );
    }

    #[test]
    fn record_pool_allocation_replaces_stale_network_allocations() {
        let mut st = state::empty();
        st.network = Some(state::NetworkState {
            name: "test-net".to_owned(),
            phase: state::NetworkPhase::Active,
            cidr: Some("172.19.0.0/16".to_owned()),
            cluster_pools: vec![ClusterPool {
                cluster: "spoke".to_owned(),
                range: "172.19.255.211-172.19.255.230".to_owned(),
            }],
        });
        let allocation = engine::PoolAllocation {
            cidr: "172.18.0.0/16".to_owned(),
            range: "172.18.255.231-172.18.255.250".to_owned(),
        };

        record_pool_allocation(&mut st, "test-net", "hub", &allocation);

        let network = st.network.as_ref().unwrap_or_else(|| std::process::abort());
        assert_eq!(network.cidr.as_deref(), Some("172.18.0.0/16"));
        assert_eq!(network.cluster_pools.len(), 1);
        let pool = network.cluster_pools.first().unwrap_or_else(|| std::process::abort());
        assert_eq!(pool.cluster, "hub");
        assert_eq!(pool.range, allocation.range);
    }

    #[test]
    fn record_pool_allocation_updates_existing_cluster_range() {
        let mut st = state::empty();
        st.network = Some(state::NetworkState {
            name: "test-net".to_owned(),
            phase: state::NetworkPhase::Active,
            cidr: Some("172.18.0.0/16".to_owned()),
            cluster_pools: vec![ClusterPool {
                cluster: "hub".to_owned(),
                range: "172.18.255.200-172.18.255.219".to_owned(),
            }],
        });
        let allocation = engine::PoolAllocation {
            cidr: "172.18.0.0/16".to_owned(),
            range: "172.18.255.231-172.18.255.250".to_owned(),
        };

        record_pool_allocation(&mut st, "test-net", "hub", &allocation);

        let network = st.network.as_ref().unwrap_or_else(|| std::process::abort());
        assert_eq!(network.cluster_pools.len(), 1);
        let pool = network.cluster_pools.first().unwrap_or_else(|| std::process::abort());
        assert_eq!(pool.range, allocation.range);
    }

    /// Build a single-stack hub config whose base stack runs the given steps.
    fn plan_config_with_steps(steps: Vec<StepSpec>) -> ForgeConfig {
        let mut config = test_config();
        config.spec.stacks = BTreeMap::from([(
            "base".to_owned(),
            StackSpec {
                description: None,
                steps,
            },
        )]);
        config
    }

    /// Run the plan handler for the hub cluster over a fresh state dir.
    fn plan_hub(config: &ForgeConfig, format: OutputFormat) -> (Result<(), ForgeError>, Vec<u8>) {
        let runner = crate::command::runner::MockRunner::new();
        let state_dir = tempfile::tempdir().unwrap_or_else(|_| std::process::abort());
        let ctx = ForgeContext {
            runner: &runner,
            config,
            state_dir: state_dir.path().to_path_buf(),
            config_dir: std::path::PathBuf::from("/tmp"),
            format,
            dry_run: false,
        };
        let mut buf = Vec::new();
        let result = handle_plan(&ctx, "hub", None, &mut buf);
        (result, buf)
    }

    #[test]
    fn plan_expands_foreach_and_renders_templates() {
        let mut config = plan_config_with_steps(vec![StepSpec::ForEach {
            property: "workers".to_owned(),
            steps: vec![StepSpec::Manifest {
                path: "{{ item }}.yaml".to_owned(),
            }],
        }]);
        if let Some(cluster) = config.spec.clusters.first_mut() {
            cluster
                .properties
                .insert("workers".to_owned(), serde_json::json!(["w1", "w2"]));
        }
        let (result, buf) = plan_hub(&config, OutputFormat::Text);
        result.unwrap_or_else(|_| std::process::abort());
        let text = String::from_utf8_lossy(&buf);
        assert!(text.contains("apply w1.yaml"), "should render w1: {text}");
        assert!(text.contains("apply w2.yaml"), "should render w2: {text}");
        assert!(!text.contains("for-each"), "for-each must be expanded: {text}");
    }

    #[test]
    fn plan_marks_unresolved_capture_without_failing() {
        let config = plan_config_with_steps(vec![StepSpec::Manifest {
            path: "{{ cluster.name }}-{{ captures.provider.ip }}.yaml".to_owned(),
        }]);
        let (result, buf) = plan_hub(&config, OutputFormat::Text);
        result.unwrap_or_else(|_| std::process::abort());
        let text = String::from_utf8_lossy(&buf);
        assert!(
            text.contains("hub-<pending-capture:provider.ip>.yaml"),
            "placeholder: {text}"
        );
    }

    #[test]
    fn plan_surfaces_unknown_property_reference() {
        let config = plan_config_with_steps(vec![StepSpec::Manifest {
            path: "{{ cluster.properties.missing }}.yaml".to_owned(),
        }]);
        let (result, _buf) = plan_hub(&config, OutputFormat::Text);
        assert!(result.is_err(), "unknown property must surface as a plan error");
    }

    #[test]
    fn plan_surfaces_rendered_path_escape() {
        let mut config = plan_config_with_steps(vec![StepSpec::Manifest {
            path: "{{ cluster.properties.path }}".to_owned(),
        }]);
        if let Some(cluster) = config.spec.clusters.first_mut() {
            cluster
                .properties
                .insert("path".to_owned(), serde_json::json!("../escape.yaml"));
        }
        let (result, _buf) = plan_hub(&config, OutputFormat::Text);
        assert!(result.is_err(), "rendered path escape must surface as a plan error");
    }

    #[test]
    fn plan_json_renders_expanded_steps() {
        let mut config = plan_config_with_steps(vec![StepSpec::ForEach {
            property: "workers".to_owned(),
            steps: vec![StepSpec::Manifest {
                path: "{{ item }}.yaml".to_owned(),
            }],
        }]);
        if let Some(cluster) = config.spec.clusters.first_mut() {
            cluster
                .properties
                .insert("workers".to_owned(), serde_json::json!(["w1"]));
        }
        let (result, buf) = plan_hub(&config, OutputFormat::Json);
        result.unwrap_or_else(|_| std::process::abort());
        let parsed: serde_json::Value = serde_json::from_slice(&buf).unwrap_or_else(|_| std::process::abort());
        let desc = parsed
            .pointer("/data/stacks/0/steps/0/description")
            .and_then(serde_json::Value::as_str);
        assert_eq!(desc, Some("apply w1.yaml"), "JSON plan must render the expanded step");
        let item = parsed.pointer("/data/stacks/0/steps/0/item");
        assert_eq!(item, Some(&serde_json::json!("w1")), "JSON plan must record the item");
    }
}
