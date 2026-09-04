//! Cluster lifecycle management.
//!
//! Dispatches cluster subcommands to KIND-specific operations in
//! [`kind`].

pub mod kind;
pub mod kubeconfig;

use std::io::Write;

use crate::{
    cli::ClusterCommand,
    cluster::kind as kind_ops,
    command::confirm,
    context::ForgeContext,
    error::ForgeError,
    output::{self, OutputFormat},
    state::{self, ClusterPhase, ClusterState, lock},
};

/// Dispatch a cluster subcommand.
///
/// `non_interactive` (the global `--non-interactive` flag) suppresses
/// the confirmation prompt of destructive subcommands.
///
/// # Errors
///
/// Returns [`ForgeError`] if the operation fails.
pub fn dispatch(
    ctx: &ForgeContext<'_>,
    cmd: &ClusterCommand,
    non_interactive: bool,
    writer: &mut dyn Write,
) -> Result<(), ForgeError> {
    match cmd {
        ClusterCommand::Create { name } => handle_create(ctx, name, writer),
        ClusterCommand::Delete { name, force } => handle_delete(ctx, name, *force, non_interactive, writer),
        ClusterCommand::List => handle_list(ctx, writer),
        ClusterCommand::Kubeconfig { name, out_file } => handle_kubeconfig(ctx, name, out_file.as_ref(), writer),
        ClusterCommand::LoadImage { name, image } => handle_load_image(ctx, name, image, writer),
        ClusterCommand::Kubectl { name, args } => handle_kubectl(ctx, name, args, writer),
    }
}

// ---------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------

/// Handle `cluster create`.
fn handle_create(ctx: &ForgeContext<'_>, name: &str, writer: &mut dyn Write) -> Result<(), ForgeError> {
    let cluster = lookup_cluster(ctx, name)?;
    let kind_name = cluster_kind_name(ctx, name);
    if ctx.dry_run {
        return report_dry_run(writer, "would create cluster", name, &kind_name, &ctx.format);
    }
    let _lock = lock::acquire(&ctx.state_dir)?;
    let mut state = state::load(&ctx.state_dir)?;
    let created = create_if_missing(ctx, &kind_name, cluster, &mut state, name)?;
    state::save(&ctx.state_dir, &state)?;
    if created {
        report_created(writer, name, &kind_name, &ctx.format)
    } else {
        report_exists(writer, name, &kind_name, &ctx.format)
    }
}

/// Handle `cluster delete`.
///
/// The KIND name is derived from the config prefix, so this command can
/// name a KIND cluster Forge never created. A KIND cluster carries no
/// Forge ownership label to check the way a network or container does
/// (`io.x-k8s.kind.cluster` proves only that it is a KIND cluster, not
/// who created it, and `kind create` offers no hook to attach one), so
/// Forge state is the ownership record: a cluster absent from state is
/// refused unless `force` is set, keeping this command from destroying
/// an unrelated same-named cluster.
///
/// On an interactive terminal the delete then asks for confirmation
/// unless `force` or `non_interactive` is set; non-TTY invocations never
/// prompt. A tracked cluster is marked `Deleting` (and saved) before the
/// delete runs, so a crash mid-delete leaves a diagnosable record
/// instead of an entry still claiming `Running`.
fn handle_delete(
    ctx: &ForgeContext<'_>,
    name: &str,
    force: bool,
    non_interactive: bool,
    writer: &mut dyn Write,
) -> Result<(), ForgeError> {
    let kind_name = cluster_kind_name(ctx, name);
    if ctx.dry_run {
        return report_dry_run(writer, "would delete cluster", name, &kind_name, &ctx.format);
    }
    if !force && state::find_cluster(&state::load(&ctx.state_dir)?, name).is_none() {
        return Err(untracked_cluster_error(name, &kind_name));
    }
    if !confirm::confirm_destructive(&format!("delete cluster '{name}'"), force || non_interactive)? {
        return confirm::report_declined(writer, &ctx.format);
    }
    let _lock = lock::acquire(&ctx.state_dir)?;
    let mut st = state::load(&ctx.state_dir)?;
    set_phase_saved(ctx, &mut st, name, ClusterPhase::Deleting)?;
    kind_ops::delete_cluster(ctx.runner, &kind_name)?;
    set_phase_saved(ctx, &mut st, name, ClusterPhase::Gone)?;
    report_deleted(writer, name, &kind_name, &ctx.format)
}

/// Handle `cluster list`.
fn handle_list(ctx: &ForgeContext<'_>, writer: &mut dyn Write) -> Result<(), ForgeError> {
    let clusters = kind_ops::list_clusters(ctx.runner)?;
    render_list(writer, &clusters, &ctx.format)
}

/// Handle `cluster kubeconfig`.
fn handle_kubeconfig(
    ctx: &ForgeContext<'_>,
    name: &str,
    output_path: Option<&std::path::PathBuf>,
    writer: &mut dyn Write,
) -> Result<(), ForgeError> {
    let kind_name = cluster_kind_name(ctx, name);
    // Fetching the kubeconfig is read-only, but writing the out-file is
    // not: a dry run must never truncate an existing kubeconfig.
    if ctx.dry_run
        && let Some(path) = output_path
    {
        let msg = format!("would write kubeconfig for '{name}' to {}", path.display());
        return report_text_or_json(writer, &msg, &ctx.format);
    }
    let kubeconfig = kind_ops::get_kubeconfig(ctx.runner, &kind_name)?;
    write_kubeconfig(writer, output_path, &kubeconfig, &ctx.format)
}

/// Handle `cluster load-image`.
fn handle_load_image(
    ctx: &ForgeContext<'_>,
    name: &str,
    image: &str,
    writer: &mut dyn Write,
) -> Result<(), ForgeError> {
    let kind_name = cluster_kind_name(ctx, name);
    if ctx.dry_run {
        return report_dry_run(writer, "would load image into cluster", name, &kind_name, &ctx.format);
    }
    kind_ops::load_image(ctx.runner, &kind_name, image)?;
    report_image_loaded(writer, name, image, &ctx.format)
}

/// Handle `cluster kubectl`.
fn handle_kubectl(
    ctx: &ForgeContext<'_>,
    name: &str,
    args: &[String],
    writer: &mut dyn Write,
) -> Result<(), ForgeError> {
    let kind_name = cluster_kind_name(ctx, name);
    // kubectl can mutate the cluster (apply/delete/patch/scale/...), so a
    // dry run must report the planned invocation without executing it.
    if ctx.dry_run {
        let msg = format!(
            "would run kubectl against cluster '{name}' (kind name: {kind_name}): {}",
            args.join(" ")
        );
        return report_text_or_json(writer, &msg, &ctx.format);
    }
    let result = kind_ops::run_kubectl(ctx.runner, &kind_name, args)?;
    report_kubectl_result(writer, &result, &ctx.format)
}

// ---------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------

/// Look up a cluster in the config by name.
fn lookup_cluster<'cfg>(
    ctx: &'cfg ForgeContext<'_>,
    name: &str,
) -> Result<&'cfg crate::config::ClusterSpec, ForgeError> {
    ctx.config
        .spec
        .clusters
        .iter()
        .find(|cl| cl.name == name)
        .ok_or_else(|| ForgeError::Config(format!("cluster '{name}' not found in config")))
}

/// Build the KIND cluster name from config prefix and cluster name.
fn cluster_kind_name(ctx: &ForgeContext<'_>, name: &str) -> String {
    kind_ops::kind_cluster_name(&ctx.config.spec.runtime.cluster_prefix, name)
}

/// Create a cluster if it doesn't already exist. Returns true if created.
///
/// A cluster that already exists in KIND is adopted into state as
/// `Running` so bulk teardown (`forge down`) still tracks it. Before a
/// real create, a `Creating` entry is persisted: creation takes
/// minutes, and a crash mid-create would otherwise leave real KIND
/// containers with no state record.
///
/// The caller must hold the state lock: this saves state, and
/// [`state::save`] requires the lock against concurrent forge
/// processes.
fn create_if_missing(
    ctx: &ForgeContext<'_>,
    kind_name: &str,
    cluster: &crate::config::ClusterSpec,
    st: &mut state::ForgeState,
    name: &str,
) -> Result<bool, ForgeError> {
    if kind_ops::cluster_exists(ctx.runner, kind_name)? {
        upsert_cluster_state(st, name, kind_name, ClusterPhase::Running);
        return Ok(false);
    }
    upsert_cluster_state(st, name, kind_name, ClusterPhase::Creating);
    state::save(&ctx.state_dir, st)?;
    let config = kind_ops::CreateClusterConfig {
        nodes: &cluster.nodes,
        ports: &cluster.ports,
        config_dir: &ctx.state_dir,
        docker_network: None,
    };
    kind_ops::create_cluster(ctx.runner, kind_name, &config)?;
    upsert_cluster_state(st, name, kind_name, ClusterPhase::Running);
    Ok(true)
}

/// Insert or update a cluster's state entry.
///
/// An existing entry also has its `kind_name` and `context` refreshed
/// so a `clusterPrefix` change cannot leave state pointing at a KIND
/// cluster that no longer matches the one just created.
fn upsert_cluster_state(st: &mut state::ForgeState, name: &str, kind_name: &str, phase: ClusterPhase) {
    if let Some(cs) = state::find_cluster_mut(st, name) {
        cs.phase = phase;
        if cs.kind_name != kind_name {
            kind_name.clone_into(&mut cs.kind_name);
            cs.context = kind_ops::kubectl_context(kind_name);
        }
        return;
    }
    st.clusters.push(ClusterState {
        name: name.to_owned(),
        kind_name: kind_name.to_owned(),
        context: kind_ops::kubectl_context(kind_name),
        phase,
    });
}

/// Set a tracked cluster's phase in state and persist it.
///
/// A cluster with no state entry (deleted purely by its derived KIND
/// name) is left unrecorded; nothing is saved for it.
///
/// The caller must hold the state lock: this saves state, and
/// [`state::save`] requires the lock against concurrent forge
/// processes.
fn set_phase_saved(
    ctx: &ForgeContext<'_>,
    st: &mut state::ForgeState,
    name: &str,
    phase: ClusterPhase,
) -> Result<(), ForgeError> {
    let Some(cs) = state::find_cluster_mut(st, name) else {
        return Ok(());
    };
    cs.phase = phase;
    state::save(&ctx.state_dir, st)
}

/// Report a kubectl invocation's output, propagating its exit status.
///
/// On success, stdout is written as text or wrapped in the JSON
/// envelope. On failure, any stdout is still written in text mode
/// (kubectl may have printed partial diagnostics) and the non-zero
/// exit surfaces as [`ForgeError::Command`] carrying kubectl's
/// stderr, so scripts gating on Forge's exit code see the failure.
fn report_kubectl_result(
    writer: &mut dyn Write,
    result: &crate::command::runner::CommandOutput,
    format: &OutputFormat,
) -> Result<(), ForgeError> {
    match format {
        OutputFormat::Json => {
            if result.status == 0 {
                let envelope = output::success(serde_json::json!({ "stdout": result.stdout }));
                output::write_json(writer, &envelope)?;
            }
        },
        OutputFormat::Text => {
            if !result.stdout.is_empty() {
                output::write_text(writer, &result.stdout)?;
            }
        },
    }
    if result.status != 0 {
        return Err(ForgeError::Command {
            program: "kubectl".to_owned(),
            message: format!("exit code {}: {}", result.status, result.stderr.trim()),
        });
    }
    Ok(())
}

/// Write kubeconfig to file or writer.
fn write_kubeconfig(
    writer: &mut dyn Write,
    output_path: Option<&std::path::PathBuf>,
    kubeconfig: &str,
    format: &OutputFormat,
) -> Result<(), ForgeError> {
    if let Some(path) = output_path {
        // The kubeconfig grants cluster-admin, so it must be 0600 rather
        // than inheriting the umask (0644 by default).
        kubeconfig::write_owner_only(path, kubeconfig)?;
        return report_text_or_json(writer, &format!("kubeconfig written to {}", path.display()), format);
    }
    output::write_text(writer, kubeconfig)?;
    Ok(())
}

/// Build the refusal for deleting a cluster Forge does not track.
///
/// State is Forge's ownership record for clusters, so a delete targets
/// only what Forge created or adopted. `--force` overrides for the
/// recovery case where state was lost but the cluster really is Forge's.
fn untracked_cluster_error(name: &str, kind_name: &str) -> ForgeError {
    ForgeError::State(format!(
        "cluster '{name}' (kind name: {kind_name}) is not tracked in Forge state; \
         refusing to delete a cluster Forge may not manage (use --force to override)"
    ))
}

// ---------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------

/// Report a dry-run action.
fn report_dry_run(
    writer: &mut dyn Write,
    action: &str,
    name: &str,
    kind_name: &str,
    format: &OutputFormat,
) -> Result<(), ForgeError> {
    let msg = format!("{action} '{name}' (kind name: {kind_name})");
    report_text_or_json(writer, &msg, format)
}

/// Report a created cluster.
fn report_created(
    writer: &mut dyn Write,
    name: &str,
    kind_name: &str,
    format: &OutputFormat,
) -> Result<(), ForgeError> {
    let msg = format!("created cluster '{name}' (kind name: {kind_name})");
    report_text_or_json(writer, &msg, format)
}

/// Report a cluster that already existed and was adopted into state.
fn report_exists(writer: &mut dyn Write, name: &str, kind_name: &str, format: &OutputFormat) -> Result<(), ForgeError> {
    let msg = format!("cluster '{name}' already exists (kind name: {kind_name})");
    report_text_or_json(writer, &msg, format)
}

/// Report a deleted cluster.
fn report_deleted(
    writer: &mut dyn Write,
    name: &str,
    kind_name: &str,
    format: &OutputFormat,
) -> Result<(), ForgeError> {
    let msg = format!("deleted cluster '{name}' (kind name: {kind_name})");
    report_text_or_json(writer, &msg, format)
}

/// Report an image loaded.
fn report_image_loaded(
    writer: &mut dyn Write,
    name: &str,
    image: &str,
    format: &OutputFormat,
) -> Result<(), ForgeError> {
    let msg = format!("loaded image '{image}' into cluster '{name}'");
    report_text_or_json(writer, &msg, format)
}

/// Render a cluster list.
fn render_list(writer: &mut dyn Write, clusters: &[String], format: &OutputFormat) -> Result<(), ForgeError> {
    match format {
        OutputFormat::Json => {
            let envelope = output::success(serde_json::json!({ "clusters": clusters }));
            output::write_json(writer, &envelope)?;
        },
        OutputFormat::Text => {
            for name in clusters {
                output::write_text(writer, name)?;
            }
        },
    }
    Ok(())
}

/// Write a message as text or JSON envelope.
fn report_text_or_json(writer: &mut dyn Write, message: &str, format: &OutputFormat) -> Result<(), ForgeError> {
    match format {
        OutputFormat::Json => {
            let envelope = output::success(serde_json::json!({ "message": message }));
            output::write_json(writer, &envelope)?;
        },
        OutputFormat::Text => {
            output::write_text(writer, message)?;
        },
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::runner::{CommandOutput, MockRunner};

    /// Build a minimal `ForgeConfig` with one cluster named `hub`.
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

    /// Build a context over the given runner, config, and state dir.
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

    /// Build a successful command output with the given stdout.
    fn stdout_ok(stdout: &str) -> CommandOutput {
        CommandOutput {
            status: 0,
            stdout: stdout.to_owned(),
            stderr: String::new(),
        }
    }

    /// Dispatch a command and return the captured output text.
    fn run_dispatch(ctx: &ForgeContext<'_>, cmd: &ClusterCommand) -> String {
        let mut buf = Vec::new();
        dispatch(ctx, cmd, false, &mut buf).unwrap_or_else(|_| std::process::abort());
        String::from_utf8_lossy(&buf).into_owned()
    }

    #[test]
    fn create_adopts_existing_cluster_into_state() {
        let dir = test_dir();
        let config = test_config();
        let mut runner = MockRunner::new();
        runner.respond("kind get clusters", stdout_ok("forge-hub\n"));
        let ctx = test_ctx(&runner, &config, &dir);

        let text = run_dispatch(&ctx, &ClusterCommand::Create { name: "hub".to_owned() });

        assert!(!runner.was_called("kind create"), "should not call kind create");
        assert!(text.contains("already exists"), "output should note existing: {text}");
        let st = state::load(dir.path()).unwrap_or_else(|_| std::process::abort());
        let cluster = state::find_cluster(&st, "hub");
        assert!(cluster.is_some(), "existing cluster should be adopted into state");
        assert_eq!(
            cluster.map(|cs| cs.phase.clone()),
            Some(ClusterPhase::Running),
            "adopted cluster should be Running"
        );
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

    #[test]
    fn create_persists_creating_phase_when_create_fails() {
        let dir = test_dir();
        let config = test_config();
        let mut runner = MockRunner::new();
        runner.respond("kind get clusters", stdout_ok(""));
        runner.respond(
            "kind",
            CommandOutput {
                status: 1,
                stdout: String::new(),
                stderr: "create blew up\n".to_owned(),
            },
        );
        let ctx = test_ctx(&runner, &config, &dir);

        let mut buf = Vec::new();
        let result = dispatch(
            &ctx,
            &ClusterCommand::Create { name: "hub".to_owned() },
            false,
            &mut buf,
        );

        assert!(result.is_err(), "a failing create should fail the command");
        let st = state::load(dir.path()).unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            state::find_cluster(&st, "hub").map(|cs| cs.phase.clone()),
            Some(ClusterPhase::Creating),
            "an interrupted create must leave a Creating record for down"
        );
    }

    #[test]
    fn delete_persists_deleting_phase_when_delete_fails() {
        let dir = test_dir();
        seed_running_hub(dir.path());
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
        let result = dispatch(
            &ctx,
            &ClusterCommand::Delete {
                name: "hub".to_owned(),
                force: false,
            },
            false,
            &mut buf,
        );

        assert!(result.is_err(), "a failing delete should fail the command");
        let st = state::load(dir.path()).unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            state::find_cluster(&st, "hub").map(|cs| cs.phase.clone()),
            Some(ClusterPhase::Deleting),
            "an interrupted delete must leave a Deleting record"
        );
    }

    #[test]
    fn kubectl_failure_surfaces_stderr_and_errors() {
        let dir = test_dir();
        let config = test_config();
        let mut runner = MockRunner::new();
        runner.respond(
            "kubectl",
            CommandOutput {
                status: 1,
                stdout: "partial output\n".to_owned(),
                stderr: "Error from server (NotFound): namespaces \"missing-ns\" not found\n".to_owned(),
            },
        );
        let ctx = test_ctx(&runner, &config, &dir);
        let cmd = ClusterCommand::Kubectl {
            name: "hub".to_owned(),
            args: vec!["get".to_owned(), "pods".to_owned()],
        };

        let mut buf = Vec::new();
        let err = match dispatch(&ctx, &cmd, false, &mut buf) {
            Ok(()) => std::process::abort(),
            Err(err) => err,
        };
        let msg = err.to_string();
        assert!(msg.contains("kubectl"), "error should name kubectl: {msg}");
        assert!(msg.contains("exit code 1"), "error should carry exit code: {msg}");
        assert!(msg.contains("NotFound"), "error should carry kubectl stderr: {msg}");
        let text = String::from_utf8_lossy(&buf);
        assert!(
            text.contains("partial output"),
            "stdout should still be written: {text}"
        );
    }

    #[test]
    fn kubectl_success_json_uses_envelope() {
        let dir = test_dir();
        let config = test_config();
        let mut runner = MockRunner::new();
        runner.respond("kubectl", stdout_ok("pod-a\n"));
        let mut ctx = test_ctx(&runner, &config, &dir);
        ctx.format = OutputFormat::Json;
        let cmd = ClusterCommand::Kubectl {
            name: "hub".to_owned(),
            args: vec!["get".to_owned(), "pods".to_owned()],
        };

        let text = run_dispatch(&ctx, &cmd);
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap_or_else(|_| {
            std::process::abort();
            #[expect(unreachable_code, reason = "abort prevents reaching this")]
            {
                serde_json::Value::Null
            }
        });
        assert_eq!(
            parsed.get("status").and_then(|val| val.as_str()),
            Some("Success"),
            "JSON output should be a success envelope: {text}"
        );
        assert_eq!(
            parsed.pointer("/data/stdout").and_then(|val| val.as_str()),
            Some("pod-a\n"),
            "envelope should carry kubectl stdout: {text}"
        );
    }

    #[test]
    fn kubeconfig_out_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = test_dir();
        let config = test_config();
        let mut runner = MockRunner::new();
        runner.respond("kind get kubeconfig --name forge-hub", stdout_ok("apiVersion: v1\n"));
        let ctx = test_ctx(&runner, &config, &dir);
        let out_path = dir.path().join("hub.kubeconfig");
        let cmd = ClusterCommand::Kubeconfig {
            name: "hub".to_owned(),
            out_file: Some(out_path.clone()),
        };

        let text = run_dispatch(&ctx, &cmd);

        assert!(
            text.contains("kubeconfig written to"),
            "should report the write: {text}"
        );
        let content = std::fs::read_to_string(&out_path).unwrap_or_else(|_| std::process::abort());
        assert_eq!(content, "apiVersion: v1\n", "out-file should carry the kubeconfig");
        let mode = std::fs::metadata(&out_path)
            .unwrap_or_else(|_| std::process::abort())
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "out-file carries admin credentials and must be 0600");
    }

    #[test]
    fn kubeconfig_dry_run_does_not_touch_out_file() {
        let dir = test_dir();
        let config = test_config();
        let runner = MockRunner::new();
        let mut ctx = test_ctx(&runner, &config, &dir);
        ctx.dry_run = true;
        let out_path = dir.path().join("existing.kubeconfig");
        std::fs::write(&out_path, "original content\n").unwrap_or_else(|_| std::process::abort());
        let cmd = ClusterCommand::Kubeconfig {
            name: "hub".to_owned(),
            out_file: Some(out_path.clone()),
        };

        let text = run_dispatch(&ctx, &cmd);

        assert!(
            text.contains("would write kubeconfig"),
            "should report planned write: {text}"
        );
        let content = std::fs::read_to_string(&out_path).unwrap_or_else(|_| std::process::abort());
        assert_eq!(content, "original content\n", "dry run must not overwrite the out-file");
    }

    #[test]
    fn kubectl_dry_run_does_not_execute() {
        let dir = test_dir();
        let config = test_config();
        let runner = MockRunner::new();
        let mut ctx = test_ctx(&runner, &config, &dir);
        ctx.dry_run = true;
        let cmd = ClusterCommand::Kubectl {
            name: "hub".to_owned(),
            args: vec!["apply".to_owned(), "-f".to_owned(), "manifest.yaml".to_owned()],
        };

        let text = run_dispatch(&ctx, &cmd);

        assert_eq!(runner.call_count(), 0, "dry run must not execute kubectl");
        assert!(
            text.contains("would run kubectl against cluster 'hub'"),
            "should report the planned invocation: {text}"
        );
        assert!(
            text.contains("apply -f manifest.yaml"),
            "should echo the kubectl args: {text}"
        );
    }

    #[test]
    fn kubectl_dry_run_json_reports_plan_without_executing() {
        let dir = test_dir();
        let config = test_config();
        let runner = MockRunner::new();
        let mut ctx = test_ctx(&runner, &config, &dir);
        ctx.dry_run = true;
        ctx.format = OutputFormat::Json;
        let cmd = ClusterCommand::Kubectl {
            name: "hub".to_owned(),
            args: vec!["delete".to_owned(), "ns".to_owned(), "prod".to_owned()],
        };

        let text = run_dispatch(&ctx, &cmd);

        assert_eq!(runner.call_count(), 0, "dry run must not execute kubectl");
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap_or_else(|_| {
            std::process::abort();
            #[expect(unreachable_code, reason = "abort prevents reaching this")]
            {
                serde_json::Value::Null
            }
        });
        let msg = parsed
            .pointer("/data/message")
            .and_then(|val| val.as_str())
            .unwrap_or_default();
        let status = parsed.get("status").and_then(|val| val.as_str());
        assert_eq!(status, Some("Success"), "success envelope");
        assert!(msg.contains("would run kubectl against cluster 'hub'"), "plan: {text}");
        assert!(msg.contains("delete ns prod"), "args: {text}");
    }

    #[test]
    fn create_reports_created_for_new_cluster() {
        let dir = test_dir();
        let config = test_config();
        let mut runner = MockRunner::new();
        runner.respond("kind get clusters", stdout_ok(""));
        runner.respond("kind", stdout_ok(""));
        let ctx = test_ctx(&runner, &config, &dir);

        let text = run_dispatch(&ctx, &ClusterCommand::Create { name: "hub".to_owned() });

        assert!(runner.was_called("kind create cluster"), "should call kind create");
        assert!(
            text.contains("created cluster 'hub'"),
            "output should say created: {text}"
        );
    }

    #[test]
    fn delete_refuses_untracked_cluster_without_force() {
        let dir = test_dir();
        let config = test_config();
        let runner = MockRunner::new();
        let ctx = test_ctx(&runner, &config, &dir);

        let mut buf = Vec::new();
        let result = dispatch(
            &ctx,
            &ClusterCommand::Delete {
                name: "hub".to_owned(),
                force: false,
            },
            false,
            &mut buf,
        );

        let err = match result {
            Ok(()) => std::process::abort(),
            Err(err) => err,
        };
        let msg = err.to_string();
        assert!(
            msg.contains("not tracked"),
            "should explain the cluster is untracked: {msg}"
        );
        assert!(msg.contains("--force"), "should point at the override: {msg}");
        assert!(
            !runner.was_called("kind delete"),
            "an untracked cluster must not be deleted"
        );
    }

    #[test]
    fn delete_forces_untracked_cluster_when_forced() {
        let dir = test_dir();
        let config = test_config();
        let mut runner = MockRunner::new();
        runner.respond("kind", stdout_ok(""));
        let ctx = test_ctx(&runner, &config, &dir);

        let text = run_dispatch(
            &ctx,
            &ClusterCommand::Delete {
                name: "hub".to_owned(),
                force: true,
            },
        );

        assert!(
            runner.was_called("kind delete cluster"),
            "--force must delete an untracked cluster"
        );
        assert!(
            text.contains("deleted cluster 'hub'"),
            "should report the delete: {text}"
        );
    }

    #[test]
    fn delete_removes_tracked_cluster_without_force() {
        let dir = test_dir();
        seed_running_hub(dir.path());
        let config = test_config();
        let mut runner = MockRunner::new();
        runner.respond("kind", stdout_ok(""));
        let ctx = test_ctx(&runner, &config, &dir);

        let text = run_dispatch(
            &ctx,
            &ClusterCommand::Delete {
                name: "hub".to_owned(),
                force: false,
            },
        );

        assert!(
            runner.was_called("kind delete cluster"),
            "a tracked cluster deletes without --force"
        );
        assert!(
            text.contains("deleted cluster 'hub'"),
            "should report the delete: {text}"
        );
        let st = state::load(dir.path()).unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            state::find_cluster(&st, "hub").map(|cs| cs.phase.clone()),
            Some(ClusterPhase::Gone),
            "a deleted tracked cluster must be recorded Gone"
        );
    }
}
