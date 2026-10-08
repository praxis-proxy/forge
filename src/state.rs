//! Persistent state for Forge environments.
//!
//! State is stored as JSON in `<state_dir>/state.json`.  All writes
//! are atomic: write to a temporary file, fsync, then rename.
//! Atomicity protects against crashes, not against concurrent forge
//! processes: mutating callers must hold the state lock (see
//! [`lock::acquire`] and the [`save`] docs).

pub mod lock;

use std::{
    collections::BTreeMap,
    io::Write as _,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use sha2::Digest as _;

use crate::{config::ForgeConfig, error::ForgeError};

/// Schema version for state files.
const STATE_API_VERSION: &str = "forge.praxis.dev/state/v1alpha1";

/// State file name within the state directory.
const STATE_FILE: &str = "state.json";

/// Temporary state file name for atomic writes.
const STATE_TMP: &str = "state.json.tmp";

/// File mode for the state file: owner read/write only.
const STATE_FILE_MODE: u32 = 0o600;

/// Directory mode for the state directory: owner-only.
const STATE_DIR_MODE: u32 = 0o700;

// ---------------------------------------------------------------
// Types
// ---------------------------------------------------------------

/// Root state object persisted to `state.json`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ForgeState {
    /// Schema version for the state file.
    pub api_version: String,
    /// Managed cluster states.
    #[serde(default)]
    pub clusters: Vec<ClusterState>,
    /// Managed service states.
    #[serde(default)]
    pub services: Vec<ServiceState>,
    /// Managed stack application states.
    #[serde(default)]
    pub stacks: Vec<StackState>,
    /// Managed container network state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkState>,
    /// Whether this state owns the tracked network creation.
    /// Missing historical provenance never authorizes network removal.
    #[serde(default)]
    pub network_created_by_forge: bool,
    /// Runtime identity returned when the tracked network was created.
    /// Legacy state without this identity never authorizes network deletion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_id: Option<String>,
    /// Correlation label persisted before a network creation attempt.
    /// It permits interrupted identity lookup to recover only that attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_creation_token: Option<String>,
    /// Detected container runtime name, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
    /// SHA-256 digest of the config that produced this state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_digest: Option<String>,
    /// Description of the last mutation operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_operation: Option<LastOperation>,
    /// Values captured from stack steps, keyed by cluster then key.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub captures: BTreeMap<String, BTreeMap<String, String>>,
}

/// State of one managed KIND cluster.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ClusterState {
    /// Cluster name from the Forge config (not the KIND name).
    pub name: String,
    /// Full KIND cluster name (prefix + "-" + name).
    pub kind_name: String,
    /// kubectl context name ("kind-" + `kind_name`).
    pub context: String,
    /// Current lifecycle phase.
    pub phase: ClusterPhase,
}

/// Lifecycle phases for a managed cluster.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ClusterPhase {
    /// Cluster creation is pending. Reserved: accepted in state files
    /// but not currently written by any command.
    Pending,
    /// Cluster is being created. Persisted before `kind create` runs
    /// so a crash mid-create leaves a record for `forge down`.
    Creating,
    /// Cluster is running.
    Running,
    /// Cluster is being deleted. Persisted before `kind delete` runs.
    Deleting,
    /// Cluster has been deleted or failed.
    Gone,
}

/// State of the managed container network.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NetworkState {
    /// Network name (e.g. `"{env_name}-net"`).
    pub name: String,
    /// Current lifecycle phase.
    pub phase: NetworkPhase,
    /// Discovered network CIDR (e.g. `"172.18.0.0/16"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cidr: Option<String>,
    /// Per-cluster `MetalLB` pool allocations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cluster_pools: Vec<ClusterPool>,
}

/// Lifecycle phases for a managed network.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkPhase {
    /// Network is active and available.
    Active,
    /// Network has been removed.
    Gone,
}

/// A per-cluster `MetalLB` IP address pool allocation.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ClusterPool {
    /// Cluster name this pool belongs to.
    pub cluster: String,
    /// Allocated address range (e.g. `"172.18.255.231-172.18.255.250"`).
    pub range: String,
}

/// State of one managed container service.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ServiceState {
    /// Service name from the Forge config.
    pub name: String,
    /// Deterministic container name.
    pub container_name: String,
    /// Container image reference.
    pub image: String,
    /// Current lifecycle phase.
    pub phase: ServicePhase,
    /// Health observation.
    pub health: ServiceHealth,
    /// Unix epoch seconds when the service was last observed.
    pub last_observed: u64,
}

/// Lifecycle phases for a managed service.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ServicePhase {
    /// Container creation pending. Reserved: accepted in state files
    /// but not currently written by any command.
    Pending,
    /// Container starting. Reserved: accepted in state files but not
    /// currently written by any command.
    Starting,
    /// Container running normally.
    Running,
    /// Health check failed.
    Unhealthy,
    /// Container stopped.
    Stopped,
    /// Container removed.
    Gone,
}

/// Health observation for a managed service.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceHealth {
    /// No health check configured or not yet probed.
    Unknown,
    /// Last health check succeeded.
    Healthy,
    /// Last health check failed.
    Unhealthy,
}

/// State of one stack application to a cluster.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct StackState {
    /// Stack name from the Forge config.
    pub name: String,
    /// Cluster this stack was applied to.
    pub cluster: String,
    /// Current lifecycle phase.
    pub phase: StackPhase,
    /// SHA-256 digest of the stack spec at last apply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    /// Unix epoch seconds of last state change.
    pub timestamp: u64,
    /// Error message if phase is `Failed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Lifecycle phases for a managed stack application.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum StackPhase {
    /// Stack application is pending. Reserved: accepted in state files
    /// but not currently written by any command.
    Pending,
    /// Stack is being applied.
    Applying,
    /// Stack has been successfully applied.
    Applied,
    /// Stack application failed.
    Failed,
}

/// Record of the last mutation.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LastOperation {
    /// Operation name (e.g. "cluster.create", "up", "down").
    pub operation: String,
    /// Unix epoch seconds when the operation started.
    pub timestamp: u64,
    /// Whether the operation succeeded.
    pub success: bool,
}

// ---------------------------------------------------------------
// Construction
// ---------------------------------------------------------------

/// Build a default empty state.
pub fn empty() -> ForgeState {
    ForgeState {
        api_version: STATE_API_VERSION.to_owned(),
        clusters: Vec::new(),
        services: Vec::new(),
        stacks: Vec::new(),
        network: None,
        network_created_by_forge: false,
        network_id: None,
        network_creation_token: None,
        runtime: None,
        config_digest: None,
        last_operation: None,
        captures: BTreeMap::new(),
    }
}

// ---------------------------------------------------------------
// Load / Save
// ---------------------------------------------------------------

/// Load state from the state directory.
///
/// Returns an empty state if the file does not exist.
///
/// # Errors
///
/// Returns [`ForgeError::State`] if the file cannot be read for any
/// reason other than not existing, or cannot be parsed. Only a true
/// `NotFound` maps to an empty state: a `Path::exists()` pre-check
/// would also swallow permission errors, symlink loops, and dangling
/// symlinks as "fresh environment", and race the file's presence.
pub fn load(state_dir: &Path) -> Result<ForgeState, ForgeError> {
    let path = state_path(state_dir);
    match std::fs::read_to_string(&path) {
        Ok(content) => parse_state(&content, &path),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(empty()),
        Err(err) => Err(ForgeError::State(format!("cannot read {}: {err}", path.display()))),
    }
}

/// Save state atomically: write temp, fsync, rename.
///
/// Callers must hold the state lock ([`lock::acquire`]) whenever
/// another forge process could be running: every save goes through
/// the single fixed temp path `state.json.tmp`, so two unlocked
/// concurrent saves interleave their writes and rename torn JSON
/// into place. This holds transitively: a helper that load-modify-
/// saves (e.g. `set_phase_saved` in `cluster.rs`) inherits the
/// requirement even when the lock was taken frames above it.
///
/// # Errors
///
/// Returns [`ForgeError::State`] if any step fails.
pub fn save(state_dir: &Path, state: &ForgeState) -> Result<(), ForgeError> {
    ensure_dir(state_dir)?;
    let tmp = write_temp(state_dir, state)?;
    fsync_path(&tmp)?;
    rename_state(&tmp, &state_path(state_dir))?;
    // The rename itself lives in the directory entry: without syncing
    // the directory a power loss can roll the rename back, leaving
    // state.json describing clusters and containers that no longer
    // match reality.
    fsync_path(state_dir)
}

/// Ensure the state directory exists.
///
/// # Errors
///
/// Returns [`ForgeError::State`] if directory creation fails.
pub fn ensure_dir(state_dir: &Path) -> Result<(), ForgeError> {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::create_dir_all(state_dir)
        .map_err(|err| ForgeError::State(format!("cannot create state dir {}: {err}", state_dir.display())))?;
    // The directory also holds exported kubeconfigs under runtime/kubeconfig.
    std::fs::set_permissions(state_dir, std::fs::Permissions::from_mode(STATE_DIR_MODE))
        .map_err(|err| ForgeError::State(format!("cannot set mode on state dir {}: {err}", state_dir.display())))
}

// ---------------------------------------------------------------
// Lookups
// ---------------------------------------------------------------

/// Find a cluster in state by config name.
pub fn find_cluster<'st>(state: &'st ForgeState, name: &str) -> Option<&'st ClusterState> {
    state.clusters.iter().find(|cluster| cluster.name == name)
}

/// Find a cluster in state by config name (mutable).
pub fn find_cluster_mut<'st>(state: &'st mut ForgeState, name: &str) -> Option<&'st mut ClusterState> {
    state.clusters.iter_mut().find(|cluster| cluster.name == name)
}

/// Find a service in state by config name.
pub fn find_service<'st>(state: &'st ForgeState, name: &str) -> Option<&'st ServiceState> {
    state.services.iter().find(|svc| svc.name == name)
}

/// Find a service in state by config name (mutable).
pub fn find_service_mut<'st>(state: &'st mut ForgeState, name: &str) -> Option<&'st mut ServiceState> {
    state.services.iter_mut().find(|svc| svc.name == name)
}

/// Find a stack in state by name and cluster.
pub fn find_stack<'st>(state: &'st ForgeState, name: &str, cluster: &str) -> Option<&'st StackState> {
    state
        .stacks
        .iter()
        .find(|stack| stack.name == name && stack.cluster == cluster)
}

/// Find a stack in state by name and cluster (mutable).
pub fn find_stack_mut<'st>(state: &'st mut ForgeState, name: &str, cluster: &str) -> Option<&'st mut StackState> {
    state
        .stacks
        .iter_mut()
        .find(|stack| stack.name == name && stack.cluster == cluster)
}

/// Find a cluster's `MetalLB` pool allocation in network state.
pub fn find_cluster_pool<'st>(state: &'st ForgeState, cluster: &str) -> Option<&'st str> {
    state
        .network
        .as_ref()
        .and_then(|net| net.cluster_pools.iter().find(|pool| pool.cluster == cluster))
        .map(|pool| pool.range.as_str())
}

// ---------------------------------------------------------------
// Config digest
// ---------------------------------------------------------------

/// Compute a SHA-256 hex digest of the config for change detection.
///
/// Serializes the config to canonical JSON, then hashes the bytes.
///
/// # Errors
///
/// Returns [`ForgeError::State`] if serialization fails.
pub fn config_digest(config: &ForgeConfig) -> Result<String, ForgeError> {
    let json = serde_json::to_string(config)
        .map_err(|err| ForgeError::State(format!("cannot serialize config for digest: {err}")))?;
    let hash = sha2::Sha256::digest(json.as_bytes());
    Ok(format!("{hash:x}"))
}

// ---------------------------------------------------------------
// Timestamps
// ---------------------------------------------------------------

/// Return the current Unix epoch seconds.
pub fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ---------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------

/// Build the path to the state file.
fn state_path(state_dir: &Path) -> PathBuf {
    state_dir.join(STATE_FILE)
}

/// Parse state file content, checking the schema version first.
fn parse_state(content: &str, path: &Path) -> Result<ForgeState, ForgeError> {
    check_api_version(content, path)?;
    serde_json::from_str(content)
        .map_err(|err| ForgeError::State(format!("corrupt state file {}: {err}", path.display())))
}

/// Permissive probe for the state file's schema version.
///
/// Unlike [`ForgeState`], this struct tolerates unknown fields so a
/// file written by any other forge version can still report which
/// version produced it instead of surfacing as corruption.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VersionProbe {
    /// Schema version declared by the file, if present.
    #[serde(default)]
    api_version: Option<String>,
}

/// Reject a state file written under a different schema version.
///
/// A file whose `apiVersion` differs from [`STATE_API_VERSION`] gets a
/// dedicated error naming both versions, so version skew (e.g. an
/// older binary reading a newer file) is not misreported as a corrupt
/// file. A file with no `apiVersion` at all falls through to the
/// strict parse, which reports the missing field.
fn check_api_version(content: &str, path: &Path) -> Result<(), ForgeError> {
    let probe: VersionProbe = serde_json::from_str(content)
        .map_err(|err| ForgeError::State(format!("corrupt state file {}: {err}", path.display())))?;
    if let Some(found) = probe.api_version
        && found != STATE_API_VERSION
    {
        return Err(ForgeError::State(format!(
            "state file {} was written by a different forge version: found apiVersion \
             \"{found}\", this forge supports \"{STATE_API_VERSION}\"",
            path.display()
        )));
    }
    Ok(())
}

/// Write state to a temporary file in the state directory.
fn write_temp(state_dir: &Path, state: &ForgeState) -> Result<PathBuf, ForgeError> {
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    let tmp = state_dir.join(STATE_TMP);
    let json = serde_json::to_string_pretty(state)
        .map_err(|err| ForgeError::State(format!("cannot serialize state: {err}")))?;
    // Captures hold values read straight out of cluster objects, so the file is
    // created 0600 rather than inheriting the umask.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(STATE_FILE_MODE)
        .open(&tmp)
        .map_err(|err| ForgeError::State(format!("cannot create {}: {err}", tmp.display())))?;
    // `mode` above applies only when the file is created. A tmp file left by a
    // killed run keeps its old mode through truncate, and rename would carry
    // that mode onto the state file, so set it on the open handle too.
    file.set_permissions(std::fs::Permissions::from_mode(STATE_FILE_MODE))
        .map_err(|err| ForgeError::State(format!("cannot set mode on {}: {err}", tmp.display())))?;
    file.write_all(json.as_bytes())
        .map_err(|err| ForgeError::State(format!("cannot write {}: {err}", tmp.display())))?;
    Ok(tmp)
}

/// Fsync a file or directory by path.
fn fsync_path(path: &Path) -> Result<(), ForgeError> {
    let file = std::fs::File::open(path)
        .map_err(|err| ForgeError::State(format!("cannot open for fsync {}: {err}", path.display())))?;
    file.sync_all()
        .map_err(|err| ForgeError::State(format!("fsync failed for {}: {err}", path.display())))
}

/// Atomic rename from temp to final path.
fn rename_state(tmp: &Path, final_path: &Path) -> Result<(), ForgeError> {
    std::fs::rename(tmp, final_path).map_err(|err| {
        ForgeError::State(format!(
            "cannot rename {} to {}: {err}",
            tmp.display(),
            final_path.display()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_writes_owner_only_state_file_and_dir() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap_or_else(|_| {
            std::process::abort();
            #[expect(unreachable_code, reason = "abort prevents reaching this")]
            {
                unreachable!()
            }
        });
        let state_dir = dir.path().join("state");
        save(&state_dir, &empty()).unwrap_or_else(|_| std::process::abort());

        let file_mode = std::fs::metadata(state_path(&state_dir))
            .unwrap_or_else(|_| std::process::abort())
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            file_mode, STATE_FILE_MODE,
            "state file must not be group- or world-readable"
        );

        let dir_mode = std::fs::metadata(&state_dir)
            .unwrap_or_else(|_| std::process::abort())
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            dir_mode, STATE_DIR_MODE,
            "state dir must not be group- or world-readable"
        );
    }

    #[test]
    fn stale_tmp_does_not_leak_its_mode_onto_state_file() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap_or_else(|_| std::process::abort());
        let state_dir = dir.path().join("state");
        ensure_dir(&state_dir).unwrap_or_else(|_| std::process::abort());
        // A tmp file left behind by a killed run, with the old world-readable mode.
        let stale = state_dir.join(STATE_TMP);
        std::fs::write(&stale, b"stale").unwrap_or_else(|_| std::process::abort());
        std::fs::set_permissions(&stale, std::fs::Permissions::from_mode(0o644))
            .unwrap_or_else(|_| std::process::abort());

        save(&state_dir, &empty()).unwrap_or_else(|_| std::process::abort());

        let mode = std::fs::metadata(state_path(&state_dir))
            .unwrap_or_else(|_| std::process::abort())
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, STATE_FILE_MODE,
            "a reused tmp file must not carry its old mode onto the state file"
        );
    }

    #[test]
    fn empty_state_has_correct_api_version() {
        let state = empty();
        assert_eq!(state.api_version, STATE_API_VERSION, "api_version mismatch");
    }

    #[test]
    fn empty_state_round_trips_through_json() {
        let state = empty();
        let json = serde_json::to_string(&state).unwrap_or_else(|_| std::process::abort());
        let parsed: ForgeState = serde_json::from_str(&json).unwrap_or_else(|_| {
            std::process::abort();
            #[expect(unreachable_code, reason = "abort prevents reaching this")]
            {
                unreachable!()
            }
        });
        assert_eq!(parsed.api_version, STATE_API_VERSION, "round-trip api_version mismatch");
        assert!(parsed.clusters.is_empty(), "should have no clusters");
    }

    #[test]
    fn load_missing_returns_empty() {
        let dir = tempfile::tempdir().unwrap_or_else(|_| {
            std::process::abort();
            #[expect(unreachable_code, reason = "abort prevents reaching this")]
            {
                unreachable!()
            }
        });
        let state = load(dir.path()).unwrap_or_else(|_| {
            std::process::abort();
            #[expect(unreachable_code, reason = "abort prevents reaching this")]
            {
                unreachable!()
            }
        });
        assert!(state.clusters.is_empty(), "missing file should yield empty state");
    }

    #[test]
    fn load_symlink_loop_is_an_error_not_empty() {
        let dir = tempfile::tempdir().unwrap_or_else(|_| std::process::abort());
        let path = dir.path().join(STATE_FILE);
        // A self-referential symlink: stat fails with ELOOP, so the old
        // Path::exists() gate read this as "no state" and returned a
        // fresh environment instead of an error.
        std::os::unix::fs::symlink(&path, &path).unwrap_or_else(|_| std::process::abort());
        let err = load(dir.path()).err().unwrap_or_else(|| std::process::abort());
        assert!(
            err.to_string().contains("cannot read"),
            "an unreadable state file must not read as a fresh environment: {err}"
        );
    }

    #[test]
    fn load_rejects_state_from_different_version() {
        let dir = tempfile::tempdir().unwrap_or_else(|_| std::process::abort());
        let path = dir.path().join(STATE_FILE);
        std::fs::write(&path, r#"{"apiVersion":"forge.praxis.dev/state/v9","newField":true}"#)
            .unwrap_or_else(|_| std::process::abort());
        let err = load(dir.path()).err().unwrap_or_else(|| std::process::abort());
        let msg = err.to_string();
        assert!(
            msg.contains("different forge version"),
            "version skew should not be reported as corruption: {msg}"
        );
        assert!(
            msg.contains("forge.praxis.dev/state/v9"),
            "error should name the file's version: {msg}"
        );
        assert!(
            msg.contains(STATE_API_VERSION),
            "error should name the supported version: {msg}"
        );
    }

    #[test]
    fn load_same_version_with_unknown_field_reports_corrupt() {
        let dir = tempfile::tempdir().unwrap_or_else(|_| std::process::abort());
        let path = dir.path().join(STATE_FILE);
        let content = format!(r#"{{"apiVersion":"{STATE_API_VERSION}","unknownField":1}}"#);
        std::fs::write(&path, content).unwrap_or_else(|_| std::process::abort());
        let err = load(dir.path()).err().unwrap_or_else(|| std::process::abort());
        let msg = err.to_string();
        assert!(
            msg.contains("corrupt state file"),
            "same-version unknown field should stay a corruption error: {msg}"
        );
    }

    #[test]
    fn save_and_load_round_trip() {
        let dir = tempfile::tempdir().unwrap_or_else(|_| {
            std::process::abort();
            #[expect(unreachable_code, reason = "abort prevents reaching this")]
            {
                unreachable!()
            }
        });
        let mut state = empty();
        state.clusters.push(ClusterState {
            name: "hub".to_owned(),
            kind_name: "forge-hub".to_owned(),
            context: "kind-forge-hub".to_owned(),
            phase: ClusterPhase::Running,
        });
        save(dir.path(), &state).unwrap_or_else(|_| std::process::abort());
        let loaded = load(dir.path()).unwrap_or_else(|_| {
            std::process::abort();
            #[expect(unreachable_code, reason = "abort prevents reaching this")]
            {
                unreachable!()
            }
        });
        assert_eq!(loaded.clusters.len(), 1, "should have one cluster");
        assert_eq!(
            loaded.clusters.first().map(|cluster| cluster.name.as_str()),
            Some("hub"),
            "cluster name mismatch"
        );
    }

    #[test]
    fn config_digest_produces_hex_string() {
        let yaml = crate::config::minimal_yaml();
        let dir = tempfile::tempdir().unwrap_or_else(|_| {
            std::process::abort();
            #[expect(unreachable_code, reason = "abort prevents reaching this")]
            {
                unreachable!()
            }
        });
        let path = dir.path().join("forge.yaml");
        std::fs::write(&path, &yaml).unwrap_or_else(|_| std::process::abort());
        let cfg = crate::config::load(&path).unwrap_or_else(|_| {
            std::process::abort();
            #[expect(unreachable_code, reason = "abort prevents reaching this")]
            {
                unreachable!()
            }
        });
        let digest = config_digest(&cfg).unwrap_or_else(|_| {
            std::process::abort();
            #[expect(unreachable_code, reason = "abort prevents reaching this")]
            {
                unreachable!()
            }
        });
        assert_eq!(digest.len(), 64, "SHA-256 hex should be 64 chars, got {}", digest.len());
        assert!(
            digest.chars().all(|ch| ch.is_ascii_hexdigit()),
            "digest should be hex: {digest}"
        );
    }

    #[test]
    fn find_cluster_returns_match() {
        let mut state = empty();
        state.clusters.push(ClusterState {
            name: "hub".to_owned(),
            kind_name: "forge-hub".to_owned(),
            context: "kind-forge-hub".to_owned(),
            phase: ClusterPhase::Running,
        });
        assert!(find_cluster(&state, "hub").is_some(), "should find hub");
        assert!(find_cluster(&state, "missing").is_none(), "should not find missing");
    }

    #[test]
    fn find_cluster_mut_allows_mutation() {
        let mut state = empty();
        state.clusters.push(ClusterState {
            name: "hub".to_owned(),
            kind_name: "forge-hub".to_owned(),
            context: "kind-forge-hub".to_owned(),
            phase: ClusterPhase::Pending,
        });
        if let Some(cluster) = find_cluster_mut(&mut state, "hub") {
            cluster.phase = ClusterPhase::Running;
        }
        assert_eq!(
            find_cluster(&state, "hub").map(|cluster| &cluster.phase),
            Some(&ClusterPhase::Running),
            "phase should be updated"
        );
    }

    #[test]
    fn stack_state_round_trips_through_json() {
        let mut state = empty();
        state.stacks.push(StackState {
            name: "base".to_owned(),
            cluster: "hub".to_owned(),
            phase: StackPhase::Applied,
            digest: Some("abc123".to_owned()),
            timestamp: 1_700_000_000,
            error: None,
        });
        let json = serde_json::to_string(&state).unwrap_or_else(|_| std::process::abort());
        let parsed: ForgeState = serde_json::from_str(&json).unwrap_or_else(|_| {
            std::process::abort();
            #[expect(unreachable_code, reason = "abort prevents reaching this")]
            {
                unreachable!()
            }
        });
        assert_eq!(parsed.stacks.len(), 1, "should have one stack");
        assert_eq!(
            parsed.stacks.first().map(|stack| stack.name.as_str()),
            Some("base"),
            "stack name mismatch"
        );
    }

    #[test]
    fn find_stack_returns_match() {
        let mut state = empty();
        state.stacks.push(make_stack_state("base", "hub"));
        assert!(find_stack(&state, "base", "hub").is_some(), "should find base/hub");
        assert!(find_stack(&state, "base", "missing").is_none(), "wrong cluster");
        assert!(find_stack(&state, "missing", "hub").is_none(), "wrong name");
    }

    #[test]
    fn find_stack_mut_allows_mutation() {
        let mut state = empty();
        state.stacks.push(make_stack_state("base", "hub"));
        if let Some(stack) = find_stack_mut(&mut state, "base", "hub") {
            stack.phase = StackPhase::Applied;
        }
        assert_eq!(
            find_stack(&state, "base", "hub").map(|stack| &stack.phase),
            Some(&StackPhase::Applied),
            "phase should be updated"
        );
    }

    #[test]
    fn cluster_pool_roundtrip() {
        let pool = ClusterPool {
            cluster: "hub".to_owned(),
            range: "172.18.255.231-172.18.255.250".to_owned(),
        };
        let json = serde_json::to_string(&pool).unwrap_or_else(|_| std::process::abort());
        let back: ClusterPool = serde_json::from_str(&json).unwrap_or_else(|_| std::process::abort());
        assert_eq!(back.cluster, "hub", "cluster name should survive roundtrip");
        assert_eq!(back.range, pool.range, "range should survive roundtrip");
    }

    #[test]
    fn network_state_with_pools_roundtrip() {
        let ns = NetworkState {
            name: "test-net".to_owned(),
            phase: NetworkPhase::Active,
            cidr: Some("172.18.0.0/16".to_owned()),
            cluster_pools: vec![
                ClusterPool {
                    cluster: "hub".to_owned(),
                    range: "172.18.255.231-172.18.255.250".to_owned(),
                },
                ClusterPool {
                    cluster: "spoke".to_owned(),
                    range: "172.18.255.211-172.18.255.230".to_owned(),
                },
            ],
        };
        let json = serde_json::to_string(&ns).unwrap_or_else(|_| std::process::abort());
        let back: NetworkState = serde_json::from_str(&json).unwrap_or_else(|_| std::process::abort());
        assert_eq!(back.cluster_pools.len(), 2, "both pools should roundtrip");
        assert_eq!(back.cidr.as_deref(), Some("172.18.0.0/16"), "cidr should roundtrip");
    }

    #[test]
    fn find_cluster_pool_returns_range() {
        let mut state = empty();
        state.network = Some(NetworkState {
            name: "test-net".to_owned(),
            phase: NetworkPhase::Active,
            cidr: Some("172.18.0.0/16".to_owned()),
            cluster_pools: vec![ClusterPool {
                cluster: "hub".to_owned(),
                range: "172.18.255.231-172.18.255.250".to_owned(),
            }],
        });
        assert_eq!(
            find_cluster_pool(&state, "hub"),
            Some("172.18.255.231-172.18.255.250"),
            "should find hub pool"
        );
        assert_eq!(
            find_cluster_pool(&state, "spoke"),
            None,
            "should return None for unknown"
        );
    }

    // Test Utilities

    /// Build a minimal [`StackState`] for testing.
    fn make_stack_state(name: &str, cluster: &str) -> StackState {
        StackState {
            name: name.to_owned(),
            cluster: cluster.to_owned(),
            phase: StackPhase::Pending,
            digest: None,
            timestamp: 0,
            error: None,
        }
    }

    #[test]
    fn grid_state_preserves_network_creation_provenance() -> Result<(), serde_json::Error> {
        let mut document = serde_json::to_value(empty())?;
        let fields = document.as_object_mut().unwrap_or_else(|| std::process::abort());
        fields.insert("networkCreatedByForge".to_owned(), serde_json::json!(true));
        let state: ForgeState = serde_json::from_value(document)?;
        assert!(
            state.network_created_by_forge,
            "Grid's persisted ownership must survive migration"
        );
        let encoded = serde_json::to_value(state)?;
        assert_eq!(
            encoded.get("networkCreatedByForge"),
            Some(&serde_json::json!(true)),
            "ownership must round trip"
        );
        Ok(())
    }

    #[test]
    fn historical_state_without_provenance_does_not_authorize_network_deletion() -> Result<(), serde_json::Error> {
        let mut document = serde_json::to_value(empty())?;
        let fields = document.as_object_mut().unwrap_or_else(|| std::process::abort());
        fields.remove("networkCreatedByForge");
        let state: ForgeState = serde_json::from_value(document)?;
        assert!(
            !state.network_created_by_forge,
            "absent historical ownership must be conservative"
        );
        Ok(())
    }
}
