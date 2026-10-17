//! Shared execution context for Forge commands.
//!
//! [`ForgeContext`] bundles the command runner, parsed configuration,
//! and global options into a single value so command handlers stay
//! under the five-argument limit.

use std::path::PathBuf;

use crate::{
    cluster::kind::{self, KindProvider},
    command::runner::CommandRunner,
    config::ForgeConfig,
    error::ForgeError,
    output::OutputFormat,
    runtime,
    state::ForgeState,
};

/// Shared execution context for a single command invocation.
///
/// Constructed in `main.rs` after parsing CLI arguments and loading
/// the configuration.  Command handlers receive `&ForgeContext`
/// instead of five separate parameters.
pub struct ForgeContext<'env> {
    /// Command runner (real or mock).
    pub runner: &'env dyn CommandRunner,
    /// Parsed and validated Forge configuration.
    pub config: &'env ForgeConfig,
    /// Directory for state files and locks.
    pub state_dir: PathBuf,
    /// Directory containing the config file (for resolving relative paths).
    pub config_dir: PathBuf,
    /// Output format (text or JSON).
    pub format: OutputFormat,
    /// If true, skip all mutating operations.
    pub dry_run: bool,
}

impl ForgeContext<'_> {
    /// The provider kind must use: from the runtime recorded in state, else a fresh resolve.
    ///
    /// # Errors
    ///
    /// Returns [`ForgeError`] if the runtime cannot be resolved or detected.
    pub fn kind_provider(&self, st: &ForgeState) -> Result<KindProvider, ForgeError> {
        let binary =
            runtime::recorded_or_resolved(self.runner, &self.config.spec.runtime.provider, st.runtime.as_deref())?;
        kind::provider_for(self.runner, &binary)
    }
}
