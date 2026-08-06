//! Path-independence smoke tests.
//!
//! Verifies that:
//! - `--config /absolute/path config validate` works from a foreign directory;
//! - `.forge` state paths are deterministic and relative to `--state-dir`;
//! - no Grid checkout or specific working directory is required.

#![allow(
    clippy::tests_outside_test_module,
    reason = "integration tests live in tests/"
)]

use std::path::Path;

// ---------------------------------------------------------------
// Binary resolution
// ---------------------------------------------------------------

/// Resolve the praxis-forge binary built by this workspace.
fn forge_binary() -> std::path::PathBuf {
    let bin = Path::new(env!("CARGO_BIN_EXE_praxis-forge"));
    assert!(
        bin.exists(),
        "praxis-forge binary not found at {}",
        bin.display()
    );
    bin.to_path_buf()
}

/// Absolute path to the fixtures directory.
fn fixtures_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

// ---------------------------------------------------------------
// Path-independence tests
// ---------------------------------------------------------------

#[test]
fn validate_with_absolute_path_from_foreign_directory() {
    let config_path = fixtures_dir().join("glb-demo.yaml");
    let output = std::process::Command::new(forge_binary())
        .arg("--config")
        .arg(&config_path)
        .arg("config")
        .arg("validate")
        .current_dir(std::env::temp_dir())
        .output()
        .unwrap_or_else(|_| std::process::abort());
    assert!(
        output.status.success(),
        "validate should succeed from foreign directory: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn validate_all_fixtures_with_absolute_paths() {
    for fixture in [
        "glb-demo.yaml",
        "combined-site.yaml",
        "llmd-pool-metrics.yaml",
        "maas-ipp.yaml",
    ] {
        let config_path = fixtures_dir().join(fixture);
        let output = std::process::Command::new(forge_binary())
            .arg("--config")
            .arg(&config_path)
            .arg("config")
            .arg("validate")
            .current_dir(std::env::temp_dir())
            .output()
            .unwrap_or_else(|_| std::process::abort());
        assert!(
            output.status.success(),
            "{fixture}: validate should succeed with absolute path: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn config_show_works_from_foreign_directory() {
    let config_path = fixtures_dir().join("maas-ipp.yaml");
    let output = std::process::Command::new(forge_binary())
        .arg("--config")
        .arg(&config_path)
        .arg("config")
        .arg("show")
        .current_dir(std::env::temp_dir())
        .output()
        .unwrap_or_else(|_| std::process::abort());
    assert!(
        output.status.success(),
        "config show should succeed from foreign directory: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("maas-ipp"),
        "output should contain environment name: {stdout}"
    );
}

#[test]
fn config_schema_works_without_config_file() {
    let output = std::process::Command::new(forge_binary())
        .arg("config")
        .arg("schema")
        .current_dir(std::env::temp_dir())
        .output()
        .unwrap_or_else(|_| std::process::abort());
    assert!(
        output.status.success(),
        "config schema should work without any config file: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("ForgeConfig"),
        "schema output should contain ForgeConfig: {stdout}"
    );
}

#[test]
fn version_flag_prints_version() {
    let output = std::process::Command::new(forge_binary())
        .arg("--version")
        .current_dir(std::env::temp_dir())
        .output()
        .unwrap_or_else(|_| std::process::abort());
    assert!(
        output.status.success(),
        "--version should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("praxis-forge"),
        "--version should print praxis-forge: {stdout}"
    );
}

#[test]
fn state_dir_flag_is_deterministic() {
    let dir = tempfile::tempdir().unwrap_or_else(|_| std::process::abort());
    let state_dir = dir.path().join("custom-state");
    let config_path = fixtures_dir().join("glb-demo.yaml");
    let output = std::process::Command::new(forge_binary())
        .arg("--config")
        .arg(&config_path)
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("--output")
        .arg("json")
        .arg("status")
        .current_dir(std::env::temp_dir())
        .output()
        .unwrap_or_else(|_| std::process::abort());
    assert!(
        output.status.success(),
        "status with custom state-dir should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn doctor_runs_from_foreign_directory() {
    let config_path = fixtures_dir().join("glb-demo.yaml");
    let output = std::process::Command::new(forge_binary())
        .arg("--config")
        .arg(&config_path)
        .arg("doctor")
        .current_dir(std::env::temp_dir())
        .output()
        .unwrap_or_else(|_| std::process::abort());
    assert!(
        output.status.success(),
        "doctor should succeed from foreign directory: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn config_init_dry_run_from_foreign_directory() {
    let output = std::process::Command::new(forge_binary())
        .arg("config")
        .arg("init")
        .arg("--dry-run")
        .current_dir(std::env::temp_dir())
        .output()
        .unwrap_or_else(|_| std::process::abort());
    assert!(
        output.status.success(),
        "config init --dry-run should succeed from foreign directory: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn invalid_config_returns_nonzero_exit_code() {
    let dir = tempfile::tempdir().unwrap_or_else(|_| std::process::abort());
    let bad_config = dir.path().join("bad.yaml");
    std::fs::write(&bad_config, "apiVersion: wrong/v1\nkind: Wrong\n")
        .unwrap_or_else(|_| std::process::abort());
    let output = std::process::Command::new(forge_binary())
        .arg("--config")
        .arg(&bad_config)
        .arg("config")
        .arg("validate")
        .current_dir(std::env::temp_dir())
        .output()
        .unwrap_or_else(|_| std::process::abort());
    assert!(
        !output.status.success(),
        "invalid config should return nonzero exit code"
    );
}
