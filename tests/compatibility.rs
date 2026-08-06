//! Compatibility tests for representative Forge configurations.
//!
//! Validates that configurations derived from Grid and MaaS/IPP demo
//! topologies load, validate, and produce correct plans from the
//! standalone Forge binary — without requiring a Grid checkout.

#![allow(
    clippy::tests_outside_test_module,
    reason = "integration tests live in tests/"
)]

use std::path::Path;

use forge::config;

// ---------------------------------------------------------------
// Fixture loader
// ---------------------------------------------------------------

/// Load and validate a fixture by name, returning the parsed config.
fn load_fixture(name: &str) -> config::ForgeConfig {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(name);
    assert!(
        path.exists(),
        "fixture {name} not found at {}",
        path.display()
    );
    let cfg = config::load(&path).unwrap_or_else(|_| {
        std::process::abort();
        #[expect(unreachable_code, reason = "abort prevents reaching this")]
        {
            unreachable!()
        }
    });
    config::validate::validate(&cfg).unwrap_or_else(|_| {
        std::process::abort();
        #[expect(unreachable_code, reason = "abort prevents reaching this")]
        {
            unreachable!()
        }
    });
    cfg
}

// ---------------------------------------------------------------
// GLB demo topology
// ---------------------------------------------------------------

#[test]
fn glb_demo_validates() {
    let cfg = load_fixture("tests/fixtures/glb-demo.yaml");
    assert_eq!(cfg.metadata.name, "glb-demo", "metadata.name mismatch");
    assert_eq!(cfg.spec.clusters.len(), 4, "should have 4 clusters");
    assert_eq!(cfg.spec.stacks.len(), 3, "should have 3 stacks");
    assert!(
        cfg.spec.network.as_ref().is_some_and(|n| n.cross_cluster),
        "should enable crossCluster"
    );
}

#[test]
fn glb_demo_cluster_properties_accessible() {
    let cfg = load_fixture("tests/fixtures/glb-demo.yaml");
    for cluster in &cfg.spec.clusters {
        assert!(
            cluster.properties.contains_key("region"),
            "cluster {} must have region property",
            cluster.name
        );
        assert!(
            cluster.properties.contains_key("role"),
            "cluster {} must have role property",
            cluster.name
        );
    }
}

// ---------------------------------------------------------------
// Combined-site topology
// ---------------------------------------------------------------

#[test]
fn combined_site_validates() {
    let cfg = load_fixture("tests/fixtures/combined-site.yaml");
    assert_eq!(cfg.metadata.name, "combined-site", "metadata.name mismatch");
    assert_eq!(cfg.spec.clusters.len(), 3, "should have 3 clusters");
    assert_eq!(cfg.spec.stacks.len(), 4, "should have 4 stacks");
}

#[test]
fn combined_site_all_clusters_reference_valid_stacks() {
    let cfg = load_fixture("tests/fixtures/combined-site.yaml");
    for cluster in &cfg.spec.clusters {
        for stack_name in &cluster.stacks {
            assert!(
                cfg.spec.stacks.contains_key(stack_name),
                "cluster {} references unknown stack {stack_name}",
                cluster.name
            );
        }
    }
}

// ---------------------------------------------------------------
// llm-d pool metrics topology
// ---------------------------------------------------------------

#[test]
fn llmd_pool_metrics_validates() {
    let cfg = load_fixture("tests/fixtures/llmd-pool-metrics.yaml");
    assert_eq!(
        cfg.metadata.name, "llmd-pool-metrics",
        "metadata.name mismatch"
    );
    assert_eq!(cfg.spec.clusters.len(), 2, "should have 2 clusters");
    assert_eq!(cfg.spec.stacks.len(), 5, "should have 5 stacks");
}

#[test]
fn llmd_pool_metrics_clusters_have_pool_name() {
    let cfg = load_fixture("tests/fixtures/llmd-pool-metrics.yaml");
    for cluster in &cfg.spec.clusters {
        assert!(
            cluster.properties.contains_key("poolName"),
            "cluster {} must have poolName property",
            cluster.name
        );
    }
}

// ---------------------------------------------------------------
// MaaS/IPP single-cluster topology
// ---------------------------------------------------------------

#[test]
fn maas_ipp_validates() {
    let cfg = load_fixture("tests/fixtures/maas-ipp.yaml");
    assert_eq!(cfg.metadata.name, "maas-ipp", "metadata.name mismatch");
    assert_eq!(cfg.spec.clusters.len(), 1, "should have 1 cluster");
    assert!(
        cfg.spec.network.as_ref().is_some_and(|n| !n.cross_cluster),
        "should not enable crossCluster"
    );
}

#[test]
fn maas_ipp_cluster_has_version_properties() {
    let cfg = load_fixture("tests/fixtures/maas-ipp.yaml");
    let cluster = cfg
        .spec
        .clusters
        .first()
        .unwrap_or_else(|| std::process::abort());
    for key in [
        "metallbVersion",
        "metallbSha256",
        "gatewayApiVersion",
        "gieVersion",
    ] {
        assert!(
            cluster.properties.contains_key(key),
            "cluster must have {key} property"
        );
    }
}

// ---------------------------------------------------------------
// Minimal fixture
// ---------------------------------------------------------------

#[test]
fn minimal_validates() {
    let cfg = load_fixture("examples/minimal.yaml");
    assert_eq!(cfg.metadata.name, "minimal", "metadata.name mismatch");
    assert!(
        cfg.spec.clusters.is_empty(),
        "minimal should have no clusters"
    );
    assert!(cfg.spec.stacks.is_empty(), "minimal should have no stacks");
}

// ---------------------------------------------------------------
// Schema version enforcement
// ---------------------------------------------------------------

#[test]
fn incompatible_api_version_rejected() {
    let dir = tempfile::tempdir().unwrap_or_else(|_| std::process::abort());
    let path = dir.path().join("forge.yaml");
    std::fs::write(
        &path,
        "apiVersion: forge.praxis.dev/v2beta1\nkind: Environment\nmetadata:\n  name: test\nspec:\n  clusters: []\n  stacks: {}\n",
    )
    .unwrap_or_else(|_| std::process::abort());
    let result = config::load(&path).and_then(|cfg| config::validate::validate(&cfg));
    assert!(
        result.is_err(),
        "incompatible apiVersion should be rejected"
    );
}

#[test]
fn wrong_kind_rejected() {
    let dir = tempfile::tempdir().unwrap_or_else(|_| std::process::abort());
    let path = dir.path().join("forge.yaml");
    std::fs::write(
        &path,
        "apiVersion: forge.praxis.dev/v1alpha1\nkind: Cluster\nmetadata:\n  name: test\nspec:\n  clusters: []\n  stacks: {}\n",
    )
    .unwrap_or_else(|_| std::process::abort());
    let result = config::load(&path).and_then(|cfg| config::validate::validate(&cfg));
    assert!(result.is_err(), "wrong kind should be rejected");
}
