# Praxis Forge

Declarative development-environment orchestrator for KIND clusters, container
services, and deployment stacks.

Forge reads a single `forge.yaml` file and brings up reproducible local
environments: Docker/Podman networks, KIND clusters, host-level container
services, and multi-step deployment stacks (kubectl, Helm, kustomize,
templates, and exec steps). It is a synchronous CLI with no async runtime.

Forge is **project-neutral**. It does not contain Grid routing/scoring/SWIM
assertions, Grid operator deployment semantics, Grid-specific overlay
assertions, Grid-specific topology orchestration, or MaaS/IPP-specific
runtime assertions. Those belong in consumer repositories that define their
own `forge.yaml` configurations.

## Installation

### From source (pinned)

Requires Rust 1.96 or later.

```sh
cargo install --locked --git https://github.com/praxis-proxy/forge --tag v0.1.1
```

### From a release binary

Download the appropriate binary from the
[Releases](https://github.com/praxis-proxy/forge/releases) page, verify the
checksum, and place it on your `PATH`:

```sh
# Example for Linux x86_64:
curl -fsSL https://github.com/praxis-proxy/forge/releases/download/v0.1.1/praxis-forge-x86_64-unknown-linux-gnu.tar.gz -o forge.tar.gz
curl -fsSL https://github.com/praxis-proxy/forge/releases/download/v0.1.1/SHA256SUMS -o SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
tar xzf forge.tar.gz
sudo install praxis-forge /usr/local/bin/
```

### Build from checkout

```sh
git clone https://github.com/praxis-proxy/forge.git
cd forge
cargo build --release
./target/release/praxis-forge --version
```

## CLI commands

```
praxis-forge [OPTIONS] <COMMAND>

Commands:
  doctor    Check availability of required external tools
  plan      Show what the environment would look like
  config    Configuration management (validate, show, init, schema)
  up        Bring up all clusters, services, and stacks
  down      Tear down all clusters, services, and the network
  status    Show the status of the environment
  apply     Apply stacks to a cluster (alias for `stack apply`)
  cluster   Individual cluster lifecycle (create, delete, list, kubeconfig, load-image, kubectl)
  service   Host-level container services (list, start, stop, logs)
  stack     Deployment stack management (list, plan, apply, status)

Global options:
  --config <PATH>         Path to forge.yaml [env: FORGE_CONFIG] [default: forge.yaml]
  --state-dir <PATH>      State directory [env: FORGE_STATE_DIR] [default: .forge]
  --runtime <RUNTIME>     Override container runtime (docker, podman, auto)
  --output <FORMAT>       Output format (text, json) [default: text]
  --dry-run               Show what would happen without making changes
  --non-interactive       Suppress interactive prompts
```

## Configuration

Forge uses a single YAML configuration file with a versioned schema:

```yaml
apiVersion: forge.praxis.dev/v1alpha1
kind: Environment

metadata:
  name: my-environment

spec:
  runtime:
    provider: auto          # auto | docker | podman
    clusterPrefix: forge    # KIND cluster name prefix

  network:
    crossCluster: false     # enable cross-cluster Docker networking
    dnsZone: forge.test     # DNS zone for cross-cluster discovery

  clusters:
    - name: hub
      stacks: [base]
      properties: {}

  services: []

  stacks:
    base:
      description: Base stack
      steps:
        - type: manifest
          path: manifests/crds.yaml
```

### Asset resolution

All relative paths in the configuration resolve from the **directory
containing the `forge.yaml` file**, not from the process working directory.
This means `--config /absolute/path/to/forge.yaml` works from any directory.

Paths prefixed with `.forge/` resolve under the configured state directory
instead (e.g., `.forge/runtime/kubeconfig/hub/config`).

### Schema and API version

The configuration schema version is `forge.praxis.dev/v1alpha1`. Forge
validates this on load and rejects unknown API versions. Generate the JSON
Schema with:

```sh
praxis-forge config schema > forge-schema.json
```

## State and evidence

Forge persists state in a JSON file at `<state-dir>/state.json` (default
`.forge/state.json`). State includes:

- Cluster lifecycle phases (creating, active, deleting, gone)
- Service container identity and restart count
- Stack application phases, digests, and errors
- Network name, CIDR, and per-cluster MetalLB pool allocations
- Captured values from stack steps
- Configuration digest (SHA-256 of the config at last operation)

State writes are **atomic** (write-tmp, fsync, rename) and protected by an
**advisory file lock** (`<state-dir>/lock`).

Kubeconfig files are exported to `<state-dir>/runtime/kubeconfig/<cluster>/config`
with loopback addresses rewritten to container-reachable DNS names.

## Cleanup behavior

`praxis-forge down` tears down in reverse order: services, clusters, network.

- **Ownership verification**: all Docker containers and networks are checked
  for `forge.managed=true` and `forge.environment=<name>` labels before
  removal. Unrelated resources are never touched.
- **Force mode**: `--force` removes resources even if state is inconsistent.
- **Keep-on-failure**: if `up` fails partway, already-created resources remain
  for debugging. Run `down` to clean up.

## Supported platforms

- **Linux x86\_64** (primary; CI-tested)
- **Linux aarch64** (cross-compiled; release artifact provided)
- Container runtime: Docker or Podman
- Kubernetes tooling: kind, kubectl, helm (checked by `doctor`)
- Rust 1.96+ for building from source

## How Forge relates to other Praxis repositories

| Repository | Relationship |
|---|---|
| `praxis-proxy/forge` | This repository. The orchestrator binary. |
| `praxis-proxy/grid` | Consumer. Defines Grid-specific `forge.yaml` demo configurations. |
| `praxis-proxy/demos` | Consumer. May contain additional demo configurations. |
| `praxis-proxy/praxis` | Independent. The Praxis proxy; Forge can deploy it via stacks. |

Forge was extracted from `praxis-proxy/grid` where it lived as an in-tree
workspace crate. The extraction preserved all source code, tests, CLI surface,
configuration schema, and behavior. The only changes from the in-tree version
are:

1. Standalone `Cargo.toml` (no workspace dependency inheritance)
2. `clippy.toml` adapted for a synchronous CLI (does not ban `std::thread::sleep`)
3. Added `fsync` to kubeconfig and template-file atomic writes

## Development

```sh
# Run tests
cargo test --features test-support

# Run clippy
cargo clippy --all-targets --features test-support -- -D warnings

# Build release
cargo build --release

# Generate docs
cargo doc --no-deps
```

The `test-support` feature enables `MockRunner` for unit tests that exercise
external command execution without running real processes.

## License

MIT
