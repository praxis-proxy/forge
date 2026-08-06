# Contributing to Praxis Forge

## Prerequisites

- Rust stable 1.96+
- Docker 29.3.0+ or Podman (for integration testing)

## Quick reference

```sh
make build       # cargo build
make test        # cargo test --features test-support
make fmt         # cargo fmt
make lint        # cargo clippy --all-targets --features test-support -- -D warnings
make doc         # cargo doc --no-deps (warnings denied)
make release     # cargo build --release
```

## Developer Certificate of Origin

TBD — waiting on CNCF sandbox submission. All commits must include a
`Signed-off-by` trailer matching the commit author (`git commit -s`).

## Pull request process

1. Open an issue describing the change before starting work.
2. Create a feature branch from `main`.
3. Keep commits focused and atomic.
4. Run `make lint` and `make test` locally before pushing.
5. Write a clear PR description explaining **why** the change is needed.

## Commit messages

- Use imperative mood ("Add config validation", not "Added").
- Subject line under 50 characters.
- Wrap body at 72 characters.

## Code style

- `#![deny(unsafe_code)]` in the crate root.
- Clippy with `-D warnings` — zero tolerance for lint violations.
- Format with `cargo fmt`.
- Errors via `thiserror`; no `unwrap()` or `expect()` in library code.
- Comments answer "why?", never "what?".

## Testing requirements

- Unit tests for all public functions.
- Integration tests for CLI commands (`tests/integration.rs`).
- Compatibility tests for representative configs (`tests/compatibility.rs`).
- Path-independence tests for standalone operation (`tests/path_independence.rs`).

## Code responsibility

Every contributor is responsible for the correctness and security of their
contributions, regardless of how the code was produced. AI-assisted code
must be human-reviewed and tested before submission.

## License

By contributing, you agree that your contributions will be licensed under
the MIT License.
