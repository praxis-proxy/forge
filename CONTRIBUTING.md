# Contributing to Praxis Forge

Thank you for your interest in contributing to Praxis Forge! We welcome
contributions of all kinds: code, documentation, bug reports, and feature
proposals.

## Prerequisites

- Rust stable 1.96+
- Docker 29.3.0+ or Podman (for integration testing)

## Getting Started

1. Fork the repository and clone your fork.
2. Build the project: `make build`.
3. Run the tests: `make test`.

## Quick Reference

```console
make build          # build Forge
make test           # all tests
make fmt            # format with rustfmt
make lint           # clippy + format check
make doc            # build docs with warnings denied
make release        # build the release binary
```

## Developer Certificate of Origin

> **WARNING**: TBD - not currently in effect; we're waiting on CNCF sandbox
> submission.

All commits must be signed off per the
[Developer Certificate of Origin][dco] (DCO). This certifies that you have
the right to submit the contribution under the project's license.

Sign off by adding `-s` to your commit command:

```console
git commit -s -m "your commit message"
```

This adds a `Signed-off-by` trailer with your name and email. Commits without
sign-off may be rejected by CI.

## Pull Request Process

1. Open an issue first for non-trivial changes.
2. Create a feature branch from `main`.
3. Keep commits focused; each commit should represent one logical change.
4. Run `make lint` and `make test` locally before submitting.
5. Submit a pull request with a clear description of the change and its
   motivation.

## Commit Messages

- Use imperative mood ("Add config validation", not "Added").
- Keep the subject line under 50 characters.
- Wrap the body at 72 characters and explain why, not only what.
- Reference issues with `Fixes #123` or `Relates to #456`.

## Code Style

Forge enforces a strict coding style. Key points:

- `#![deny(unsafe_code)]` in the crate root.
- Clippy with `-D warnings` (zero tolerance for lint violations).
- Format with `cargo fmt`.
- Errors via `thiserror`.
- Comments answer "why?", never "what?".

## Testing Requirements

New capabilities require:

1. Unit tests covering the implementation.
2. Integration tests proving CLI behavior end to end.
3. Compatibility tests for representative environment configurations.
4. Path-independence tests proving standalone operation.

A feature without appropriate tests is not complete.

## Code Responsibility

Every contributor is responsible for the correctness and security of the code
they submit, regardless of how it was produced. AI-assisted code must be
human-reviewed and tested before submission.

Signed-off commits represent your assertion that you have reviewed and fully
understand the changes you are submitting.

## Communication

- [GitHub Issues][issues] for bugs and feature requests.
- [GitHub Discussions][discussions] for questions and design.

## License

By contributing, you agree that your contributions will be licensed under
the Apache License, Version 2.0.

[dco]: https://developercertificate.org/
[issues]: https://github.com/praxis-proxy/forge/issues
[discussions]: https://github.com/orgs/praxis-proxy/discussions
